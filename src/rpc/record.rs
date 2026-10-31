use std::io::{self, IoSlice};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug)]
pub struct RecordLimits {
    pub max_record_size: usize,
    pub max_fragment_size: usize,
    pub max_fragments: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("RPC fragment of {actual} bytes exceeds limit {limit}")]
    FragmentTooLarge { actual: usize, limit: usize },
    #[error("RPC record exceeds {limit} bytes")]
    RecordTooLarge { limit: usize },
    #[error("RPC record has more than {limit} fragments")]
    TooManyFragments { limit: usize },
    #[error("RPC fragment size must be non-zero")]
    EmptyFragment,
    #[error("RPC record byte budget is closed")]
    BudgetClosed,
}

const LAST_FRAGMENT: u32 = 0x8000_0000;
const MAX_WIRE_FRAGMENT_SIZE: usize = 0x7fff_ffff;
/// An RPC message starts with its four-byte transaction ID.
const XID_SIZE: usize = 4;
/// The largest block read at a time while dropping a refused fragment.
const SKIP_BLOCK_SIZE: usize = 8 * 1024;

/// One record read by `read_record_budgeted`.
#[derive(Debug)]
pub enum InboundRecord {
    /// A record within the limits, and the budget it holds while it is queued
    /// or executing.
    Accepted {
        record: Vec<u8>,
        budget: OwnedSemaphorePermit,
    },
    /// A single-fragment record over the limits. It was read and dropped, so
    /// the stream is at the next record and the call can be rejected without
    /// closing the connection. `xid` is `None` only for a record shorter than
    /// an XID.
    Refused { xid: Option<u32>, reason: RecordRefusal },
}

/// Why `read_record_budgeted` refused a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordRefusal {
    #[error("RPC fragment of {actual} bytes exceeds limit {limit}")]
    FragmentTooLarge { actual: usize, limit: usize },
    #[error("RPC record of {actual} bytes exceeds limit {limit}")]
    RecordTooLarge { actual: usize, limit: usize },
}

pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R, limits: RecordLimits) -> Result<Vec<u8>, RecordError> {
    let header = reader.read_u32().await?;
    read_fragments(reader, header, limits).await
}

/// Reads a record while charging its byte budget before any fragment body is
/// allocated. The returned permit keeps the record charged while it is queued
/// or executing.
///
/// A single-fragment record (the common case) has a known final size and
/// reserves exactly that size. A fragmented record reserves the maximum record
/// size up front: a whole-record reservation prevents fragmented readers from
/// holding partial reservations while waiting on each other.
///
/// A single-fragment record over the limits is refused instead of failing the
/// stream. Clients resend a call whose connection closed before it was
/// answered, so closing the connection over a call too large to accept would
/// make a hard-mounted client reconnect and resend it forever. Kernel clients
/// send each call as one fragment, and such a record is known to be too large
/// from its first header, so it is read and dropped through a scratch block
/// of at most `SKIP_BLOCK_SIZE` bytes without charging any budget. Every other
/// violation, including any in a fragmented record, fails the stream as soon
/// as it is seen.
pub async fn read_record_budgeted<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: RecordLimits,
    budget: Arc<Semaphore>,
) -> Result<InboundRecord, RecordError> {
    let header = reader.read_u32().await?;
    let reservation = match fragment_length(header, limits, 0) {
        Ok(length) if header & LAST_FRAGMENT != 0 => length,
        Ok(_) => limits.max_record_size,
        Err(error) => {
            let reason = refusal(header, error)?;
            let xid = skip_fragment(reader, (header & !LAST_FRAGMENT) as usize).await?;
            return Ok(InboundRecord::Refused { xid, reason });
        },
    };
    let reservation = u32::try_from(reservation).map_err(|_| RecordError::RecordTooLarge {
        limit: u32::MAX as usize,
    })?;
    let permit = budget
        .acquire_many_owned(reservation)
        .await
        .map_err(|_| RecordError::BudgetClosed)?;
    let record = read_fragments(reader, header, limits).await?;
    Ok(InboundRecord::Accepted { record, budget: permit })
}

/// Returns why a record whose first fragment `header` failed validation with
/// `error` is refused, or `error` if it is not a single fragment over a size
/// limit and must fail the stream.
fn refusal(header: u32, error: RecordError) -> Result<RecordRefusal, RecordError> {
    if header & LAST_FRAGMENT == 0 {
        return Err(error);
    }
    match error {
        RecordError::FragmentTooLarge { actual, limit } => Ok(RecordRefusal::FragmentTooLarge { actual, limit }),
        RecordError::RecordTooLarge { limit } => Ok(RecordRefusal::RecordTooLarge {
            actual: (header & !LAST_FRAGMENT) as usize,
            limit,
        }),
        error => Err(error),
    }
}

/// Validates one fragment header against the per-fragment limit and the
/// record bytes already received, returning the fragment body length.
fn fragment_length(header: u32, limits: RecordLimits, received: usize) -> Result<usize, RecordError> {
    let length = (header & !LAST_FRAGMENT) as usize;
    if length == 0 && header & LAST_FRAGMENT == 0 {
        return Err(RecordError::EmptyFragment);
    }
    if length > limits.max_fragment_size {
        return Err(RecordError::FragmentTooLarge {
            actual: length,
            limit: limits.max_fragment_size,
        });
    }
    if received.checked_add(length).is_none_or(|total| total > limits.max_record_size) {
        return Err(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        });
    }
    Ok(length)
}

/// Reads the fragment bodies of one record, starting from an already-read
/// first fragment header. A record that exceeds a limit fails as soon as the
/// violation is seen.
async fn read_fragments<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut header: u32,
    limits: RecordLimits,
) -> Result<Vec<u8>, RecordError> {
    let mut record = Vec::new();
    for fragment in 1..=limits.max_fragments {
        let length = fragment_length(header, limits, record.len())?;
        let start = record.len();
        reserve_record(&mut record, start + length, limits.max_record_size)?;
        record.resize(start + length, 0);
        reader.read_exact(&mut record[start..]).await?;
        if header & LAST_FRAGMENT != 0 {
            return Ok(record);
        }
        if fragment == limits.max_fragments {
            // Fail without waiting for a header that may never arrive.
            break;
        }
        header = reader.read_u32().await?;
    }
    Err(RecordError::TooManyFragments {
        limit: limits.max_fragments,
    })
}

/// Reads and drops one fragment body of `length` bytes and returns the XID
/// in its first bytes. Only the XID and one bounded scratch block are held.
async fn skip_fragment<R: AsyncRead + Unpin>(reader: &mut R, length: usize) -> Result<Option<u32>, RecordError> {
    let mut xid = [0; XID_SIZE];
    let xid_length = length.min(XID_SIZE);
    reader.read_exact(&mut xid[..xid_length]).await?;
    let mut remaining = length - xid_length;
    let mut scratch = vec![0; remaining.min(SKIP_BLOCK_SIZE)];
    while remaining > 0 {
        let block = remaining.min(scratch.len());
        let read = reader.read(&mut scratch[..block]).await?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        remaining -= read;
    }
    Ok((xid_length == XID_SIZE).then(|| u32::from_be_bytes(xid)))
}

/// Grows geometrically for fragmented records while never requesting a
/// capacity above the validated record-size limit. This avoids reallocating
/// and copying the full prefix for every fragment.
fn reserve_record(record: &mut Vec<u8>, required: usize, limit: usize) -> Result<(), RecordError> {
    if required <= record.capacity() {
        return Ok(());
    }
    let target = record.capacity().saturating_mul(2).max(required).min(limit);
    record
        .try_reserve_exact(target.saturating_sub(record.len()))
        .map_err(|_| RecordError::RecordTooLarge { limit })
}

pub async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &[u8],
    max_fragment_size: usize,
) -> Result<(), RecordError> {
    write_record_limited(
        writer,
        record,
        RecordLimits {
            max_record_size: usize::MAX,
            max_fragment_size,
            max_fragments: usize::MAX,
        },
    )
    .await
}

/// Writes one record while enforcing aggregate size and fragment-count
/// limits as well as the per-fragment limit.
pub async fn write_record_limited<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &[u8],
    limits: RecordLimits,
) -> Result<(), RecordError> {
    write_record_segments_limited(writer, [record, &[], &[]], limits).await
}

/// Writes a record held in up to three immutable segments without first
/// coalescing them. Fragment boundaries may cross segment boundaries.
pub async fn write_record_segments_limited<W: AsyncWrite + Unpin>(
    writer: &mut W,
    segments: [&[u8]; 3],
    limits: RecordLimits,
) -> Result<(), RecordError> {
    let length = segments.iter().try_fold(0usize, |length, segment| {
        length.checked_add(segment.len()).ok_or(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })
    })?;
    validate_record_length(length, limits)?;
    write_segmented_fragments(writer, segments, length, limits.max_fragment_size).await
}

/// Validates the length of an outbound record against the aggregate size,
/// fragment-size, and fragment-count limits.
pub fn validate_record_length(length: usize, limits: RecordLimits) -> Result<(), RecordError> {
    if length > limits.max_record_size {
        return Err(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        });
    }
    let fragment_count = if length == 0 {
        1
    } else if limits.max_fragment_size == 0 {
        usize::MAX
    } else {
        length.div_ceil(limits.max_fragment_size)
    };
    if fragment_count > limits.max_fragments {
        return Err(RecordError::TooManyFragments {
            limit: limits.max_fragments,
        });
    }
    if limits.max_fragment_size == 0 {
        return Err(RecordError::FragmentTooLarge {
            actual: length,
            limit: 0,
        });
    }
    Ok(())
}

async fn write_segmented_fragments<W: AsyncWrite + Unpin>(
    writer: &mut W,
    segments: [&[u8]; 3],
    total_length: usize,
    max_fragment_size: usize,
) -> Result<(), RecordError> {
    if total_length == 0 {
        writer.write_all(&LAST_FRAGMENT.to_be_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }
    // Persistent cursor into `segments`; it advances by exactly the payload
    // bytes of each fragment. Record-marking headers are not counted.
    let mut segment_index = 0usize;
    let mut segment_offset = 0usize;
    let mut remaining_total = total_length;
    while remaining_total > 0 {
        let fragment_length = remaining_total.min(max_fragment_size);
        if fragment_length > MAX_WIRE_FRAGMENT_SIZE {
            return Err(RecordError::FragmentTooLarge {
                actual: fragment_length,
                limit: MAX_WIRE_FRAGMENT_SIZE,
            });
        }
        let last = fragment_length == remaining_total;
        let header = (fragment_length as u32 | if last { LAST_FRAGMENT } else { 0 }).to_be_bytes();
        let mut slices = [IoSlice::new(&[]); 4];
        slices[0] = IoSlice::new(&header);
        let mut slice_count = 1usize;
        let mut remaining_fragment = fragment_length;
        while remaining_fragment > 0 {
            while segment_index < segments.len() && segment_offset == segments[segment_index].len() {
                segment_index += 1;
                segment_offset = 0;
            }
            let segment = segments
                .get(segment_index)
                .ok_or(RecordError::RecordTooLarge { limit: total_length })?;
            let take = remaining_fragment.min(segment.len() - segment_offset);
            slices[slice_count] = IoSlice::new(&segment[segment_offset..segment_offset + take]);
            slice_count += 1;
            remaining_fragment -= take;
            segment_offset += take;
        }
        write_all_slices(writer, &mut slices[..slice_count]).await?;
        remaining_total -= fragment_length;
    }
    writer.flush().await?;
    Ok(())
}

async fn write_all_slices<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut slices: &mut [IoSlice<'_>],
) -> Result<(), RecordError> {
    if writer.is_write_vectored() {
        // Async writers may consume only an arbitrary prefix of the iovec.
        // Advance the slices in place so retries neither duplicate the header
        // nor skip payload bytes.
        while !slices.is_empty() {
            let written = writer.write_vectored(slices).await?;
            if written == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            IoSlice::advance_slices(&mut slices, written);
        }
    } else {
        for slice in slices {
            writer.write_all(slice).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    fn accepted(inbound: InboundRecord) -> (Vec<u8>, OwnedSemaphorePermit) {
        match inbound {
            InboundRecord::Accepted { record, budget } => (record, budget),
            InboundRecord::Refused { xid, reason } => panic!("record {xid:?} was refused: {reason}"),
        }
    }

    // A deterministic short-writing sink that exercises the iovec retry path
    // without relying on operating-system socket buffer pressure.
    struct PartialVectoredWriter {
        output: Vec<u8>,
        max_write: usize,
        vectored_writes: usize,
    }

    impl AsyncWrite for PartialVectoredWriter {
        fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
            let written = buffer.len().min(self.max_write);
            self.output.extend_from_slice(&buffer[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut remaining = self.max_write;
            let mut written = 0usize;
            for buffer in buffers {
                let take = buffer.len().min(remaining);
                self.output.extend_from_slice(&buffer[..take]);
                written += take;
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            self.vectored_writes += 1;
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn multi_fragment_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let write = tokio::spawn(async move { write_record(&mut client, b"abcdefgh", 3).await.unwrap() });
        let value = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 8,
                max_fragment_size: 3,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        write.await.unwrap();
        assert_eq!(value, b"abcdefgh");
    }

    #[tokio::test]
    async fn partial_vectored_writes_preserve_fragmented_wire_bytes() {
        let segments = [&b"ab"[..], &b"cdefg"[..], &b"hijk"[..]];
        let limits = RecordLimits {
            max_record_size: 11,
            max_fragment_size: 5,
            max_fragments: 3,
        };
        let mut writer = PartialVectoredWriter {
            output: Vec::new(),
            max_write: 3,
            vectored_writes: 0,
        };

        write_record_segments_limited(&mut writer, segments, limits).await.unwrap();

        let mut expected = Vec::new();
        for (index, fragment) in b"abcdefghijk".chunks(5).enumerate() {
            let last = index == 2;
            let header = fragment.len() as u32 | if last { 0x8000_0000 } else { 0 };
            expected.extend_from_slice(&header.to_be_bytes());
            expected.extend_from_slice(fragment);
        }
        assert_eq!(writer.output, expected);
        assert!(writer.vectored_writes > 3);
    }

    #[tokio::test]
    async fn aggregate_budget_is_reserved_before_fragment_allocation() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(&0x8000_0008u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcdefgh").await.unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let read_budget = budget.clone();
        let read = tokio::spawn(async move {
            read_record_budgeted(
                &mut server,
                RecordLimits {
                    max_record_size: 8,
                    max_fragment_size: 8,
                    max_fragments: 1,
                },
                read_budget,
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());
        budget.add_permits(4);
        let (record, reservation) = accepted(read.await.unwrap());
        assert_eq!(record, b"abcdefgh");
        assert_eq!(budget.available_permits(), 0);
        drop(reservation);
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn fragmented_records_do_not_deadlock_on_partial_budget_reservations() {
        let limits = RecordLimits {
            max_record_size: 8,
            max_fragment_size: 4,
            max_fragments: 2,
        };
        let budget = Arc::new(Semaphore::new(8));
        let (mut first_client, mut first_server) = tokio::io::duplex(32);
        first_client.write_all(&4u32.to_be_bytes()).await.unwrap();
        first_client.write_all(b"abcd").await.unwrap();
        let first_budget = budget.clone();
        let first =
            tokio::spawn(async move { read_record_budgeted(&mut first_server, limits, first_budget).await.unwrap() });
        while budget.available_permits() != 0 {
            tokio::task::yield_now().await;
        }

        let (mut second_client, mut second_server) = tokio::io::duplex(32);
        second_client.write_all(&4u32.to_be_bytes()).await.unwrap();
        second_client.write_all(b"ijkl").await.unwrap();
        second_client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        second_client.write_all(b"mnop").await.unwrap();
        let second_budget = budget.clone();
        let second =
            tokio::spawn(async move { read_record_budgeted(&mut second_server, limits, second_budget).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());

        first_client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        first_client.write_all(b"efgh").await.unwrap();
        let (first_record, first_reservation) = accepted(first.await.unwrap());
        assert_eq!(first_record, b"abcdefgh");
        assert!(!second.is_finished());
        drop(first_reservation);

        let (second_record, second_reservation) = accepted(second.await.unwrap());
        assert_eq!(second_record, b"ijklmnop");
        drop(second_reservation);
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn single_fragment_records_reserve_only_their_length() {
        let limits = RecordLimits {
            max_record_size: 64,
            max_fragment_size: 64,
            max_fragments: 4,
        };
        let budget = Arc::new(Semaphore::new(100));
        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&0x8000_0008u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcdefgh").await.unwrap();
        let (record, permit) = accepted(read_record_budgeted(&mut server, limits, budget.clone()).await.unwrap());
        assert_eq!(record, b"abcdefgh");
        assert_eq!(budget.available_permits(), 92);
        drop(permit);
        assert_eq!(budget.available_permits(), 100);

        client.write_all(&4u32.to_be_bytes()).await.unwrap();
        client.write_all(b"ijkl").await.unwrap();
        client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        client.write_all(b"mnop").await.unwrap();
        let (record, permit) = accepted(read_record_budgeted(&mut server, limits, budget.clone()).await.unwrap());
        assert_eq!(record, b"ijklmnop");
        assert_eq!(budget.available_permits(), 100 - 64, "fragmented records reserve the record limit");
        drop(permit);
    }

    #[tokio::test]
    async fn invalid_first_header_is_handled_without_waiting_for_budget() {
        let limits = RecordLimits {
            max_record_size: 64,
            max_fragment_size: 32,
            max_fragments: 4,
        };
        let exhausted = Arc::new(Semaphore::new(0));
        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&0x8000_0021u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0xab; 33]).await.unwrap();
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        let deadline = std::time::Duration::from_secs(1);

        let refused = tokio::time::timeout(deadline, read_record_budgeted(&mut server, limits, exhausted.clone()))
            .await
            .expect("an oversized record must not wait for budget");
        assert!(matches!(
            refused,
            Ok(InboundRecord::Refused {
                xid: Some(0xabab_abab),
                reason: RecordRefusal::FragmentTooLarge { actual: 33, limit: 32 },
            })
        ));
        let empty = tokio::time::timeout(deadline, read_record_budgeted(&mut server, limits, exhausted))
            .await
            .expect("an empty fragment must not wait for budget");
        assert!(matches!(empty, Err(RecordError::EmptyFragment)));
    }

    #[tokio::test]
    async fn single_fragment_records_over_the_limits_are_refused_and_the_stream_stays_aligned() {
        let limits = RecordLimits {
            max_record_size: 12,
            max_fragment_size: 8,
            max_fragments: 3,
        };
        // A fragment limit above the record limit lets one fragment exceed
        // only the record limit.
        let wide = RecordLimits {
            max_record_size: 8,
            max_fragment_size: 12,
            ..limits
        };
        let budget = Arc::new(Semaphore::new(64));
        let (mut client, mut server) = tokio::io::duplex(1024);
        // One fragment over the fragment limit, as Linux sends a WRITE, and
        // one over the record limit. Skipping must also cross blocks.
        client.write_all(&0x8000_0009u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0, 0, 0, 1, 9, 9, 9, 9, 9]).await.unwrap();
        client.write_all(&0x8000_0009u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0, 0, 0, 2, 9, 9, 9, 9, 9]).await.unwrap();
        client
            .write_all(&(0x8000_0000u32 | (SKIP_BLOCK_SIZE as u32 * 2 + 1)).to_be_bytes())
            .await
            .unwrap();
        // The skipped body is larger than the pipe, so it is written while
        // the reader drains it.
        let writer = tokio::spawn(async move {
            client.write_all(&[0, 0, 0, 3]).await.unwrap();
            client.write_all(&vec![7; SKIP_BLOCK_SIZE * 2 - 3]).await.unwrap();
            client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
            client.write_all(b"next").await.unwrap();
            client
        });

        for (record_limits, expected_xid, expected_reason) in [
            (limits, 1, RecordRefusal::FragmentTooLarge { actual: 9, limit: 8 }),
            (wide, 2, RecordRefusal::RecordTooLarge { actual: 9, limit: 8 }),
            (
                limits,
                3,
                RecordRefusal::FragmentTooLarge {
                    actual: SKIP_BLOCK_SIZE * 2 + 1,
                    limit: 8,
                },
            ),
        ] {
            match read_record_budgeted(&mut server, record_limits, budget.clone()).await.unwrap() {
                InboundRecord::Refused { xid, reason } => {
                    assert_eq!(xid, Some(expected_xid));
                    assert_eq!(reason, expected_reason);
                },
                InboundRecord::Accepted { record, .. } => panic!("record {record:?} was accepted"),
            }
            assert_eq!(budget.available_permits(), 64, "a refused record holds no budget");
        }
        let (record, permit) = accepted(read_record_budgeted(&mut server, limits, budget.clone()).await.unwrap());
        assert_eq!(record, b"next");
        drop(permit);
        let mut client = writer.await.unwrap();

        // A refused record too short to carry an XID, then streams that end
        // inside a refused record's body and inside its XID.
        let tiny = RecordLimits {
            max_record_size: 2,
            max_fragment_size: 2,
            max_fragments: 1,
        };
        client.write_all(&0x8000_0003u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        client.write_all(&0x8000_0009u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcdef").await.unwrap();
        drop(client);
        assert!(matches!(
            read_record_budgeted(&mut server, tiny, budget.clone()).await,
            Ok(InboundRecord::Refused { xid: None, .. })
        ));
        assert!(matches!(
            read_record_budgeted(&mut server, tiny, budget.clone()).await,
            Err(RecordError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&0x8000_0009u32.to_be_bytes()).await.unwrap();
        client.write_all(b"ab").await.unwrap();
        drop(client);
        assert!(matches!(
            read_record_budgeted(&mut server, tiny, budget).await,
            Err(RecordError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn fragmented_records_over_the_limits_fail_without_waiting_for_more_input() {
        let limits = RecordLimits {
            max_record_size: 12,
            max_fragment_size: 8,
            max_fragments: 3,
        };
        let budget = Arc::new(Semaphore::new(64));
        let mut first_fragment_too_large = Vec::new();
        first_fragment_too_large.extend_from_slice(&9u32.to_be_bytes());
        first_fragment_too_large.extend_from_slice(&[0, 0, 0, 1, 9]);
        let mut record_too_large = Vec::new();
        record_too_large.extend_from_slice(&8u32.to_be_bytes());
        record_too_large.extend_from_slice(&[0, 0, 0, 2, 8, 8, 8, 8]);
        record_too_large.extend_from_slice(&0x8000_0008u32.to_be_bytes());
        let mut too_many_fragments = Vec::new();
        for byte in [0, 0, 3] {
            too_many_fragments.extend_from_slice(&1u32.to_be_bytes());
            too_many_fragments.push(byte);
        }

        for (input, expected) in [
            (first_fragment_too_large, RecordError::FragmentTooLarge { actual: 9, limit: 8 }),
            (record_too_large, RecordError::RecordTooLarge { limit: 12 }),
            (too_many_fragments, RecordError::TooManyFragments { limit: 3 }),
        ] {
            // The client stays connected and sends nothing more, so a reader
            // that waited for the rest of the record would time out.
            let (mut client, mut server) = tokio::io::duplex(1024);
            client.write_all(&input).await.unwrap();
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                read_record_budgeted(&mut server, limits, budget.clone()),
            )
            .await
            .expect("a framing violation must fail without more input")
            .unwrap_err();
            assert_eq!(error.to_string(), expected.to_string());
            assert_eq!(budget.available_permits(), 64, "a failed record returns its budget");
            drop(client);
        }
    }

    #[tokio::test]
    async fn empty_records_and_empty_final_fragments_round_trip() {
        let limits = RecordLimits {
            max_record_size: 16,
            max_fragment_size: 16,
            max_fragments: 2,
        };
        let (mut client, mut server) = tokio::io::duplex(64);
        write_record(&mut client, b"", 16).await.unwrap();
        assert!(read_record(&mut server, limits).await.unwrap().is_empty());

        client.write_all(&2u32.to_be_bytes()).await.unwrap();
        client.write_all(b"ab").await.unwrap();
        client.write_all(&0x8000_0000u32.to_be_bytes()).await.unwrap();
        assert_eq!(read_record(&mut server, limits).await.unwrap(), b"ab");
    }

    #[tokio::test]
    async fn record_size_limit_spans_fragments() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&4u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcd").await.unwrap();
        client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        let error = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 6,
                max_fragment_size: 4,
                max_fragments: 4,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::RecordTooLarge { limit: 6 }));
    }

    #[tokio::test]
    async fn oversized_fragment_is_rejected_before_body_read() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&0x8000_1000u32.to_be_bytes()).await.unwrap();
        let error = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 1024,
                max_fragment_size: 512,
                max_fragments: 1,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::FragmentTooLarge { .. }));
    }

    #[tokio::test]
    async fn fragment_count_is_bounded() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(&1u32.to_be_bytes()).await.unwrap();
        client.write_all(&[1]).await.unwrap();
        client.write_all(&1u32.to_be_bytes()).await.unwrap();
        client.write_all(&[2]).await.unwrap();
        let error = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 32,
                max_fragment_size: 16,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::TooManyFragments { limit: 2 }));
    }

    #[tokio::test]
    async fn outbound_record_and_fragment_limits_are_enforced() {
        let mut output = Vec::new();
        let error = write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 4,
                max_fragment_size: 4,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::RecordTooLarge { limit: 4 }));

        let error = write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 5,
                max_fragment_size: 2,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::TooManyFragments { limit: 2 }));

        output.clear();
        write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 5,
                max_fragment_size: 2,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            output,
            [
                2u32.to_be_bytes().as_slice(),
                b"12",
                2u32.to_be_bytes().as_slice(),
                b"34",
                0x8000_0001u32.to_be_bytes().as_slice(),
                b"5",
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn segmented_records_cross_segment_and_fragment_boundaries() {
        let mut output = Vec::new();
        write_record_segments_limited(
            &mut output,
            [b"abc", b"defgh", b"ij"],
            RecordLimits {
                max_record_size: 10,
                max_fragment_size: 4,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        let expected = [
            4u32.to_be_bytes().as_slice(),
            b"abcd",
            4u32.to_be_bytes().as_slice(),
            b"efgh",
            0x8000_0002u32.to_be_bytes().as_slice(),
            b"ij",
        ]
        .concat();
        assert_eq!(output, expected);
    }
}
