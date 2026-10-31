#![no_main]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use nfsembed::rpc::record::{read_record, read_record_budgeted, InboundRecord, RecordLimits, RecordRefusal};
use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::Semaphore;

/// Small enough that a refused fragment and the records after it fit in a
/// short input. Three full fragments exceed the record limit, so fragmented
/// records can break each of the three limits.
const LIMITS: RecordLimits = RecordLimits {
    max_record_size: 128,
    max_fragment_size: 64,
    max_fragments: 4,
};
/// One record's worth. Every permit must be back before the next read, which
/// is checked first, so a leaked permit fails instead of blocking that read.
const BUDGET: usize = LIMITS.max_record_size;
const LAST_FRAGMENT: u32 = 0x8000_0000;

/// What reading the record framed at the start of a stream must produce.
#[derive(Debug)]
enum Expected {
    /// A record within the limits, the budget it reserves, and the length of
    /// its framing.
    Accepted {
        record: Vec<u8>,
        reservation: usize,
        framed: usize,
    },
    /// A complete single fragment over the limits.
    Refused {
        xid: Option<u32>,
        reason: RecordRefusal,
        framed: usize,
    },
    /// Broken framing, a fragmented record over a limit, or a stream that
    /// ends inside the record.
    Failed,
}

/// Models the record-marking rules independently of the reader under test.
fn expected(stream: &[u8]) -> Expected {
    let Some(first) = be_u32(stream, 0) else {
        return Expected::Failed;
    };
    let first_length = (first & !LAST_FRAGMENT) as usize;
    let single = first & LAST_FRAGMENT != 0;
    let refusal = if !single {
        None
    } else if first_length > LIMITS.max_fragment_size {
        Some(RecordRefusal::FragmentTooLarge {
            actual: first_length,
            limit: LIMITS.max_fragment_size,
        })
    } else if first_length > LIMITS.max_record_size {
        Some(RecordRefusal::RecordTooLarge {
            actual: first_length,
            limit: LIMITS.max_record_size,
        })
    } else {
        None
    };
    if let Some(reason) = refusal {
        if stream.len() < 4 + first_length {
            return Expected::Failed;
        }
        return Expected::Refused {
            xid: if first_length >= 4 { be_u32(stream, 4) } else { None },
            reason,
            framed: 4 + first_length,
        };
    }

    let reservation = if single { first_length } else { LIMITS.max_record_size };
    let mut record = Vec::new();
    let mut offset = 0;
    for _ in 0..LIMITS.max_fragments {
        let Some(header) = be_u32(stream, offset) else {
            return Expected::Failed;
        };
        let length = (header & !LAST_FRAGMENT) as usize;
        let last = header & LAST_FRAGMENT != 0;
        if (length == 0 && !last) || length > LIMITS.max_fragment_size || record.len() + length > LIMITS.max_record_size
        {
            return Expected::Failed;
        }
        let Some(body) = stream.get(offset + 4..offset + 4 + length) else {
            return Expected::Failed;
        };
        record.extend_from_slice(body);
        offset += 4 + length;
        if last {
            return Expected::Accepted {
                record,
                reservation,
                framed: offset,
            };
        }
    }
    Expected::Failed
}

fn be_u32(stream: &[u8], offset: usize) -> Option<u32> {
    let bytes = stream.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().unwrap()))
}

/// Writes `data` into a pipe large enough to hold it and closes the pipe.
async fn feed(mut writer: DuplexStream, data: &[u8]) {
    let _ = writer.write_all(data).await;
}

/// Counts the bytes read through it, to check where each record ends.
struct Counted<R> {
    inner: R,
    read: usize,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.read += buf.filled().len() - filled;
        poll
    }
}

fuzz_target!(|data: &[u8]| {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| Builder::new_current_thread().build().unwrap());
    let capacity = data.len().max(1);
    runtime.block_on(async {
        // The unbudgeted reader refuses nothing: a record over the limits
        // fails it.
        let (writer, mut reader) = tokio::io::duplex(capacity);
        let (_, result) = tokio::join!(feed(writer, data), read_record(&mut reader, LIMITS));
        match (result, expected(data)) {
            (Ok(record), Expected::Accepted { record: want, .. }) => assert_eq!(record, want),
            (Err(_), Expected::Refused { .. } | Expected::Failed) => {},
            (result, expected) => panic!("read_record returned {result:?}, expected {expected:?}"),
        }

        // Read the input as one connection's stream of records. Each read,
        // refused records and errors included, must match the model, and
        // every record must end exactly where its framing does, so that the
        // next read starts at the next record.
        let budget = Arc::new(Semaphore::new(BUDGET));
        let (writer, reader) = tokio::io::duplex(capacity);
        let mut reader = Counted { inner: reader, read: 0 };
        let read = async {
            loop {
                assert_eq!(budget.available_permits(), BUDGET, "a record's budget was not returned");
                let start = reader.read;
                let stream = &data[start..];
                let result = read_record_budgeted(&mut reader, LIMITS, budget.clone()).await;
                let framed = match (result, expected(stream)) {
                    (
                        Ok(InboundRecord::Accepted { record, budget: permit }),
                        Expected::Accepted {
                            record: want,
                            reservation,
                            framed,
                        },
                    ) => {
                        assert_eq!(record, want, "an accepted record has the wrong bytes");
                        assert_eq!(permit.num_permits(), reservation, "a record reserved the wrong budget");
                        framed
                    },
                    (
                        Ok(InboundRecord::Refused { xid, reason }),
                        Expected::Refused {
                            xid: want,
                            reason: why,
                            framed,
                        },
                    ) => {
                        assert_eq!((xid, reason), (want, why), "a refusal named the wrong call or reason");
                        assert_eq!(budget.available_permits(), BUDGET, "a refused record holds budget");
                        framed
                    },
                    (Err(_), Expected::Failed) => break,
                    (result, expected) => panic!("read_record_budgeted returned {result:?}, expected {expected:?}"),
                };
                assert_eq!(reader.read - start, framed, "a record left the stream misaligned");
            }
        };
        tokio::join!(feed(writer, data), read);
        assert_eq!(budget.available_permits(), BUDGET, "a record's budget was not returned");
    });
});
