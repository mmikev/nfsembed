use bytes::{Bytes, BytesMut};

static XDR_PADDING: [u8; 3] = [0; 3];

/// An encoded RPC reply that can retain a large opaque payload without
/// copying it into the protocol prefix. Cloning a reply is always shallow.
#[derive(Clone, Debug)]
pub struct EncodedReply {
    storage: ReplyStorage,
    // `Some` means the complete backing allocation is known and safe to
    // charge directly to the replay cache. Unknown `Bytes` owners must first
    // be compacted because a short slice can pin a much larger allocation.
    retained_bytes: Option<usize>,
}

#[derive(Clone, Debug)]
enum ReplyStorage {
    Contiguous(Bytes),
    Segmented {
        prefix: Bytes,
        payload: Bytes,
        padding: usize,
        len: usize,
    },
}

impl EncodedReply {
    /// Creates a reply whose protocol prefix and opaque payload can be written
    /// as separate buffers. `padding` is the trailing XDR padding byte count.
    pub fn segmented(prefix: Bytes, payload: Bytes, padding: usize) -> Self {
        assert!(padding <= XDR_PADDING.len());
        let len = prefix
            .len()
            .checked_add(payload.len())
            .and_then(|len| len.checked_add(padding))
            .expect("validated RPC reply length");
        Self {
            storage: ReplyStorage::Segmented {
                prefix,
                payload,
                padding,
                len,
            },
            retained_bytes: None,
        }
    }

    /// Returns the encoded wire length, including XDR padding.
    pub fn len(&self) -> usize {
        match &self.storage {
            ReplyStorage::Contiguous(bytes) => bytes.len(),
            ReplyStorage::Segmented { len, .. } => *len,
        }
    }

    /// Returns whether the encoded wire representation is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the immutable buffers in wire order for vectored transport.
    pub fn segments(&self) -> [&[u8]; 3] {
        match &self.storage {
            ReplyStorage::Contiguous(bytes) => [bytes, &[], &[]],
            ReplyStorage::Segmented {
                prefix,
                payload,
                padding,
                ..
            } => [prefix, payload, &XDR_PADDING[..*padding]],
        }
    }

    /// Returns the protocol prefix used for status extraction and tracing.
    pub fn prefix(&self) -> &[u8] {
        match &self.storage {
            ReplyStorage::Contiguous(bytes) => bytes,
            ReplyStorage::Segmented { prefix, .. } => prefix,
        }
    }

    pub(crate) fn replay_storage_requires_copy(&self) -> bool {
        self.retained_bytes.is_none()
    }

    /// Produces cache-owned storage with a known allocation charge. Replies
    /// created from an owned `Vec` can remain shallow; replies backed by an
    /// arbitrary `Bytes` owner are compacted so a small slice cannot pin an
    /// unaccounted large allocation for the replay TTL.
    pub(crate) fn replay_storage(&self) -> (Self, usize) {
        if let Some(retained_bytes) = self.retained_bytes {
            return (self.clone(), retained_bytes);
        }

        match &self.storage {
            ReplyStorage::Contiguous(bytes) => {
                let (bytes, retained_bytes) = compact_bytes(bytes);
                (
                    Self {
                        storage: ReplyStorage::Contiguous(bytes),
                        retained_bytes: Some(retained_bytes),
                    },
                    retained_bytes,
                )
            },
            ReplyStorage::Segmented {
                prefix,
                payload,
                padding,
                len,
            } => {
                let (prefix, prefix_bytes) = compact_bytes(prefix);
                let (payload, payload_bytes) = compact_bytes(payload);
                let retained_bytes = (*len).max(prefix_bytes.saturating_add(payload_bytes));
                (
                    Self {
                        storage: ReplyStorage::Segmented {
                            prefix,
                            payload,
                            padding: *padding,
                            len: *len,
                        },
                        retained_bytes: Some(retained_bytes),
                    },
                    retained_bytes,
                )
            },
        }
    }

    /// Coalesces the reply when a consumer specifically requires contiguous
    /// storage. The production transport writes `segments` directly.
    pub fn into_bytes(self) -> Bytes {
        match self.storage {
            ReplyStorage::Contiguous(bytes) => bytes,
            ReplyStorage::Segmented {
                prefix,
                payload,
                padding,
                len,
            } => {
                let mut output = BytesMut::with_capacity(len);
                for segment in [&prefix[..], &payload[..], &XDR_PADDING[..padding]] {
                    output.extend_from_slice(segment);
                }
                output.freeze()
            },
        }
    }
}

impl From<Bytes> for EncodedReply {
    fn from(value: Bytes) -> Self {
        Self {
            storage: ReplyStorage::Contiguous(value),
            retained_bytes: None,
        }
    }
}

impl From<Vec<u8>> for EncodedReply {
    fn from(value: Vec<u8>) -> Self {
        let retained_bytes = value.capacity();
        Self {
            storage: ReplyStorage::Contiguous(Bytes::from(value)),
            retained_bytes: Some(retained_bytes),
        }
    }
}

fn compact_bytes(input: &[u8]) -> (Bytes, usize) {
    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input);
    let retained_bytes = output.capacity();
    (Bytes::from(output), retained_bytes)
}

impl PartialEq for EncodedReply {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut left = self.segments().into_iter().flat_map(|segment| segment.iter());
        let mut right = other.segments().into_iter().flat_map(|segment| segment.iter());
        left.by_ref().eq(right.by_ref())
    }
}

impl Eq for EncodedReply {}

impl PartialEq<Bytes> for EncodedReply {
    fn eq(&self, other: &Bytes) -> bool {
        self.len() == other.len() && self.segments().into_iter().flat_map(|segment| segment.iter()).eq(other.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmented_reply_coalesces_without_changing_wire_bytes() {
        let reply = EncodedReply::segmented(Bytes::from_static(b"prefix"), Bytes::from_static(b"data"), 3);
        assert_eq!(reply.len(), 13);
        assert_eq!(reply.clone().into_bytes(), Bytes::from_static(b"prefixdata\0\0\0"));
        assert_eq!(reply, EncodedReply::from(b"prefixdata\0\0\0".to_vec()));
    }

    #[test]
    fn equality_compares_wire_bytes_regardless_of_segmentation() {
        let segmented = EncodedReply::segmented(Bytes::from_static(b"ab"), Bytes::from_static(b"cd"), 0);
        let other_split = EncodedReply::segmented(Bytes::from_static(b"a"), Bytes::from_static(b"bcd"), 0);
        assert_eq!(segmented, other_split);
        assert_eq!(segmented, Bytes::from_static(b"abcd"));
        assert_ne!(segmented, Bytes::from_static(b"abce"));
        assert_ne!(segmented, EncodedReply::segmented(Bytes::from_static(b"ab"), Bytes::from_static(b"cd"), 1));
        assert_eq!(segmented.prefix(), b"ab");
        assert!(!segmented.is_empty());
        assert!(EncodedReply::from(Vec::new()).is_empty());
    }

    #[test]
    fn unknown_bytes_owners_are_compacted_for_replay_retention() {
        let large = Bytes::from(vec![7; 4096]);
        let reply = EncodedReply::from(large.slice(..16));
        assert!(reply.replay_storage_requires_copy());
        let (cached, retained_bytes) = reply.replay_storage();
        assert_eq!(cached, reply);
        assert!(!cached.replay_storage_requires_copy());
        assert!((16..4096).contains(&retained_bytes), "a slice must not charge or pin its parent allocation");
        assert_ne!(cached.segments()[0].as_ptr(), large.as_ptr());
    }

    #[test]
    fn vec_backing_capacity_is_charged_without_copying() {
        let mut value = Vec::with_capacity(1024);
        value.extend_from_slice(b"data");
        let pointer = value.as_ptr();
        let reply = EncodedReply::from(value);
        let (cached, retained_bytes) = reply.replay_storage();
        assert_eq!(cached.segments()[0].as_ptr(), pointer);
        assert!(retained_bytes >= 1024);
    }
}
