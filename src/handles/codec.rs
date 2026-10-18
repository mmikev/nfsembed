use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::vfs::{ExportId, ObjectKey};

type HmacSha256 = Hmac<Sha256>;

const FORMAT_VERSION: u8 = 1;
const INSTANCE_SIZE: usize = 8;
const TAG_SIZE: usize = 16;
const PAYLOAD_SIZE: usize = 1 + INSTANCE_SIZE + 4 + 8 + 8;
pub const HANDLE_SIZE: usize = PAYLOAD_SIZE + TAG_SIZE;
const _: () = assert!(HANDLE_SIZE <= 64);

#[derive(Clone)]
pub struct HandleCodec {
    instance_id: [u8; INSTANCE_SIZE],
    // Keep the keyed HMAC state initialized; cloning it is cheaper than
    // rebuilding the key schedule for every handle encode or verification.
    mac: HmacSha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HandleError {
    #[error("invalid file-handle length")]
    InvalidLength,
    #[error("unsupported file-handle format")]
    InvalidFormat,
    #[error("file handle belongs to a different server instance")]
    StaleInstance,
    #[error("file handle belongs to a different export")]
    WrongExport,
    #[error("file-handle integrity check failed")]
    InvalidTag,
}

impl HandleCodec {
    pub fn random() -> Self {
        Self::try_random().expect("operating-system random source is unavailable")
    }

    pub fn try_random() -> Result<Self, rand::Error> {
        let mut instance_id = [0; INSTANCE_SIZE];
        let mut secret = [0; 32];
        OsRng.try_fill_bytes(&mut instance_id)?;
        OsRng.try_fill_bytes(&mut secret)?;
        let mac = HmacSha256::new_from_slice(&secret).expect("HMAC accepts any key size");
        Ok(Self { instance_id, mac })
    }

    pub fn encode(&self, export_id: ExportId, object: ObjectKey) -> [u8; HANDLE_SIZE] {
        let mut handle = [0; HANDLE_SIZE];
        handle[0] = FORMAT_VERSION;
        handle[1..9].copy_from_slice(&self.instance_id);
        handle[9..13].copy_from_slice(&export_id.0.to_be_bytes());
        handle[13..21].copy_from_slice(&object.file_id.to_be_bytes());
        handle[21..29].copy_from_slice(&object.generation.to_be_bytes());
        let tag = self.tag(&handle[..PAYLOAD_SIZE]);
        handle[PAYLOAD_SIZE..].copy_from_slice(&tag);
        handle
    }

    pub fn decode(&self, export_id: ExportId, handle: &[u8]) -> Result<ObjectKey, HandleError> {
        let (encoded_export, object) = self.decode_any(handle)?;
        if encoded_export != export_id {
            return Err(HandleError::WrongExport);
        }
        Ok(object)
    }

    pub fn decode_any(&self, handle: &[u8]) -> Result<(ExportId, ObjectKey), HandleError> {
        let encoded_export = self.peek_export(handle)?;
        let mut mac = self.mac.clone();
        mac.update(&handle[..PAYLOAD_SIZE]);
        mac.verify_truncated_left(&handle[PAYLOAD_SIZE..])
            .map_err(|_| HandleError::InvalidTag)?;
        let file_id = u64::from_be_bytes(handle[13..21].try_into().map_err(|_| HandleError::InvalidLength)?);
        let generation = u64::from_be_bytes(handle[21..29].try_into().map_err(|_| HandleError::InvalidLength)?);
        Ok((encoded_export, ObjectKey { file_id, generation }))
    }

    /// Checks a handle's length, format, and server instance and returns its
    /// export ID **without** verifying the integrity tag. This is only a
    /// routing hint: every object must still be resolved through `decode`,
    /// which authenticates the complete handle before the VFS sees it.
    pub(crate) fn peek_export(&self, handle: &[u8]) -> Result<ExportId, HandleError> {
        if handle.len() != HANDLE_SIZE {
            return Err(HandleError::InvalidLength);
        }
        if handle[0] != FORMAT_VERSION {
            return Err(HandleError::InvalidFormat);
        }
        if handle[1..9] != self.instance_id {
            return Err(HandleError::StaleInstance);
        }
        let export = handle[9..13].try_into().map_err(|_| HandleError::InvalidLength)?;
        Ok(ExportId(u32::from_be_bytes(export)))
    }

    pub fn instance_id(&self) -> [u8; INSTANCE_SIZE] {
        self.instance_id
    }

    fn tag(&self, payload: &[u8]) -> [u8; TAG_SIZE] {
        let mut mac = self.mac.clone();
        mac.update(payload);
        let bytes = mac.finalize().into_bytes();
        let mut tag = [0; TAG_SIZE];
        tag.copy_from_slice(&bytes[..TAG_SIZE]);
        tag
    }
}

impl std::fmt::Debug for HandleCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleCodec")
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_scope_checks() {
        let codec = HandleCodec::random();
        let key = ObjectKey {
            file_id: 42,
            generation: 7,
        };
        let handle = codec.encode(ExportId(3), key);
        assert_eq!(codec.decode(ExportId(3), &handle), Ok(key));
        assert_eq!(codec.decode(ExportId(4), &handle), Err(HandleError::WrongExport));
        assert_eq!(HandleCodec::random().decode(ExportId(3), &handle), Err(HandleError::StaleInstance));
    }

    #[test]
    fn forged_handle_is_rejected() {
        let codec = HandleCodec::random();
        let mut handle = codec.encode(
            ExportId(1),
            ObjectKey {
                file_id: 1,
                generation: 1,
            },
        );
        handle[15] ^= 1;
        assert_eq!(codec.decode(ExportId(1), &handle), Err(HandleError::InvalidTag));
    }

    #[test]
    fn malformed_handles_are_classified_before_tag_verification() {
        let codec = HandleCodec::random();
        let handle = codec.encode(
            ExportId(5),
            ObjectKey {
                file_id: 1,
                generation: 1,
            },
        );
        assert_eq!(codec.decode(ExportId(5), &handle[..HANDLE_SIZE - 1]), Err(HandleError::InvalidLength));
        assert_eq!(codec.decode(ExportId(5), &[handle.as_slice(), &[0]].concat()), Err(HandleError::InvalidLength));
        let mut wrong_format = handle;
        wrong_format[0] = FORMAT_VERSION + 1;
        assert_eq!(codec.decode(ExportId(5), &wrong_format), Err(HandleError::InvalidFormat));
        assert_eq!(codec.peek_export(&handle), Ok(ExportId(5)));
        assert_eq!(HandleCodec::random().peek_export(&handle), Err(HandleError::StaleInstance));

        // The routing hint is unauthenticated: a forged export ID is still
        // rejected when the handle is decoded for that export.
        let mut forged_export = handle;
        forged_export[12] ^= 1;
        assert_eq!(codec.peek_export(&forged_export), Ok(ExportId(4)));
        assert_eq!(codec.decode(ExportId(4), &forged_export), Err(HandleError::InvalidTag));
    }

    #[test]
    fn every_single_byte_forgery_is_rejected() {
        let codec = HandleCodec::random();
        let handle = codec.encode(
            ExportId(9),
            ObjectKey {
                file_id: 11,
                generation: 13,
            },
        );
        for index in 0..handle.len() {
            let mut forged = handle;
            forged[index] ^= 0x80;
            assert!(codec.decode(ExportId(9), &forged).is_err(), "byte {index} was not authenticated");
        }
    }
}
