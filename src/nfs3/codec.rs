use crate::nfs3::procedures::{
    AccessResult, CommitResult, CreateResult, FsInfoResult, FsStatResult, GetAttrResult, LinkResult, LookupResult,
    PathConfResult, ReadDirEntry, ReadDirEntryExtension, ReadDirResult, ReadLinkResult, ReadResult, RenameResult,
    SetAttrResult, WccResult, WriteResult,
};
use crate::nfs3::types::{FileAttributes, FileType, NfsStatus, NfsTime, WccData, WriteStability};
pub use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::vfs::DeviceNumber;

pub trait EncodeNfsResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
}

impl EncodeNfsResult for GetAttrResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_attributes(encoder, attributes)?;
            },
            Self::Err { status } => encoder.write_u32(*status as u32),
        }
        Ok(())
    }
}

impl EncodeNfsResult for LookupResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_handle,
                object_attributes,
                directory_attributes,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encoder.write_opaque(object_handle)?;
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
            Self::Err {
                status,
                directory_attributes,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for AccessResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, access } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(*access);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, data, eof } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(u32::try_from(data.len()).map_err(|_| EncodeError::TooLarge(data.len()))?);
                encoder.write_bool(*eof);
                encoder.write_opaque(data)?;
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for WriteResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                file_wcc,
                count,
                committed,
                verifier,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, file_wcc)?;
                encoder.write_u32(*count);
                encoder.write_u32(encode_stability(*committed));
                encoder.write_fixed(verifier);
            },
            Self::Err { status, file_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, file_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for CreateResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_handle,
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encoder.write_bool(object_handle.is_some());
                if let Some(handle) = object_handle {
                    encoder.write_opaque(handle)?;
                }
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
            Self::Err { status, directory_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for WccResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { object_wcc } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, object_wcc)?;
            },
            Self::Err { status, object_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, object_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for LinkResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
            Self::Err {
                status,
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadDirResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                directory_attributes,
                verifier,
                entries,
                eof,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
                encoder.write_fixed(verifier);
                for entry in entries {
                    encode_readdir_entry(encoder, entry)?;
                }
                encoder.write_bool(false);
                encoder.write_bool(*eof);
            },
            Self::Err {
                status,
                directory_attributes,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for FsStatResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, info } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u64(info.total_bytes);
                encoder.write_u64(info.free_bytes);
                encoder.write_u64(info.available_bytes);
                encoder.write_u64(info.total_files);
                encoder.write_u64(info.free_files);
                encoder.write_u64(info.available_files);
                encoder.write_u32(info.invariant_seconds);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for PathConfResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, info } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(info.max_links);
                encoder.write_u32(info.max_name_length);
                encoder.write_bool(info.no_truncation);
                encoder.write_bool(info.chown_restricted);
                encoder.write_bool(info.case_insensitive);
                encoder.write_bool(info.case_preserving);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for CommitResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { file_wcc, verifier } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, file_wcc)?;
                encoder.write_fixed(verifier);
            },
            Self::Err { status, file_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, file_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for SetAttrResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { object_wcc } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, object_wcc)?;
            },
            Self::Err { status, object_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, object_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for RenameResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                from_directory_wcc,
                to_directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, from_directory_wcc)?;
                encode_wcc(encoder, to_directory_wcc)?;
            },
            Self::Err {
                status,
                from_directory_wcc,
                to_directory_wcc,
            } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, from_directory_wcc)?;
                encode_wcc(encoder, to_directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadLinkResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, path } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_opaque(path)?;
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for FsInfoResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                attributes,
                info,
                properties,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(info.max_read);
                encoder.write_u32(info.preferred_read);
                encoder.write_u32(info.read_multiple);
                encoder.write_u32(info.max_write);
                encoder.write_u32(info.preferred_write);
                encoder.write_u32(info.write_multiple);
                encoder.write_u32(info.preferred_readdir);
                encoder.write_u64(info.max_file_size);
                encode_time(encoder, info.time_granularity)?;
                encoder.write_u32(*properties);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

pub fn encode_readdir_entry(encoder: &mut Encoder, entry: &ReadDirEntry) -> Result<(), EncodeError> {
    encoder.write_bool(true);
    encoder.write_u64(entry.file_id);
    encoder.write_opaque(&entry.name)?;
    encoder.write_u64(entry.cookie);
    match &entry.extension {
        ReadDirEntryExtension::Basic => {},
        ReadDirEntryExtension::Plus { attributes, handle } => {
            encode_post_attributes(encoder, attributes.as_ref())?;
            encoder.write_bool(handle.is_some());
            if let Some(handle) = handle {
                encoder.write_opaque(handle)?;
            }
        },
    }
    Ok(())
}

/// XDR size of `fattr3`.
pub const FATTR3_SIZE: usize = 84;
/// XDR size of a `READDIR3resok` without entries or directory attributes:
/// the post-op attribute flag, cookie verifier, list terminator, and eof.
const EMPTY_READDIR_SIZE: usize = 4 + 8 + 4 + 4;

/// Size limits for one READDIR or READDIRPLUS result (RFC 1813).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadDirLimits {
    /// Maximum size of the `READDIR3resok`/`READDIRPLUS3resok` value,
    /// excluding the status discriminant (`count` or `maxcount`).
    pub max_size: usize,
    /// READDIRPLUS `dircount`: maximum bytes of directory information,
    /// counting each entry without its attributes and file handle.
    pub directory_size: Option<usize>,
}

/// Encodes a complete READDIR or READDIRPLUS result with the production size
/// policy, pulling entries from `entries` only while they fit:
///
/// * directory attributes are omitted when they alone exceed `max_size`;
/// * entries stop at the first one that would exceed `max_size` or the `dircount` budget, and a truncated listing never
///   reports `eof`;
/// * `NFS3ERR_TOOSMALL` is returned when not even an empty listing, or the first available entry, fits.
pub fn encode_readdir_reply(
    encoder: &mut Encoder,
    directory_attributes: Option<&FileAttributes>,
    verifier: [u8; 8],
    entries: impl IntoIterator<Item = ReadDirEntry>,
    eof: bool,
    limits: ReadDirLimits,
) -> Result<(), EncodeError> {
    let start = encoder.len();
    let attributes = directory_attributes.filter(|_| EMPTY_READDIR_SIZE + FATTR3_SIZE <= limits.max_size);
    let mut used = EMPTY_READDIR_SIZE + attributes.map_or(0, |_| FATTR3_SIZE);
    if used > limits.max_size {
        return encode_readdir_too_small(encoder, directory_attributes);
    }
    encoder.write_u32(NfsStatus::Ok as u32);
    encode_post_attributes(encoder, attributes)?;
    encoder.write_fixed(&verifier);
    let mut directory_used = 0usize;
    let mut encoded_any = false;
    let mut truncated = false;
    for entry in entries {
        let (directory_bytes, total_bytes) = readdir_entry_size(&entry);
        // The list terminator also counts toward `dircount`.
        let directory_fits = limits
            .directory_size
            .is_none_or(|limit| directory_used + directory_bytes + 4 <= limit);
        if !directory_fits || used + total_bytes > limits.max_size {
            truncated = true;
            break;
        }
        directory_used += directory_bytes;
        used += total_bytes;
        encode_readdir_entry(encoder, &entry)?;
        encoded_any = true;
    }
    if truncated && !encoded_any {
        encoder.truncate(start);
        return encode_readdir_too_small(encoder, directory_attributes);
    }
    encoder.write_bool(false);
    encoder.write_bool(eof && !truncated);
    Ok(())
}

fn encode_readdir_too_small(encoder: &mut Encoder, attributes: Option<&FileAttributes>) -> Result<(), EncodeError> {
    encoder.write_u32(NfsStatus::TooSmall as u32);
    encode_post_attributes(encoder, attributes)
}

/// Returns the XDR size of one directory entry as `(directory information,
/// complete entry)`, both including the entry's list discriminant.
fn readdir_entry_size(entry: &ReadDirEntry) -> (usize, usize) {
    let directory_bytes = 4 + 8 + xdr_opaque_size(entry.name.len()) + 8;
    let extension_bytes = match &entry.extension {
        ReadDirEntryExtension::Basic => 0,
        ReadDirEntryExtension::Plus { attributes, handle } => {
            let attributes = attributes.as_ref().map_or(0, |_| FATTR3_SIZE);
            let handle = handle.as_ref().map_or(0, |handle| xdr_opaque_size(handle.len()));
            4 + attributes + 4 + handle
        },
    };
    (directory_bytes, directory_bytes + extension_bytes)
}

fn xdr_opaque_size(length: usize) -> usize {
    4 + length.next_multiple_of(4)
}

fn encode_stability(stability: WriteStability) -> u32 {
    match stability {
        WriteStability::Unstable => 0,
        WriteStability::DataSync => 1,
        WriteStability::FileSync => 2,
    }
}

pub fn encode_attributes(encoder: &mut Encoder, attributes: &FileAttributes) -> Result<(), EncodeError> {
    encoder.write_u32(match attributes.file_type {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::BlockDevice => 3,
        FileType::CharacterDevice => 4,
        FileType::Symlink => 5,
        FileType::Socket => 6,
        FileType::Fifo => 7,
    });
    encoder.write_u32(attributes.mode);
    encoder.write_u32(attributes.links);
    encoder.write_u32(attributes.uid);
    encoder.write_u32(attributes.gid);
    encoder.write_u64(attributes.size);
    encoder.write_u64(attributes.used);
    let device = if matches!(attributes.file_type, FileType::BlockDevice | FileType::CharacterDevice) {
        attributes.device.unwrap_or_default()
    } else {
        DeviceNumber::default()
    };
    encoder.write_u32(device.major);
    encoder.write_u32(device.minor);
    encoder.write_u64(attributes.fs_id);
    encoder.write_u64(attributes.file_id);
    encode_time(encoder, attributes.access_time)?;
    encode_time(encoder, attributes.modify_time)?;
    encode_time(encoder, attributes.change_time)?;
    Ok(())
}

pub fn encode_post_attributes(encoder: &mut Encoder, attributes: Option<&FileAttributes>) -> Result<(), EncodeError> {
    encoder.write_bool(attributes.is_some());
    if let Some(attributes) = attributes {
        encode_attributes(encoder, attributes)?;
    }
    Ok(())
}

pub fn encode_wcc(encoder: &mut Encoder, wcc: &WccData) -> Result<(), EncodeError> {
    encoder.write_bool(wcc.before.is_some());
    if let Some(attributes) = &wcc.before {
        encoder.write_u64(attributes.size);
        encode_time(encoder, attributes.modify_time)?;
        encode_time(encoder, attributes.change_time)?;
    }
    encode_post_attributes(encoder, wcc.after.as_ref())?;
    Ok(())
}

pub fn encode_time(encoder: &mut Encoder, time: NfsTime) -> Result<(), EncodeError> {
    let seconds = u32::try_from(time.seconds).map_err(|_| EncodeError::InvalidTime {
        seconds: time.seconds,
        nanoseconds: time.nanoseconds,
    })?;
    if time.nanoseconds > 999_999_999 {
        return Err(EncodeError::InvalidTime {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        });
    }
    encoder.write_u32(seconds);
    encoder.write_u32(time.nanoseconds);
    Ok(())
}

#[cfg(test)]
fn encode_getattr_for_test(result: &GetAttrResult) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    result.encode_result(&mut encoder)?;
    Ok(encoder.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::DeviceNumber;

    #[test]
    fn setattr_failure_is_one_complete_wcc_result() {
        let result = SetAttrResult::Err {
            status: NfsStatus::NotSynchronized,
            object_wcc: WccData::default(),
        };
        let mut encoder = Encoder::new();
        result.encode_result(&mut encoder).unwrap();
        assert_eq!(encoder.into_bytes(), [10002u32.to_be_bytes(), 0u32.to_be_bytes(), 0u32.to_be_bytes()].concat());
    }

    #[test]
    fn rename_failure_contains_both_wcc_arms() {
        let result = RenameResult::Err {
            status: NfsStatus::Access,
            from_directory_wcc: WccData::default(),
            to_directory_wcc: WccData::default(),
        };
        let mut encoder = Encoder::new();
        result.encode_result(&mut encoder).unwrap();
        assert_eq!(encoder.len(), 20);
    }

    #[test]
    fn device_numbers_are_preserved_in_file_attributes() {
        let attributes = FileAttributes {
            file_type: FileType::BlockDevice,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: Some(DeviceNumber { major: 12, minor: 34 }),
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        let mut encoder = Encoder::new();
        encode_attributes(&mut encoder, &attributes).unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(u32::from_be_bytes(bytes[36..40].try_into().unwrap()), 12);
        assert_eq!(u32::from_be_bytes(bytes[40..44].try_into().unwrap()), 34);
    }

    #[test]
    fn device_numbers_are_zeroed_for_non_device_file_types() {
        let attributes = FileAttributes {
            file_type: FileType::Regular,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: Some(DeviceNumber { major: 12, minor: 34 }),
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        let mut encoder = Encoder::new();
        encode_attributes(&mut encoder, &attributes).unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(u32::from_be_bytes(bytes[36..40].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(bytes[40..44].try_into().unwrap()), 0);
    }

    #[test]
    fn out_of_range_backend_times_are_rejected_instead_of_clamped() {
        let attributes = FileAttributes {
            file_type: FileType::Regular,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: None,
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime {
                seconds: u64::from(u32::MAX) + 1,
                nanoseconds: 0,
            },
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        assert!(matches!(
            encode_getattr_for_test(&GetAttrResult::Ok { attributes }),
            Err(EncodeError::InvalidTime { .. })
        ));
    }

    fn readdir_attributes() -> FileAttributes {
        FileAttributes {
            file_type: FileType::Directory,
            mode: 0o755,
            links: 2,
            uid: 0,
            gid: 0,
            size: 4096,
            used: 4096,
            device: None,
            fs_id: 1,
            file_id: 1,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        }
    }

    fn readdir_entries(plus: bool) -> Vec<ReadDirEntry> {
        (0..24)
            .map(|index| ReadDirEntry {
                file_id: index,
                name: vec![b'n'; index as usize % 11 + 1],
                cookie: index + 1,
                extension: if plus {
                    ReadDirEntryExtension::Plus {
                        attributes: (index % 3 != 0).then(readdir_attributes),
                        handle: (index % 5 != 0).then(|| vec![9; 45]),
                    }
                } else {
                    ReadDirEntryExtension::Basic
                },
            })
            .collect()
    }

    fn encoded_len(encode: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>) -> usize {
        let mut encoder = Encoder::new();
        encode(&mut encoder).unwrap();
        encoder.len()
    }

    /// The pre-streaming production policy, which sized every candidate by
    /// fully encoding it. Kept as an oracle for `encode_readdir_reply`.
    fn readdir_reference(
        attributes: Option<&FileAttributes>,
        entries: &[ReadDirEntry],
        eof: bool,
        limits: ReadDirLimits,
    ) -> Vec<u8> {
        let too_small = || {
            let mut encoder = Encoder::new();
            ReadDirResult::Err {
                status: NfsStatus::TooSmall,
                directory_attributes: attributes.cloned(),
            }
            .encode_result(&mut encoder)
            .unwrap();
            encoder.into_bytes()
        };
        let empty_size = |attributes: Option<&FileAttributes>| {
            let empty = ReadDirResult::Ok {
                directory_attributes: attributes.cloned(),
                verifier: [3; 8],
                entries: Vec::new(),
                eof: false,
            };
            encoded_len(|encoder| empty.encode_result(encoder)) - 4
        };
        let mut selected = attributes;
        if empty_size(selected) > limits.max_size {
            selected = None;
        }
        if empty_size(selected) > limits.max_size {
            return too_small();
        }
        let mut used = empty_size(selected);
        let mut directory_used = 0;
        let mut kept = Vec::new();
        let mut truncated = false;
        for entry in entries {
            let basic = ReadDirEntry {
                extension: ReadDirEntryExtension::Basic,
                ..entry.clone()
            };
            let directory_bytes = encoded_len(|encoder| encode_readdir_entry(encoder, &basic));
            let total_bytes = encoded_len(|encoder| encode_readdir_entry(encoder, entry));
            if limits
                .directory_size
                .is_some_and(|limit| directory_used + directory_bytes + 4 > limit)
                || used + total_bytes > limits.max_size
            {
                truncated = true;
                break;
            }
            directory_used += directory_bytes;
            used += total_bytes;
            kept.push(entry.clone());
        }
        if truncated && kept.is_empty() {
            return too_small();
        }
        let mut encoder = Encoder::new();
        ReadDirResult::Ok {
            directory_attributes: selected.cloned(),
            verifier: [3; 8],
            entries: kept,
            eof: eof && !truncated,
        }
        .encode_result(&mut encoder)
        .unwrap();
        encoder.into_bytes()
    }

    #[test]
    fn streaming_readdir_encoder_matches_the_reference_policy() {
        let attributes = readdir_attributes();
        for plus in [false, true] {
            let entries = readdir_entries(plus);
            for directory_attributes in [None, Some(&attributes)] {
                for directory_size in [None, Some(0), Some(64), Some(300), Some(10_000)] {
                    for max_size in (0..=3000).step_by(13) {
                        for eof in [false, true] {
                            let limits = ReadDirLimits {
                                max_size,
                                directory_size,
                            };
                            let mut actual = Encoder::new();
                            encode_readdir_reply(
                                &mut actual,
                                directory_attributes,
                                [3; 8],
                                entries.clone(),
                                eof,
                                limits,
                            )
                            .unwrap();
                            let actual = actual.into_bytes();
                            let expected = readdir_reference(directory_attributes, &entries, eof, limits);
                            assert_eq!(actual, expected, "plus={plus} limits={limits:?} eof={eof}");
                            if actual[..4] == [0; 4] {
                                assert!(actual.len() - 4 <= max_size);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn readdir_entries_are_only_pulled_while_they_fit() {
        let entries = readdir_entries(true);
        let mut pulled = 0;
        let mut encoder = Encoder::new();
        encode_readdir_reply(
            &mut encoder,
            None,
            [0; 8],
            entries.into_iter().inspect(|_| pulled += 1),
            true,
            ReadDirLimits {
                max_size: 400,
                directory_size: None,
            },
        )
        .unwrap();
        let reply = encoder.into_bytes();
        let mut decoder = Decoder::new(&reply);
        assert_eq!(decoder.read_u32(), Ok(NfsStatus::Ok as u32));
        assert_eq!(decoder.read_bool(), Ok(false));
        decoder.read_fixed::<8>().unwrap();
        let mut kept = 0;
        while decoder.read_bool().unwrap() {
            kept += 1;
            decoder.read_u64().unwrap();
            decoder.read_opaque("name", 255).unwrap();
            decoder.read_u64().unwrap();
            if decoder.read_bool().unwrap() {
                decoder.read_fixed::<FATTR3_SIZE>().unwrap();
            }
            if decoder.read_bool().unwrap() {
                decoder.read_opaque("handle", 64).unwrap();
            }
        }
        assert_eq!(decoder.read_bool(), Ok(false), "a truncated listing must not report eof");
        decoder.finish().unwrap();
        assert!(kept > 0);
        assert_eq!(pulled, kept + 1, "only the first rejected entry may be pulled");
    }

    #[test]
    fn readdir_without_room_for_one_entry_is_too_small_and_keeps_attributes() {
        let attributes = readdir_attributes();
        let mut encoder = Encoder::new();
        encode_readdir_reply(
            &mut encoder,
            Some(&attributes),
            [0; 8],
            readdir_entries(false),
            true,
            ReadDirLimits {
                max_size: EMPTY_READDIR_SIZE + 4,
                directory_size: None,
            },
        )
        .unwrap();
        let reply = encoder.into_bytes();
        let mut decoder = Decoder::new(&reply);
        assert_eq!(decoder.read_u32(), Ok(NfsStatus::TooSmall as u32));
        assert_eq!(decoder.read_bool(), Ok(true));
        decoder.read_fixed::<FATTR3_SIZE>().unwrap();
        decoder.finish().unwrap();

        let mut empty_directory = Encoder::new();
        encode_readdir_reply(
            &mut empty_directory,
            Some(&attributes),
            [0; 8],
            Vec::new(),
            true,
            ReadDirLimits {
                max_size: EMPTY_READDIR_SIZE,
                directory_size: None,
            },
        )
        .unwrap();
        assert_eq!(
            empty_directory.into_bytes(),
            [0u32, 0, 0, 0, 0, 1]
                .iter()
                .flat_map(|word| word.to_be_bytes())
                .collect::<Vec<_>>(),
            "an empty directory fits without attributes and reports eof"
        );
    }
}
