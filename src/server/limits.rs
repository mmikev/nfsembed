use std::time::Duration;

use crate::nfs3::dispatch::Procedure;
use crate::rpc::codec::Decoder;
use crate::rpc::record::RecordLimits;

/// Largest encoded reply of every procedure whose result has a fixed upper
/// bound: the RPC envelope plus CREATE with a maximum-size handle, post-op
/// attributes, and complete WCC data. Every other fixed-size NFS, MOUNT, and
/// portmapper result and every RPC error reply is smaller.
pub(crate) const MAXIMUM_FIXED_REPLY_SIZE: usize = 304;
const MAX_VALID_RPC_CALL_PREFIX_SIZE: usize = 440;
const MAX_FILE_HANDLE_XDR_SIZE: usize = 68;
const WRITE_ARGUMENT_FIXED_SIZE: usize = MAX_FILE_HANDLE_XDR_SIZE + 8 + 4 + 4 + 4;
const WRITE_PADDING_ALLOWANCE: usize = 3;
const MAXIMUM_WRITE_RECORD_OVERHEAD: usize =
    MAX_VALID_RPC_CALL_PREFIX_SIZE + WRITE_ARGUMENT_FIXED_SIZE + WRITE_PADDING_ALLOWANCE;
const MAXIMUM_READ_REPLY_OVERHEAD: usize = 24 + 4 + 88 + 4 + 4 + 4 + 3;
const READDIR_REPLY_OVERHEAD: usize = 24 + 4;

#[derive(Clone, Debug)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub max_requests_per_connection: usize,
    pub max_inflight_requests: usize,
    pub max_rpc_record_size: usize,
    pub max_rpc_fragment_size: usize,
    pub max_fragments_per_record: usize,
    pub max_buffered_request_bytes: usize,
    pub max_buffered_reply_bytes: usize,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub max_readdir_response_size: u32,
    pub request_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub replay_cache_capacity: usize,
    pub replay_cache_max_bytes: usize,
    pub replay_cache_ttl: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub max_mounts: usize,
}

impl ServerLimits {
    pub fn production_defaults() -> Self {
        Self {
            max_connections: 1024,
            max_requests_per_connection: 32,
            max_inflight_requests: 2048,
            max_rpc_record_size: 2 * 1024 * 1024,
            max_rpc_fragment_size: 1024 * 1024,
            max_fragments_per_record: 16,
            max_buffered_request_bytes: 64 * 1024 * 1024,
            max_buffered_reply_bytes: 64 * 1024 * 1024,
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            max_readdir_response_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            idle_connection_timeout: Duration::from_secs(120),
            replay_cache_capacity: 4096,
            replay_cache_max_bytes: 64 * 1024 * 1024,
            replay_cache_ttl: Duration::from_secs(120),
            graceful_shutdown_timeout: Duration::from_secs(10),
            max_mounts: 4096,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.max_connections == 0 {
            return Err("max_connections must be greater than zero");
        }
        if self.max_requests_per_connection == 0 || self.max_inflight_requests == 0 {
            return Err("request concurrency limits must be greater than zero");
        }
        if self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_requests_per_connection > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_inflight_requests > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err("connection and request limits exceed the runtime maximum");
        }
        if self.max_rpc_fragment_size == 0 || self.max_rpc_record_size < self.max_rpc_fragment_size {
            return Err("RPC record limit must be at least the non-zero fragment limit");
        }
        if self.max_rpc_fragment_size > 0x7fff_ffff || self.max_rpc_record_size > u32::MAX as usize {
            return Err("RPC record and fragment limits exceed wire or budgeting capacity");
        }
        if self.max_fragments_per_record == 0
            || self.replay_cache_capacity == 0
            || self.replay_cache_max_bytes == 0
            || self.max_mounts == 0
        {
            return Err("fragment, replay, and mount limits must be greater than zero");
        }
        if self.max_buffered_request_bytes < self.max_rpc_record_size
            || self.max_buffered_reply_bytes < self.max_rpc_record_size
            || self.max_buffered_request_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_buffered_reply_bytes > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err("buffer byte budgets must each hold one record and fit the runtime semaphore");
        }
        // RPC envelope plus the largest mutation result (CREATE with a
        // maximum-size handle, post-op attributes, and complete WCC data).
        // Rejecting smaller transports prevents a side effect from executing
        // when its only possible reply cannot be delivered.
        if self.max_rpc_record_size < MAXIMUM_FIXED_REPLY_SIZE
            || MAXIMUM_FIXED_REPLY_SIZE.div_ceil(self.max_rpc_fragment_size) > self.max_fragments_per_record
        {
            return Err("RPC limits must be able to carry every mutation reply");
        }
        let transport_capacity = self.transport_record_capacity();
        let read_capacity = transport_capacity.saturating_sub(MAXIMUM_READ_REPLY_OVERHEAD);
        let write_capacity = transport_capacity.saturating_sub(MAXIMUM_WRITE_RECORD_OVERHEAD);
        let readdir_capacity = transport_capacity.saturating_sub(READDIR_REPLY_OVERHEAD);
        if self.max_read_size == 0
            || self.max_write_size == 0
            || self.max_readdir_response_size == 0
            || self.max_read_size as usize > read_capacity
            || self.max_write_size as usize > write_capacity
            || self.max_readdir_response_size as usize > readdir_capacity
        {
            return Err("transfer limits exceed the effective RPC transport capacity");
        }
        Ok(())
    }

    pub(crate) fn transport_record_capacity(&self) -> usize {
        self.max_rpc_record_size
            .min(self.max_rpc_fragment_size.saturating_mul(self.max_fragments_per_record))
    }

    pub(crate) fn record_limits(&self) -> RecordLimits {
        RecordLimits {
            max_record_size: self.max_rpc_record_size,
            max_fragment_size: self.max_rpc_fragment_size,
            max_fragments: self.max_fragments_per_record,
        }
    }

    /// Returns an upper bound on the encoded reply to one call, which is the
    /// number of reply-buffer bytes reserved before the call executes. Only
    /// READ and READDIR(PLUS) replies scale with a client-requested count, and
    /// only READLINK, DUMP, and EXPORT carry backend- or table-sized lists
    /// that need the full record limit; every other reply, including every
    /// RPC-level error, fits in `MAXIMUM_FIXED_REPLY_SIZE`. A reply that
    /// would exceed its reservation is replaced by `SYSTEM_ERR`.
    pub(crate) fn reply_reservation(&self, program: u32, version: u32, procedure: u32, arguments: &[u8]) -> usize {
        // READ: handle, offset, count. READDIR: handle, cookie, verifier,
        // count. READDIRPLUS: handle, cookie, verifier, dircount, maxcount.
        let count_after = |skipped_words: usize| {
            let mut decoder = Decoder::new(arguments);
            decoder.read_opaque_slice("NFS file handle", 64).ok()?;
            for _ in 0..skipped_words {
                decoder.read_u32().ok()?;
            }
            decoder.read_u32().ok().map(|count| count as usize)
        };
        let bound = match (program, version) {
            (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION) => match Procedure::from_wire(procedure) {
                Some(Procedure::Read) => {
                    count_after(2).map(|count| MAXIMUM_READ_REPLY_OVERHEAD + count.min(self.max_read_size as usize))
                },
                Some(Procedure::ReadDir) => count_after(4)
                    .map(|count| READDIR_REPLY_OVERHEAD + count.min(self.max_readdir_response_size as usize)),
                Some(Procedure::ReadDirPlus) => count_after(5)
                    .map(|count| READDIR_REPLY_OVERHEAD + count.min(self.max_readdir_response_size as usize)),
                Some(Procedure::ReadLink) => Some(self.max_rpc_record_size),
                _ => None,
            },
            (crate::mount3::types::PROGRAM, crate::mount3::types::VERSION) if matches!(procedure, 2 | 5) => {
                Some(self.max_rpc_record_size)
            },
            _ => None,
        };
        bound.unwrap_or(0).max(MAXIMUM_FIXED_REPLY_SIZE).min(self.max_rpc_record_size)
    }
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self::production_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount3::codec::EncodeMountResult;
    use crate::mount3::types::MountResult;
    use crate::nfs3::codec::EncodeNfsResult;
    use crate::nfs3::procedures::{
        AccessResult, CommitResult, CreateResult, FsInfoResult, FsStatResult, GetAttrResult, LinkResult, LookupResult,
        PathConfResult, RenameResult, SetAttrResult, WccResult, WriteResult,
    };
    use crate::nfs3::types::WccData;
    use crate::rpc::codec::Encoder;
    use crate::vfs::{FileAttributes, FileType, FsInfo, FsStat, NfsTime, PathConf, WccAttributes, WriteStability};

    const RPC_ACCEPTED_REPLY_ENVELOPE: usize = 24;

    fn maximum_time() -> NfsTime {
        NfsTime {
            seconds: u64::from(u32::MAX),
            nanoseconds: 999_999_999,
        }
    }

    fn maximum_attributes() -> FileAttributes {
        FileAttributes {
            file_type: FileType::Regular,
            mode: u32::MAX,
            links: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            size: u64::MAX,
            used: u64::MAX,
            device: None,
            fs_id: u64::MAX,
            file_id: u64::MAX,
            access_time: maximum_time(),
            modify_time: maximum_time(),
            change_time: maximum_time(),
        }
    }

    fn maximum_wcc() -> WccData {
        WccData {
            before: Some(WccAttributes {
                size: u64::MAX,
                modify_time: maximum_time(),
                change_time: maximum_time(),
            }),
            after: Some(maximum_attributes()),
        }
    }

    fn reply_size(result: &impl EncodeNfsResult) -> usize {
        let mut body = Encoder::new();
        result.encode_result(&mut body).unwrap();
        body.len() + RPC_ACCEPTED_REPLY_ENVELOPE
    }

    #[test]
    fn fixed_reply_bound_is_exactly_the_largest_complete_union_arm() {
        let create = CreateResult::Ok {
            object_handle: Some(vec![0; 64]),
            object_attributes: Some(maximum_attributes()),
            directory_wcc: maximum_wcc(),
        };
        assert_eq!(reply_size(&create), MAXIMUM_FIXED_REPLY_SIZE);

        let attributes = Some(maximum_attributes());
        let fixed_results: Vec<(&str, usize)> = vec![
            (
                "GETATTR",
                reply_size(&GetAttrResult::Ok {
                    attributes: maximum_attributes(),
                }),
            ),
            (
                "SETATTR",
                reply_size(&SetAttrResult::Ok {
                    object_wcc: maximum_wcc(),
                }),
            ),
            (
                "LOOKUP",
                reply_size(&LookupResult::Ok {
                    object_handle: vec![0; 64],
                    object_attributes: attributes.clone(),
                    directory_attributes: attributes.clone(),
                }),
            ),
            (
                "ACCESS",
                reply_size(&AccessResult::Ok {
                    attributes: attributes.clone(),
                    access: u32::MAX,
                }),
            ),
            (
                "WRITE",
                reply_size(&WriteResult::Ok {
                    file_wcc: maximum_wcc(),
                    count: u32::MAX,
                    committed: WriteStability::FileSync,
                    verifier: [0xff; 8],
                }),
            ),
            (
                "REMOVE",
                reply_size(&WccResult::Ok {
                    object_wcc: maximum_wcc(),
                }),
            ),
            (
                "RENAME",
                reply_size(&RenameResult::Ok {
                    from_directory_wcc: maximum_wcc(),
                    to_directory_wcc: maximum_wcc(),
                }),
            ),
            (
                "LINK",
                reply_size(&LinkResult::Ok {
                    object_attributes: attributes.clone(),
                    directory_wcc: maximum_wcc(),
                }),
            ),
            (
                "FSSTAT",
                reply_size(&FsStatResult::Ok {
                    attributes: attributes.clone(),
                    info: FsStat::default(),
                }),
            ),
            (
                "FSINFO",
                reply_size(&FsInfoResult::Ok {
                    attributes: attributes.clone(),
                    info: FsInfo {
                        max_read: u32::MAX,
                        preferred_read: u32::MAX,
                        read_multiple: u32::MAX,
                        max_write: u32::MAX,
                        preferred_write: u32::MAX,
                        write_multiple: u32::MAX,
                        preferred_readdir: u32::MAX,
                        max_file_size: u64::MAX,
                        time_granularity: maximum_time(),
                    },
                    properties: u32::MAX,
                }),
            ),
            (
                "PATHCONF",
                reply_size(&PathConfResult::Ok {
                    attributes: attributes.clone(),
                    info: PathConf {
                        max_links: u32::MAX,
                        max_name_length: u32::MAX,
                        no_truncation: true,
                        chown_restricted: true,
                        case_insensitive: true,
                        case_preserving: true,
                    },
                }),
            ),
            (
                "COMMIT",
                reply_size(&CommitResult::Ok {
                    file_wcc: maximum_wcc(),
                    verifier: [0xff; 8],
                }),
            ),
            ("MNT", {
                let mut body = Encoder::new();
                MountResult::Ok {
                    file_handle: vec![0; 64],
                    auth_flavors: vec![1, 0],
                }
                .encode_result(&mut body)
                .unwrap();
                body.len() + RPC_ACCEPTED_REPLY_ENVELOPE
            }),
        ];
        for (procedure, size) in fixed_results {
            assert!(size <= MAXIMUM_FIXED_REPLY_SIZE, "{procedure} reply of {size} bytes exceeds the fixed bound");
        }
    }

    fn read_arguments(count: u32) -> Vec<u8> {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&[7; 45]).unwrap();
        arguments.write_u64(0);
        arguments.write_u32(count);
        arguments.into_bytes()
    }

    fn readdir_arguments(directory_count: Option<u32>, count: u32) -> Vec<u8> {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&[7; 45]).unwrap();
        arguments.write_u64(0);
        arguments.write_fixed(&[0; 8]);
        if let Some(directory_count) = directory_count {
            arguments.write_u32(directory_count);
        }
        arguments.write_u32(count);
        arguments.into_bytes()
    }

    #[test]
    fn reply_reservations_scale_only_with_requested_transfer_counts() {
        let limits = ServerLimits::production_defaults();
        let nfs = |procedure, arguments: &[u8]| limits.reply_reservation(100_003, 3, procedure, arguments);
        let full = limits.max_rpc_record_size;

        assert_eq!(nfs(6, &read_arguments(4096)), MAXIMUM_READ_REPLY_OVERHEAD + 4096);
        assert_eq!(nfs(6, &read_arguments(u32::MAX)), MAXIMUM_READ_REPLY_OVERHEAD + limits.max_read_size as usize);
        assert_eq!(nfs(6, &read_arguments(0)), MAXIMUM_FIXED_REPLY_SIZE);
        assert_eq!(nfs(6, &read_arguments(4096)[..20]), MAXIMUM_FIXED_REPLY_SIZE, "garbage arguments");
        assert_eq!(nfs(16, &readdir_arguments(None, 8192)), READDIR_REPLY_OVERHEAD + 8192);
        assert_eq!(
            nfs(17, &readdir_arguments(Some(1024), 65_536)),
            READDIR_REPLY_OVERHEAD + 65_536,
            "READDIRPLUS is bounded by maxcount, not dircount"
        );
        assert_eq!(
            nfs(17, &readdir_arguments(Some(1024), u32::MAX)),
            READDIR_REPLY_OVERHEAD + limits.max_readdir_response_size as usize
        );
        assert_eq!(nfs(5, &[]), full, "READLINK targets are backend-sized");
        for procedure in [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 22] {
            assert_eq!(nfs(procedure, &read_arguments(u32::MAX)), MAXIMUM_FIXED_REPLY_SIZE);
        }
        assert_eq!(limits.reply_reservation(100_003, 2, 6, &read_arguments(4096)), MAXIMUM_FIXED_REPLY_SIZE);

        for (procedure, expected) in [
            (0, MAXIMUM_FIXED_REPLY_SIZE),
            (1, MAXIMUM_FIXED_REPLY_SIZE),
            (2, full),
            (5, full),
        ] {
            assert_eq!(limits.reply_reservation(100_005, 3, procedure, &[]), expected);
        }
        assert_eq!(limits.reply_reservation(100_000, 2, 3, &[]), MAXIMUM_FIXED_REPLY_SIZE);
        assert_eq!(limits.reply_reservation(42, 1, 1, &[]), MAXIMUM_FIXED_REPLY_SIZE);
    }

    #[test]
    fn transfer_limits_include_protocol_and_fragment_overhead() {
        let mut limits = ServerLimits::production_defaults();
        limits.max_rpc_record_size = 1024;
        limits.max_rpc_fragment_size = 1024;
        limits.max_read_size = (1024 - MAXIMUM_READ_REPLY_OVERHEAD) as u32;
        limits.max_write_size = (1024 - MAXIMUM_WRITE_RECORD_OVERHEAD) as u32;
        limits.max_readdir_response_size = (1024 - READDIR_REPLY_OVERHEAD) as u32;
        assert!(limits.validate().is_ok());

        limits.max_write_size += 1;
        assert_eq!(limits.validate(), Err("transfer limits exceed the effective RPC transport capacity"));
    }
}
