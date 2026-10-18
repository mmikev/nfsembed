mod capabilities;
mod context;
mod types;

use async_trait::async_trait;
pub use capabilities::VfsCapabilities;
pub use context::{ExportId, Principal, RequestContext};
pub use types::*;

/// Application-provided virtual filesystem contract for NFSv3.
///
/// Unsupported optional operations have safe `NFS3ERR_NOTSUPP` defaults.
/// Operation futures are cancelled when the configured request deadline is
/// reached. Mutation implementations must therefore keep irreversible work
/// cancellation-safe and must not detach untracked work from the returned
/// future.
#[async_trait]
pub trait VirtualFileSystem: Send + Sync + 'static {
    fn capabilities(&self) -> VfsCapabilities;
    fn root(&self) -> ObjectKey;

    #[doc(hidden)]
    fn unsupported_mutation(&self) -> NfsError {
        if self.capabilities().read_only {
            NfsError::ReadOnly
        } else {
            NfsError::NotSupported
        }
    }

    async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError>;

    async fn lookup(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError>;

    async fn access(&self, _context: &RequestContext, _object: ObjectKey, _requested: u32) -> Result<u32, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn setattr(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _attributes: SetAttributes,
        _guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn readlink(&self, _context: &RequestContext, _object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn read(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<ReadResult, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Zero-copy read extension. Existing implementations only need to
    /// implement `read`; converting its `Vec` result into `Bytes` transfers
    /// ownership without copying. Backends with immutable shared storage can
    /// override this method directly.
    async fn read_bytes(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadBytesResult, NfsError> {
        self.read(context, object, offset, count).await.map(Into::into)
    }

    async fn write(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _data: &[u8],
        _requested: WriteStability,
    ) -> Result<MutationResult<WriteResult>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn create(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
        _mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn mkdir(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn symlink(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _target: &[u8],
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn mknod(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _node_type: NodeType,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn remove(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn rmdir(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn rename(
        &self,
        _context: &RequestContext,
        _from_parent: ObjectKey,
        _from_name: &NfsName,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn link(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        _directory: ObjectKey,
        _cookie: u64,
        _verifier: [u8; 8],
        _backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn fsstat(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn fsinfo(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn pathconf(&self, _context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn commit(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadOnlyDefaults;

    #[async_trait]
    impl VirtualFileSystem for ReadOnlyDefaults {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn root(&self) -> ObjectKey {
            ObjectKey {
                file_id: 1,
                generation: 1,
            }
        }

        async fn getattr(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FileAttributes, NfsError> {
            Err(NfsError::NotSupported)
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotSupported)
        }
    }

    #[tokio::test]
    async fn default_access_requires_an_authoritative_backend_answer() {
        let context = RequestContext {
            principal: Principal::Anonymous,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            export_id: ExportId(1),
        };
        assert_eq!(ReadOnlyDefaults.access(&context, ReadOnlyDefaults.root(), 0x3f).await, Err(NfsError::NotSupported));
    }
}
