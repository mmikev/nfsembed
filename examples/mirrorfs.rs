use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::io;
use std::io::SeekFrom;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nfsembed::vfs::{
    CreateMode, CreatedObject, DirectoryEntry, FileAttributes, FileType, FsInfo, FsStat, MutationResult, NfsError,
    NfsName, NfsTime, ObjectKey, PathConf, ReadDirectoryPage, ReadResult, RequestContext, SetAttributes, SetTime,
    VfsCapabilities, VirtualFileSystem, WccAttributes, WriteResult, WriteStability,
};
use nfsembed::{AuthPolicy, NfsServer, PortmapperSockets};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::debug;

const ROOT_ID: u64 = 1;
const GENERATION: u64 = 1;

#[cfg(unix)]
type RelativeKey = Vec<OsString>;
#[cfg(windows)]
type RelativeKey = Vec<Vec<u16>>;
type ExclusiveVerifierBucket = Vec<(Vec<OsString>, [u8; 8])>;

#[derive(Debug)]
struct FsMap {
    root: PathBuf,
    next_file_id: u64,
    id_to_relative: HashMap<u64, Vec<OsString>>,
    id_to_key: HashMap<u64, RelativeKey>,
    relative_to_id: HashMap<RelativeKey, Vec<u64>>,
    exclusive_verifiers: HashMap<RelativeKey, ExclusiveVerifierBucket>,
}

impl FsMap {
    fn new(root: PathBuf) -> Self {
        let root_key = RelativeKey::new();
        Self {
            root,
            next_file_id: ROOT_ID + 1,
            id_to_relative: HashMap::from([(ROOT_ID, Vec::new())]),
            id_to_key: HashMap::from([(ROOT_ID, root_key.clone())]),
            relative_to_id: HashMap::from([(root_key, vec![ROOT_ID])]),
            exclusive_verifiers: HashMap::new(),
        }
    }

    fn relative(&self, object: ObjectKey) -> Result<Vec<OsString>, NfsError> {
        if object.generation != GENERATION {
            return Err(NfsError::Stale);
        }
        self.id_to_relative.get(&object.file_id).cloned().ok_or(NfsError::Stale)
    }

    fn path(&self, relative: &[OsString]) -> PathBuf {
        let mut path = self.root.clone();
        path.extend(relative);
        path
    }

    fn child_relative(&self, parent: ObjectKey, name: &NfsName) -> Result<Vec<OsString>, NfsError> {
        let mut relative = self.relative(parent)?;
        relative.push(nfs_name_to_os_string(name)?);
        Ok(relative)
    }

    fn intern(&mut self, relative: Vec<OsString>) -> Result<u64, NfsError> {
        let key = relative_key(&relative)?;
        if let Some(file_ids) = self.relative_to_id.get(&key) {
            if let Some(file_id) = file_ids.iter().find(|file_id| {
                self.id_to_relative
                    .get(file_id)
                    .is_some_and(|candidate| relative_eq(candidate, &relative))
            }) {
                return Ok(*file_id);
            }
        }
        let file_id = self.next_file_id;
        self.next_file_id += 1;
        self.id_to_relative.insert(file_id, relative);
        self.id_to_key.insert(file_id, key.clone());
        self.relative_to_id.entry(key).or_default().push(file_id);
        Ok(file_id)
    }

    fn remove_indexed_id(&mut self, key: &RelativeKey, file_id: u64) {
        let remove_key = if let Some(file_ids) = self.relative_to_id.get_mut(key) {
            file_ids.retain(|candidate| *candidate != file_id);
            file_ids.is_empty()
        } else {
            false
        };
        if remove_key {
            self.relative_to_id.remove(key);
        }
    }

    fn forget_prefix(&mut self, prefix: &[OsString]) -> Result<(), NfsError> {
        let prefix_key = relative_key(prefix)?;
        let forgotten = self
            .id_to_key
            .iter()
            .filter(|(file_id, key)| {
                key.starts_with(&prefix_key)
                    && self
                        .id_to_relative
                        .get(file_id)
                        .is_some_and(|relative| relative_starts_with(relative, prefix))
            })
            .map(|(file_id, _)| *file_id)
            .collect::<Vec<_>>();
        for file_id in forgotten {
            self.id_to_relative.remove(&file_id);
            if let Some(key) = self.id_to_key.remove(&file_id) {
                self.remove_indexed_id(&key, file_id);
            }
        }
        self.exclusive_verifiers.retain(|key, verifiers| {
            if key.starts_with(&prefix_key) {
                verifiers.retain(|(relative, _)| !relative_starts_with(relative, prefix));
            }
            !verifiers.is_empty()
        });
        Ok(())
    }

    fn move_prefix(&mut self, from: &[OsString], to: &[OsString]) -> Result<(), NfsError> {
        let from_key = relative_key(from)?;
        let to_key = relative_key(to)?;
        if !relative_eq(from, to) {
            self.forget_prefix(to)?;
        }
        let moved = self
            .id_to_key
            .iter()
            .filter(|(file_id, key)| {
                key.starts_with(&from_key)
                    && self
                        .id_to_relative
                        .get(file_id)
                        .is_some_and(|relative| relative_starts_with(relative, from))
            })
            .map(|(file_id, key)| (*file_id, key.clone()))
            .collect::<Vec<_>>();
        for (file_id, old_key) in moved {
            let old_relative = self.id_to_relative.get(&file_id).cloned().ok_or(NfsError::Stale)?;
            let mut new_relative = to.to_vec();
            new_relative.extend_from_slice(&old_relative[from.len()..]);
            let mut new_key = to_key.clone();
            new_key.extend_from_slice(&old_key[from_key.len()..]);

            self.id_to_relative.insert(file_id, new_relative.clone());
            self.id_to_key.insert(file_id, new_key.clone());
            self.remove_indexed_id(&old_key, file_id);
            self.relative_to_id.entry(new_key.clone()).or_default().push(file_id);
            if let Some(verifier) = self.take_exclusive_verifier(&old_key, &old_relative) {
                self.exclusive_verifiers
                    .entry(new_key)
                    .or_default()
                    .push((new_relative, verifier));
            }
        }
        Ok(())
    }

    fn exclusive_verifier(&self, relative: &[OsString]) -> Result<Option<[u8; 8]>, NfsError> {
        Ok(self.exclusive_verifiers.get(&relative_key(relative)?).and_then(|verifiers| {
            verifiers
                .iter()
                .find(|(candidate, _)| relative_eq(candidate, relative))
                .map(|(_, verifier)| *verifier)
        }))
    }

    fn remember_exclusive_verifier(&mut self, relative: &[OsString], verifier: [u8; 8]) -> Result<(), NfsError> {
        let verifiers = self.exclusive_verifiers.entry(relative_key(relative)?).or_default();
        verifiers.retain(|(candidate, _)| !relative_eq(candidate, relative));
        verifiers.push((relative.to_vec(), verifier));
        Ok(())
    }

    fn take_exclusive_verifier(&mut self, key: &RelativeKey, relative: &[OsString]) -> Option<[u8; 8]> {
        let mut verifier = None;
        let remove_key = if let Some(verifiers) = self.exclusive_verifiers.get_mut(key) {
            verifiers.retain(|(candidate, candidate_verifier)| {
                if relative_eq(candidate, relative) {
                    verifier = Some(*candidate_verifier);
                    false
                } else {
                    true
                }
            });
            verifiers.is_empty()
        } else {
            false
        };
        if remove_key {
            self.exclusive_verifiers.remove(key);
        }
        verifier
    }
}

#[derive(Debug)]
pub struct MirrorFs {
    map: tokio::sync::Mutex<FsMap>,
}

impl MirrorFs {
    pub fn new(root: PathBuf) -> Self {
        Self {
            map: tokio::sync::Mutex::new(FsMap::new(root)),
        }
    }

    fn key(file_id: u64) -> ObjectKey {
        ObjectKey {
            file_id,
            generation: GENERATION,
        }
    }

    async fn object_path(&self, object: ObjectKey) -> Result<(u64, PathBuf), NfsError> {
        let map = self.map.lock().await;
        let relative = map.relative(object)?;
        Ok((object.file_id, map.path(&relative)))
    }

    async fn child_path(&self, parent: ObjectKey, name: &NfsName) -> Result<(Vec<OsString>, PathBuf), NfsError> {
        let map = self.map.lock().await;
        let relative = map.child_relative(parent, name)?;
        let path = map.path(&relative);
        Ok((relative, path))
    }

    async fn created(&self, relative: Vec<OsString>, metadata: Metadata) -> Result<CreatedObject, NfsError> {
        let mut map = self.map.lock().await;
        let file_id = map.intern(relative)?;
        Ok(CreatedObject {
            object: Self::key(file_id),
            attributes: Some(metadata_to_attributes(file_id, &metadata)),
        })
    }

    async fn parent_snapshot(&self, parent: ObjectKey) -> Result<(Option<WccAttributes>, PathBuf), NfsError> {
        let (_, path) = self.object_path(parent).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok((Some(metadata_to_wcc(&metadata)), path))
    }

    async fn create_object(
        &self,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
        kind: CreateKind,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        validate_attributes(&attributes)?;
        let (before, parent_path) = self.parent_snapshot(parent).await?;
        if !tokio::fs::symlink_metadata(&parent_path).await.map_err(map_io_error)?.is_dir() {
            return Err(NfsError::NotDirectory);
        }
        let (relative, path) = self.child_path(parent, name).await?;

        match kind {
            CreateKind::File(mode) => {
                if let CreateMode::Exclusive { verifier } = mode {
                    if tokio::fs::symlink_metadata(&path).await.is_ok() {
                        let map = self.map.lock().await;
                        if map.exclusive_verifier(&relative)? != Some(verifier) {
                            return Err(NfsError::Exists);
                        }
                    } else {
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .await
                            .map_err(map_io_error)?;
                        self.map.lock().await.remember_exclusive_verifier(&relative, verifier)?;
                    }
                } else {
                    let mut options = OpenOptions::new();
                    options.write(true);
                    match mode {
                        CreateMode::Unchecked => {
                            options.create(true);
                        },
                        CreateMode::Guarded => {
                            options.create_new(true);
                        },
                        CreateMode::Exclusive { .. } => unreachable!(),
                    }
                    options.open(&path).await.map_err(map_io_error)?;
                    apply_attributes(&path, &attributes).await?;
                }
            },
            CreateKind::Directory => {
                tokio::fs::create_dir(&path).await.map_err(map_io_error)?;
                apply_attributes(&path, &attributes).await?;
            },
            #[cfg(unix)]
            CreateKind::Symlink(target) => {
                create_symlink(&target, &path).await?;
            },
        }

        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        let created = self.created(relative, metadata).await?;
        let after = tokio::fs::symlink_metadata(parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(parent.file_id, &metadata));
        Ok(MutationResult {
            value: created,
            before,
            after,
        })
    }

    async fn remove_object(
        &self,
        parent: ObjectKey,
        name: &NfsName,
        directory: bool,
    ) -> Result<MutationResult<()>, NfsError> {
        let (before, parent_path) = self.parent_snapshot(parent).await?;
        let (relative, path) = self.child_path(parent, name).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if directory {
            if !metadata.is_dir() {
                return Err(NfsError::NotDirectory);
            }
            tokio::fs::remove_dir(&path).await.map_err(map_io_error)?;
        } else {
            if metadata.is_dir() {
                return Err(NfsError::IsDirectory);
            }
            tokio::fs::remove_file(&path).await.map_err(map_io_error)?;
        }
        self.map.lock().await.forget_prefix(&relative)?;
        let after = tokio::fs::symlink_metadata(parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(parent.file_id, &metadata));
        Ok(MutationResult {
            value: (),
            before,
            after,
        })
    }
}

enum CreateKind {
    File(CreateMode),
    Directory,
    #[cfg(unix)]
    Symlink(Vec<u8>),
}

#[async_trait]
impl VirtualFileSystem for MirrorFs {
    fn capabilities(&self) -> VfsCapabilities {
        VfsCapabilities {
            hard_links: false,
            symbolic_links: cfg!(unix),
            mknod: false,
            ..VfsCapabilities::READ_WRITE
        }
    }

    fn root(&self) -> ObjectKey {
        Self::key(ROOT_ID)
    }

    async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        debug!(?path, "getattr");
        Ok(metadata_to_attributes(file_id, &metadata))
    }

    async fn lookup(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            let mut map = self.map.lock().await;
            let mut relative = map.relative(parent)?;
            if name.as_bytes() == b".." {
                relative.pop();
            }
            let path = map.path(&relative);
            let metadata = tokio::fs::symlink_metadata(path).await.map_err(map_io_error)?;
            let file_id = map.intern(relative)?;
            return Ok(CreatedObject {
                object: Self::key(file_id),
                attributes: Some(metadata_to_attributes(file_id, &metadata)),
            });
        }
        let (relative, path) = self.child_path(parent, name).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        self.created(relative, metadata).await
    }

    async fn access(&self, _context: &RequestContext, _object: ObjectKey, requested: u32) -> Result<u32, NfsError> {
        Ok(requested)
    }

    async fn setattr(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        attributes: SetAttributes,
        guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if guard.is_some_and(|guard| guard != metadata_to_attributes(file_id, &before_metadata).change_time) {
            return Err(NfsError::NotSynchronized);
        }
        apply_attributes(&path, &attributes).await?;
        let after_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: (),
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }

    async fn readlink(&self, _context: &RequestContext, object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        let (_, path) = self.object_path(object).await?;
        if !tokio::fs::symlink_metadata(&path)
            .await
            .map_err(map_io_error)?
            .file_type()
            .is_symlink()
        {
            return Err(NfsError::BadType);
        }
        let target = tokio::fs::read_link(path).await.map_err(map_io_error)?;
        os_path_to_nfs_bytes(target.as_os_str())
    }

    async fn read(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let mut file = File::open(&path).await.map_err(map_io_error)?;
        let metadata = file.metadata().await.map_err(map_io_error)?;
        if !metadata.is_file() {
            return Err(if metadata.is_dir() {
                NfsError::IsDirectory
            } else {
                NfsError::Invalid
            });
        }
        let start = offset.min(metadata.len());
        let end = offset.saturating_add(count as u64).min(metadata.len());
        file.seek(SeekFrom::Start(start)).await.map_err(map_io_error)?;
        let mut data = vec![0; usize::try_from(end - start).map_err(|_| NfsError::TooSmall)?];
        file.read_exact(&mut data).await.map_err(map_io_error)?;
        Ok(ReadResult {
            data,
            eof: end == metadata.len(),
            attributes: Some(metadata_to_attributes(file_id, &metadata)),
        })
    }

    async fn write(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        data: &[u8],
        requested: WriteStability,
    ) -> Result<MutationResult<WriteResult>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if !before_metadata.is_file() {
            return Err(if before_metadata.is_dir() {
                NfsError::IsDirectory
            } else {
                NfsError::Invalid
            });
        }
        let mut file = OpenOptions::new().write(true).open(&path).await.map_err(map_io_error)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(map_io_error)?;
        file.write_all(data).await.map_err(map_io_error)?;
        let committed = match requested {
            WriteStability::Unstable => WriteStability::Unstable,
            WriteStability::DataSync => {
                file.sync_data().await.map_err(map_io_error)?;
                WriteStability::DataSync
            },
            WriteStability::FileSync => {
                file.sync_all().await.map_err(map_io_error)?;
                WriteStability::FileSync
            },
        };
        let after_metadata = file.metadata().await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: WriteResult {
                count: u32::try_from(data.len()).unwrap_or(u32::MAX),
                committed,
            },
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }

    async fn create(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
        mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_object(parent, name, attributes, CreateKind::File(mode)).await
    }

    async fn mkdir(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_object(parent, name, attributes, CreateKind::Directory).await
    }

    async fn symlink(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        target: &[u8],
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        #[cfg(windows)]
        {
            let _ = (parent, name, target, attributes);
            return Err(NfsError::NotSupported);
        }
        #[cfg(unix)]
        self.create_object(parent, name, attributes, CreateKind::Symlink(target.to_vec()))
            .await
    }

    async fn remove(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.remove_object(parent, name, false).await
    }

    async fn rmdir(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.remove_object(parent, name, true).await
    }

    async fn rename(
        &self,
        _context: &RequestContext,
        from_parent: ObjectKey,
        from_name: &NfsName,
        to_parent: ObjectKey,
        to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        let (from_before, from_parent_path) = self.parent_snapshot(from_parent).await?;
        let (to_before, to_parent_path) = self.parent_snapshot(to_parent).await?;
        let (from_relative, from_path) = self.child_path(from_parent, from_name).await?;
        let (to_relative, to_path) = self.child_path(to_parent, to_name).await?;
        rename_host_path(&from_path, &to_path, relative_eq(&from_relative, &to_relative)).await?;
        self.map.lock().await.move_prefix(&from_relative, &to_relative)?;
        let from_after = tokio::fs::symlink_metadata(from_parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(from_parent.file_id, &metadata));
        let to_after = tokio::fs::symlink_metadata(to_parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(to_parent.file_id, &metadata));
        Ok((
            MutationResult {
                value: (),
                before: from_before,
                after: from_after,
            },
            MutationResult {
                value: (),
                before: to_before,
                after: to_after,
            },
        ))
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        directory: ObjectKey,
        cookie: u64,
        verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        let (_, directory_path) = self.object_path(directory).await?;
        let directory_metadata = tokio::fs::symlink_metadata(&directory_path).await.map_err(map_io_error)?;
        if !directory_metadata.is_dir() {
            return Err(NfsError::NotDirectory);
        }
        let current_verifier = directory_verifier(&directory_metadata);
        if cookie != 0 && verifier != current_verifier {
            return Err(NfsError::BadCookie);
        }

        let mut reader = tokio::fs::read_dir(&directory_path).await.map_err(map_io_error)?;
        let mut children = Vec::new();
        while let Some(entry) = reader.next_entry().await.map_err(map_io_error)? {
            let path = entry.path();
            let name = entry.file_name();
            children.push((
                os_component_to_nfs_bytes(name.as_os_str())?,
                path.clone(),
                tokio::fs::symlink_metadata(path).await.map_err(map_io_error)?,
            ));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));

        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        let selected = children.iter().skip(start).take(backend_hint.max(1));
        let mut entries = Vec::new();
        for (index, (name_bytes, _path, metadata)) in selected.enumerate() {
            let nfs_name = NfsName::new(name_bytes.clone())?;
            let relative = {
                let map = self.map.lock().await;
                let mut relative = map.relative(directory)?;
                relative.push(nfs_name_to_os_string(&nfs_name)?);
                relative
            };
            let file_id = self.map.lock().await.intern(relative)?;
            entries.push(DirectoryEntry {
                object: Self::key(file_id),
                file_id,
                name: nfs_name,
                cookie: (start + index + 1) as u64,
                attributes: Some(metadata_to_attributes(file_id, metadata)),
            });
        }
        Ok(ReadDirectoryPage {
            verifier: current_verifier,
            eof: start.saturating_add(entries.len()) >= children.len(),
            entries,
        })
    }

    async fn fsstat(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        // The standard library has no portable statvfs API. These conservative
        // values keep the example mountable without adding a platform binding.
        Ok(FsStat {
            total_bytes: 1 << 40,
            free_bytes: 1 << 39,
            available_bytes: 1 << 39,
            total_files: 1_000_000,
            free_files: 999_000,
            available_files: 999_000,
            invariant_seconds: 1,
        })
    }

    async fn fsinfo(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        Ok(FsInfo {
            max_read: 1024 * 1024,
            preferred_read: 128 * 1024,
            read_multiple: 4096,
            max_write: 1024 * 1024,
            preferred_write: 128 * 1024,
            write_multiple: 4096,
            preferred_readdir: 32 * 1024,
            max_file_size: u64::MAX,
            time_granularity: NfsTime {
                seconds: 0,
                nanoseconds: 1,
            },
        })
    }

    async fn pathconf(&self, _context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        Ok(PathConf {
            max_links: u32::MAX,
            max_name_length: NfsName::MAX_LEN as u32,
            no_truncation: true,
            chown_restricted: true,
            case_insensitive: cfg!(windows),
            case_preserving: true,
        })
    }

    async fn commit(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<MutationResult<()>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .map_err(map_io_error)?
            .sync_all()
            .await
            .map_err(map_io_error)?;
        let after_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: (),
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }
}

#[cfg(unix)]
fn nfs_name_to_os_string(name: &NfsName) -> Result<OsString, NfsError> {
    Ok(OsString::from_vec(name.as_bytes().to_vec()))
}

#[cfg(windows)]
fn nfs_name_to_os_string(name: &NfsName) -> Result<OsString, NfsError> {
    let value = std::str::from_utf8(name.as_bytes()).map_err(|_| NfsError::Invalid)?;
    if !valid_windows_component(value) {
        return Err(NfsError::Invalid);
    }
    Ok(OsString::from(value))
}

#[cfg(any(test, windows))]
fn valid_windows_component(value: &str) -> bool {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.ends_with([' ', '.'])
        || value
            .chars()
            .any(|character| character <= '\u{1f}' || r#"<>:"/\|?*"#.contains(character))
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or_default().to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            stem.strip_prefix("COM"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        )
        && !matches!(
            stem.strip_prefix("LPT"),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        )
}

#[cfg(unix)]
fn relative_eq(left: &[OsString], right: &[OsString]) -> bool {
    left == right
}

#[cfg(windows)]
fn relative_eq(left: &[OsString], right: &[OsString]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| windows_component_eq(left, right))
}

#[cfg(unix)]
fn relative_starts_with(relative: &[OsString], prefix: &[OsString]) -> bool {
    relative.starts_with(prefix)
}

#[cfg(windows)]
fn relative_starts_with(relative: &[OsString], prefix: &[OsString]) -> bool {
    relative.len() >= prefix.len()
        && relative
            .iter()
            .zip(prefix)
            .all(|(component, prefix)| windows_component_eq(component, prefix))
}

#[cfg(unix)]
fn relative_key(relative: &[OsString]) -> Result<RelativeKey, NfsError> {
    Ok(relative.to_vec())
}

#[cfg(windows)]
fn relative_key(relative: &[OsString]) -> Result<RelativeKey, NfsError> {
    relative.iter().map(|component| windows_component_key(component)).collect()
}

#[cfg(windows)]
fn windows_component_eq(left: &OsStr, right: &OsStr) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len())) else {
        return false;
    };
    // SAFETY: both pointers remain valid for the explicit lengths supplied to
    // CompareStringOrdinal, and the function does not retain either pointer.
    unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL }
}

#[cfg(windows)]
fn windows_component_key(value: &OsStr) -> Result<Vec<u16>, NfsError> {
    use std::ptr;

    use windows_sys::Win32::Globalization::{LCMapStringEx, LCMAP_UPPERCASE, LOCALE_NAME_INVARIANT};

    let value = value.encode_wide().collect::<Vec<_>>();
    let value_len = i32::try_from(value.len()).map_err(|_| NfsError::NameTooLong)?;
    // SAFETY: the source pointer is valid for `value_len` code units and the
    // null output pointer requests the required output size.
    let key_len = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            value.as_ptr(),
            value_len,
            ptr::null_mut(),
            0,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if key_len == 0 {
        return Err(map_io_error(io::Error::last_os_error()));
    }
    let mut key = vec![0; key_len as usize];
    // SAFETY: `key` has the exact capacity reported by the sizing call, and
    // neither input nor output pointer is retained by LCMapStringEx.
    let written = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            value.as_ptr(),
            value_len,
            key.as_mut_ptr(),
            key_len,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if written != key_len {
        return Err(map_io_error(io::Error::last_os_error()));
    }
    Ok(key)
}

#[cfg(unix)]
fn os_component_to_nfs_bytes(value: &OsStr) -> Result<Vec<u8>, NfsError> {
    Ok(value.as_bytes().to_vec())
}

#[cfg(windows)]
fn os_component_to_nfs_bytes(value: &OsStr) -> Result<Vec<u8>, NfsError> {
    let value = value.to_str().ok_or(NfsError::Invalid)?;
    if !valid_windows_component(value) {
        return Err(NfsError::Invalid);
    }
    Ok(value.as_bytes().to_vec())
}

#[cfg(unix)]
fn os_path_to_nfs_bytes(value: &OsStr) -> Result<Vec<u8>, NfsError> {
    Ok(value.as_bytes().to_vec())
}

#[cfg(windows)]
fn os_path_to_nfs_bytes(value: &OsStr) -> Result<Vec<u8>, NfsError> {
    Ok(value.to_str().ok_or(NfsError::Invalid)?.as_bytes().to_vec())
}

#[cfg(unix)]
async fn create_symlink(target: &[u8], path: &Path) -> Result<(), NfsError> {
    tokio::fs::symlink(OsStr::from_bytes(target), path).await.map_err(map_io_error)
}

#[cfg(unix)]
async fn rename_host_path(from: &Path, to: &Path, _case_only: bool) -> Result<(), NfsError> {
    tokio::fs::rename(from, to).await.map_err(map_io_error)
}

#[cfg(windows)]
async fn rename_host_path(from: &Path, to: &Path, case_only: bool) -> Result<(), NfsError> {
    if !case_only || from == to {
        return tokio::fs::rename(from, to).await.map_err(map_io_error);
    }

    let from = from.to_path_buf();
    let to = to.to_path_buf();
    tokio::task::spawn_blocking(move || rename_host_path_case_only(&from, &to))
        .await
        .map_err(|_| NfsError::Io)?
}

#[cfg(windows)]
fn rename_host_path_case_only(from: &Path, to: &Path) -> Result<(), NfsError> {
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::ptr;

    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO, FILE_RENAME_INFO_0,
    };

    const DELETE: u32 = 0x0001_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x0000_0001;

    let file = std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(from)
        .map_err(map_io_error)?;
    let destination = if to.is_absolute() {
        to.to_path_buf()
    } else {
        std::env::current_dir().map_err(map_io_error)?.join(to)
    };
    let destination = destination.as_os_str().encode_wide().collect::<Vec<_>>();
    let name_bytes = destination.len().checked_mul(size_of::<u16>()).ok_or(NfsError::NameTooLong)?;
    let name_bytes = u32::try_from(name_bytes).map_err(|_| NfsError::NameTooLong)?;
    let header_bytes = offset_of!(FILE_RENAME_INFO, FileName);
    let total_bytes = header_bytes
        .checked_add(name_bytes as usize)
        .and_then(|size| size.checked_add(size_of::<u16>()))
        .ok_or(NfsError::NameTooLong)?;
    let word_bytes = size_of::<usize>();
    let mut storage = vec![0usize; total_bytes.div_ceil(word_bytes)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();

    // SAFETY: `storage` is aligned for FILE_RENAME_INFO and sized for the
    // header, the complete UTF-16 destination name, and its trailing NUL.
    // SetFileInformationByHandle consumes the buffer during the call and does
    // not retain it.
    let succeeded = unsafe {
        ptr::write(
            info,
            FILE_RENAME_INFO {
                Anonymous: FILE_RENAME_INFO_0 {
                    Flags: FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
                },
                RootDirectory: ptr::null_mut(),
                FileNameLength: name_bytes,
                FileName: [0],
            },
        );
        ptr::copy_nonoverlapping(destination.as_ptr(), (*info).FileName.as_mut_ptr(), destination.len());
        *(*info).FileName.as_mut_ptr().add(destination.len()) = 0;
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileRenameInfo,
            info.cast::<c_void>(),
            u32::try_from(total_bytes).map_err(|_| NfsError::NameTooLong)?,
        )
    };
    if succeeded == 0 {
        return Err(map_io_error(io::Error::last_os_error()));
    }
    Ok(())
}

fn map_io_error(error: io::Error) -> NfsError {
    match error.kind() {
        io::ErrorKind::NotFound => NfsError::NotFound,
        io::ErrorKind::PermissionDenied => NfsError::Access,
        io::ErrorKind::AlreadyExists => NfsError::Exists,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => NfsError::Invalid,
        io::ErrorKind::StorageFull => NfsError::NoSpace,
        _ => error.raw_os_error().and_then(map_raw_os_error).unwrap_or(NfsError::Io),
    }
}

#[cfg(unix)]
fn map_raw_os_error(error: i32) -> Option<NfsError> {
    match error {
        18 => Some(NfsError::CrossDevice),
        20 => Some(NfsError::NotDirectory),
        21 => Some(NfsError::IsDirectory),
        36 => Some(NfsError::NameTooLong),
        39 | 66 => Some(NfsError::NotEmpty),
        _ => None,
    }
}

#[cfg(windows)]
fn map_raw_os_error(error: i32) -> Option<NfsError> {
    match error {
        3 => Some(NfsError::NotFound),
        5 => Some(NfsError::Access),
        17 => Some(NfsError::CrossDevice),
        87 => Some(NfsError::Invalid),
        112 => Some(NfsError::NoSpace),
        145 => Some(NfsError::NotEmpty),
        206 => Some(NfsError::NameTooLong),
        _ => None,
    }
}

#[cfg(unix)]
fn metadata_time(seconds: i64, nanoseconds: i64) -> NfsTime {
    NfsTime {
        seconds: seconds.max(0) as u64,
        nanoseconds: nanoseconds.clamp(0, 999_999_999) as u32,
    }
}

#[cfg(windows)]
fn metadata_time(time: SystemTime) -> NfsTime {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    NfsTime {
        seconds: duration.as_secs(),
        nanoseconds: duration.subsec_nanos(),
    }
}

#[cfg(unix)]
fn metadata_file_type(metadata: &Metadata) -> FileType {
    let os_type = metadata.file_type();
    if os_type.is_file() {
        FileType::Regular
    } else if os_type.is_dir() {
        FileType::Directory
    } else if os_type.is_symlink() {
        FileType::Symlink
    } else if os_type.is_block_device() {
        FileType::BlockDevice
    } else if os_type.is_char_device() {
        FileType::CharacterDevice
    } else if os_type.is_socket() {
        FileType::Socket
    } else {
        FileType::Fifo
    }
}

#[cfg(windows)]
fn metadata_file_type(metadata: &Metadata) -> FileType {
    let os_type = metadata.file_type();
    if os_type.is_dir() {
        FileType::Directory
    } else if os_type.is_symlink() {
        FileType::Symlink
    } else {
        FileType::Regular
    }
}

#[cfg(unix)]
fn metadata_platform_attributes(metadata: &Metadata) -> (u32, u32, u32, u32, u64, u64, NfsTime, NfsTime, NfsTime) {
    (
        metadata.permissions().mode() & 0o7777,
        metadata.nlink() as u32,
        metadata.uid(),
        metadata.gid(),
        metadata.blocks().saturating_mul(512),
        metadata.dev(),
        metadata_time(metadata.atime(), metadata.atime_nsec()),
        metadata_time(metadata.mtime(), metadata.mtime_nsec()),
        metadata_time(metadata.ctime(), metadata.ctime_nsec()),
    )
}

#[cfg(windows)]
fn metadata_platform_attributes(metadata: &Metadata) -> (u32, u32, u32, u32, u64, u64, NfsTime, NfsTime, NfsTime) {
    let base_mode = if metadata.is_dir() { 0o555 } else { 0o444 };
    let mode = if metadata.permissions().readonly() {
        base_mode
    } else {
        base_mode | 0o222
    };
    let access_time = metadata_time(metadata.accessed().unwrap_or(UNIX_EPOCH));
    let modify_time = metadata_time(metadata.modified().unwrap_or(UNIX_EPOCH));
    let change_time = metadata_time(metadata.modified().or_else(|_| metadata.created()).unwrap_or(UNIX_EPOCH));
    (
        mode,
        if metadata.is_dir() { 2 } else { 1 },
        0,
        0,
        metadata.len(),
        0,
        access_time,
        modify_time,
        change_time,
    )
}

fn metadata_to_attributes(file_id: u64, metadata: &Metadata) -> FileAttributes {
    let (mode, links, uid, gid, used, fs_id, access_time, modify_time, change_time) =
        metadata_platform_attributes(metadata);
    FileAttributes {
        file_type: metadata_file_type(metadata),
        mode,
        links,
        uid,
        gid,
        size: metadata.len(),
        used,
        device: None,
        fs_id,
        file_id,
        access_time,
        modify_time,
        change_time,
    }
}

fn metadata_to_wcc(metadata: &Metadata) -> WccAttributes {
    let (_, _, _, _, _, _, _, modify_time, change_time) = metadata_platform_attributes(metadata);
    WccAttributes {
        size: metadata.len(),
        modify_time,
        change_time,
    }
}

#[cfg(unix)]
fn directory_verifier(metadata: &Metadata) -> [u8; 8] {
    let seconds = metadata.mtime() as u64;
    let nanoseconds = metadata.mtime_nsec() as u64;
    (seconds.rotate_left(17) ^ nanoseconds ^ metadata.ino()).to_be_bytes()
}

#[cfg(windows)]
fn directory_verifier(metadata: &Metadata) -> [u8; 8] {
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    let duration = modified.duration_since(UNIX_EPOCH).unwrap_or_default();
    (duration.as_secs().rotate_left(17) ^ u64::from(duration.subsec_nanos()) ^ metadata.len()).to_be_bytes()
}

#[cfg(unix)]
async fn apply_mode(path: &Path, mode: u32) -> Result<(), NfsError> {
    let writable_mode = (mode | 0o200) & 0o7777;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(writable_mode))
        .await
        .map_err(map_io_error)
}

#[cfg(windows)]
async fn apply_mode(path: &Path, mode: u32) -> Result<(), NfsError> {
    let mut permissions = tokio::fs::metadata(path).await.map_err(map_io_error)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    tokio::fs::set_permissions(path, permissions).await.map_err(map_io_error)
}

async fn apply_attributes(path: &Path, attributes: &SetAttributes) -> Result<(), NfsError> {
    validate_attributes(attributes)?;
    if let Some(mode) = attributes.mode {
        apply_mode(path, mode).await?;
    }
    if let Some(size) = attributes.size {
        OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(map_io_error)?
            .set_len(size)
            .await
            .map_err(map_io_error)?;
    }
    if let Some(access_time) = attributes.access_time {
        let time = set_time_to_file_time(access_time);
        filetime::set_file_atime(path, time).map_err(map_io_error)?;
    }
    if let Some(modify_time) = attributes.modify_time {
        let time = set_time_to_file_time(modify_time);
        filetime::set_file_mtime(path, time).map_err(map_io_error)?;
    }
    Ok(())
}

fn validate_attributes(attributes: &SetAttributes) -> Result<(), NfsError> {
    if attributes.uid.is_some() || attributes.gid.is_some() {
        return Err(NfsError::NotSupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::valid_windows_component;

    #[test]
    fn windows_components_reject_aliases_and_path_syntax() {
        for valid in ["file.txt", "résumé", "COM10", "folder-name"] {
            assert!(valid_windows_component(valid), "{valid}");
        }
        for invalid in [
            ".",
            "..",
            "CON",
            "con.txt",
            "LPT1.log",
            "COM¹.txt",
            "bad\\name",
            "bad:name",
            "trail.",
            "trail ",
        ] {
            assert!(!valid_windows_component(invalid), "{invalid}");
        }
    }

    #[tokio::test]
    async fn unsupported_create_ownership_does_not_touch_the_host_namespace() {
        use nfsembed::vfs::{CreateMode, NfsError, NfsName, SetAttributes, VirtualFileSystem};

        use super::{CreateKind, MirrorFs};

        let root = std::env::temp_dir().join(format!(
            "nfsembed-create-preflight-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let fs = MirrorFs::new(root.clone());

        for (name, kind, attributes) in [
            (
                "uid-file",
                CreateKind::File(CreateMode::Unchecked),
                SetAttributes {
                    uid: Some(1234),
                    ..SetAttributes::default()
                },
            ),
            (
                "gid-directory",
                CreateKind::Directory,
                SetAttributes {
                    gid: Some(1234),
                    ..SetAttributes::default()
                },
            ),
        ] {
            let name = NfsName::new(name.as_bytes().to_vec()).unwrap();
            assert_eq!(fs.create_object(fs.root(), &name, attributes, kind).await, Err(NfsError::NotSupported),);
            assert!(!root.join(std::str::from_utf8(name.as_bytes()).unwrap()).exists());
        }

        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn path_interning_uses_a_reverse_index() {
        use super::FsMap;

        let mut map = FsMap::new(std::path::PathBuf::from("unused"));
        for index in 0..4096 {
            map.intern(vec![std::ffi::OsString::from(format!("entry-{index}"))]).unwrap();
        }
        assert_eq!(map.relative_to_id.len(), 4097);
        assert_eq!(map.intern(vec![std::ffi::OsString::from("entry-2048")]).unwrap(), 2050,);
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_is_folded_without_changing_the_host_path() {
        use nfsembed::vfs::{NfsName, ObjectKey};

        use super::{nfs_name_to_os_string, relative_eq, relative_key, FsMap, GENERATION};

        let mut map = FsMap::new(std::path::PathBuf::from(r"C:\mirror-root"));
        let original = vec![std::ffi::OsString::from("MiXeD.Txt")];
        let file_id = map.intern(original.clone()).unwrap();
        assert_eq!(map.intern(vec![std::ffi::OsString::from("mixed.txt")]).unwrap(), file_id);
        assert_eq!(
            map.relative(ObjectKey {
                file_id,
                generation: GENERATION,
            })
            .unwrap(),
            original,
        );

        let name = NfsName::new(b"AnotherMiXeD.Txt".to_vec()).unwrap();
        assert_eq!(nfs_name_to_os_string(&name).unwrap(), "AnotherMiXeD.Txt");
        let capital = [std::ffi::OsString::from("Σ.txt")];
        let normal_sigma = [std::ffi::OsString::from("σ.txt")];
        let final_sigma = [std::ffi::OsString::from("ς.txt")];
        assert!(relative_eq(&capital, &normal_sigma));
        assert_eq!(relative_key(&capital).unwrap(), relative_key(&normal_sigma).unwrap());
        assert_eq!(map.intern(capital.to_vec()).unwrap(), map.intern(normal_sigma.to_vec()).unwrap());

        // Windows ordinal comparison and invariant mapping both keep final
        // sigma distinct from the ordinary sigma pair.
        assert!(!relative_eq(&capital, &final_sigma));
        assert_ne!(relative_key(&capital).unwrap(), relative_key(&final_sigma).unwrap());
        assert_ne!(map.intern(capital.to_vec()).unwrap(), map.intern(final_sigma.to_vec()).unwrap());

        map.move_prefix(&[std::ffi::OsString::from("mixed.txt")], &[std::ffi::OsString::from("MIXED.txt")])
            .unwrap();
        assert_eq!(
            map.relative(ObjectKey {
                file_id,
                generation: GENERATION,
            })
            .unwrap(),
            vec![std::ffi::OsString::from("MIXED.txt")],
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_case_only_rename_preserves_requested_spelling() {
        use super::rename_host_path;

        let root = std::env::temp_dir().join(format!(
            "nfsembed-case-rename-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let from = root.join("MiXeD.txt");
        let to = root.join("MIXED.txt");
        std::fs::write(&from, b"case-preserved").unwrap();

        rename_host_path(&from, &to, true).await.unwrap();
        let name = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().file_name();
        assert_eq!(name, "MIXED.txt");
        assert_eq!(std::fs::read(&to).unwrap(), b"case-preserved");

        std::fs::remove_file(&to).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_readlink_accepts_a_preexisting_multicomponent_target() {
        use nfsembed::vfs::{ExportId, NfsName, Principal, RequestContext, VirtualFileSystem};

        use super::MirrorFs;

        let root = std::env::temp_dir().join(format!(
            "nfsembed-readlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let target_directory = root.join("target-directory");
        std::fs::create_dir_all(&target_directory).unwrap();
        std::fs::write(target_directory.join("target.txt"), b"target").unwrap();
        let link = root.join("link.txt");
        std::os::windows::fs::symlink_file(r"target-directory\target.txt", &link).unwrap();

        let fs = MirrorFs::new(root.clone());
        let context = RequestContext {
            principal: Principal::Anonymous,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            export_id: ExportId(1),
        };
        let name = NfsName::new(b"link.txt".to_vec()).unwrap();
        let object = fs.lookup(&context, fs.root(), &name).await.unwrap().object;
        assert_eq!(fs.readlink(&context, object).await.unwrap(), br"target-directory\target.txt",);

        let renamed_name = NfsName::new(b"LINK.txt".to_vec()).unwrap();
        fs.rename(&context, fs.root(), &name, fs.root(), &renamed_name).await.unwrap();
        assert_eq!(fs.readlink(&context, object).await.unwrap(), br"target-directory\target.txt",);
        assert_eq!(std::fs::read(target_directory.join("target.txt")).unwrap(), b"target");
        let renamed_link = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_type().unwrap().is_symlink())
            .unwrap();
        assert_eq!(renamed_link.file_name(), "LINK.txt");

        std::fs::remove_file(root.join("LINK.txt")).unwrap();
        std::fs::remove_file(target_directory.join("target.txt")).unwrap();
        std::fs::remove_dir(target_directory).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}

fn set_time_to_file_time(time: SetTime) -> filetime::FileTime {
    match time {
        SetTime::ServerTime => filetime::FileTime::now(),
        SetTime::ClientTime(time) => filetime::FileTime::from_unix_time(time.seconds as i64, time.nanoseconds),
    }
}

// `certification_server` also includes this file as a backend module, where
// the example entry point is unused.
#[allow(dead_code)]
const HOST_PORT: u16 = 11111;

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();

    let root = PathBuf::from(std::env::args().nth(1).ok_or("must supply directory to mirror")?);
    if !root.is_dir() {
        return Err("mirror root must be a directory".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", HOST_PORT)).await?;
    let server = NfsServer::builder(MirrorFs::new(root))
        .auth_policy(AuthPolicy::AuthSysOrAnonymous)
        .build()?;
    if let Ok(address) = std::env::var("NFSEMBED_PORTMAPPER") {
        let portmapper_tcp = TcpListener::bind(address).await?;
        let portmapper_udp = UdpSocket::bind(portmapper_tcp.local_addr()?).await?;
        server
            .serve_with_portmapper(
                listener,
                PortmapperSockets::new(portmapper_tcp, portmapper_udp),
                std::future::pending(),
            )
            .await?;
    } else {
        server.serve(listener, std::future::pending()).await?;
    }
    Ok(())
}

// Test with:
// mount -t nfs -o nolocks,vers=3,tcp,port=11111,mountport=11111,soft 127.0.0.1:/ mnt/
