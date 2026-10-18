mod builder;
mod config;
mod connection;
mod handle;
mod limits;
mod portmapper;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, MutexGuard, PoisonError};
use std::task::Poll;

pub use builder::NfsServerBuilder;
pub use config::{AuthPolicy, PortmapperMode};
use connection::{serve_connection, ConnectionState};
pub use handle::{MountInfo, ServerHandle};
pub use limits::ServerLimits;
pub use portmapper::PortmapperSockets;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;

use crate::handles::HandleCodec;
use crate::replay::{ReplayCache, ReplayError};
use crate::rpc::codec::{DecodeError, EncodeError};
use crate::rpc::record::RecordError;
use crate::vfs::VirtualFileSystem;

/// Tracks request executions, which outlive their connection so that a
/// mutation whose reply was lost still completes and populates the replay
/// cache. Shutdown waits for, or aborts, every tracked execution.
pub(crate) struct ExecutionTracker {
    // A synchronous lock: it is only held to spawn, reap, or poll tasks and
    // never across an await point.
    tasks: std::sync::Mutex<JoinSet<()>>,
}

impl ExecutionTracker {
    fn new() -> Self {
        Self {
            tasks: std::sync::Mutex::new(JoinSet::new()),
        }
    }

    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.tasks();
        while let Some(result) = tasks.try_join_next() {
            log_execution_failure(result);
        }
        tasks.spawn(future);
    }

    /// Waits until every tracked execution, including any spawned while
    /// waiting, has finished.
    async fn wait(&self) {
        std::future::poll_fn(|context| {
            let mut tasks = self.tasks();
            loop {
                match tasks.poll_join_next(context) {
                    Poll::Ready(Some(result)) => log_execution_failure(result),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }

    fn abort_all(&self) {
        self.tasks().abort_all();
    }

    fn tasks(&self) -> MutexGuard<'_, JoinSet<()>> {
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn log_execution_failure(result: Result<(), JoinError>) {
    if let Err(error) = result {
        tracing::warn!(error = %error, "request execution task failed");
    }
}

#[derive(Clone)]
pub(crate) struct ExportState {
    pub vfs: Arc<dyn VirtualFileSystem>,
    pub id: crate::vfs::ExportId,
    pub path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("invalid server configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("replay waiter closed")]
    ReplayWaiterClosed(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("server task failed: {0}")]
    Task(JoinError),
    #[error("server is shutting down")]
    ShuttingDown,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("request timed out")]
    RequestTimeout,
    #[error("operating-system random source failed: {0}")]
    Entropy(#[from] rand::Error),
}

pub struct NfsServer {
    exports: Arc<Vec<ExportState>>,
    limits: ServerLimits,
    auth_policy: AuthPolicy,
    portmapper: PortmapperMode,
}

impl NfsServer {
    pub fn builder(vfs: impl VirtualFileSystem) -> NfsServerBuilder {
        NfsServerBuilder::new(Arc::new(vfs))
    }

    pub fn builder_arc(vfs: Arc<dyn VirtualFileSystem>) -> NfsServerBuilder {
        NfsServerBuilder::new(vfs)
    }

    fn from_builder(builder: NfsServerBuilder) -> Self {
        Self {
            exports: Arc::new(builder.exports),
            limits: builder.limits,
            auth_policy: builder.auth_policy,
            portmapper: builder.portmapper,
        }
    }

    pub async fn start(&self, listener: TcpListener) -> Result<ServerHandle, ServerError> {
        self.start_inner(listener, None).await
    }

    /// Starts NFS/MOUNT together with a standalone TCP+UDP portmapper.
    pub async fn start_with_portmapper(
        &self,
        listener: TcpListener,
        portmapper: PortmapperSockets,
    ) -> Result<ServerHandle, ServerError> {
        self.start_inner(listener, Some(portmapper)).await
    }

    async fn start_inner(
        &self,
        listener: TcpListener,
        portmapper: Option<PortmapperSockets>,
    ) -> Result<ServerHandle, ServerError> {
        let local_addr = listener.local_addr()?;
        let mount_infos = self.mount_infos(local_addr);
        let portmapper = portmapper.map(|sockets| sockets.prepare(local_addr.port())).transpose()?;
        let portmapper_addr = portmapper.as_ref().map(|portmapper| portmapper.local_addr);
        let (shutdown, receive) = watch::channel(false);
        let (state, executions) = self.connection_state(local_addr.port())?;
        let deadline = self.limits.graceful_shutdown_timeout;
        let task = tokio::spawn(async move { run(listener, portmapper, receive, state, executions, deadline).await });
        Ok(ServerHandle::new(mount_infos, portmapper_addr, shutdown, task))
    }

    pub async fn serve<F>(&self, listener: TcpListener, shutdown_signal: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        self.serve_inner(listener, None, shutdown_signal).await
    }

    /// Serves NFS/MOUNT together with a standalone TCP+UDP portmapper.
    pub async fn serve_with_portmapper<F>(
        &self,
        listener: TcpListener,
        portmapper: PortmapperSockets,
        shutdown_signal: F,
    ) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        self.serve_inner(listener, Some(portmapper), shutdown_signal).await
    }

    async fn serve_inner<F>(
        &self,
        listener: TcpListener,
        portmapper: Option<PortmapperSockets>,
        shutdown_signal: F,
    ) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        let local_addr = listener.local_addr()?;
        let portmapper = portmapper.map(|sockets| sockets.prepare(local_addr.port())).transpose()?;
        let (shutdown, receive) = watch::channel(false);
        let signal_task = async move {
            shutdown_signal.await;
            let _ = shutdown.send(true);
        };
        let (state, executions) = self.connection_state(local_addr.port())?;
        tokio::pin!(signal_task);
        let server = run(listener, portmapper, receive, state, executions, self.limits.graceful_shutdown_timeout);
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            _ = &mut signal_task => server.await,
        }
    }

    fn mount_infos(&self, local_addr: SocketAddr) -> Vec<MountInfo> {
        self.exports
            .iter()
            .map(|export| MountInfo {
                server_addr: local_addr,
                export_path: export.path.clone(),
                nfs_version: crate::nfs3::types::VERSION,
                nfs_port: local_addr.port(),
                mount_port: local_addr.port(),
            })
            .collect()
    }

    fn connection_state(&self, local_port: u16) -> Result<(Arc<ConnectionState>, Arc<ExecutionTracker>), ServerError> {
        let executions = Arc::new(ExecutionTracker::new());
        let state = Arc::new(ConnectionState {
            exports: self.exports.clone(),
            limits: self.limits.clone(),
            auth_policy: self.auth_policy,
            portmapper: self.portmapper,
            // Every start/serve call is a fresh server run. Handles and the
            // WRITE verifier must change across stop/start cycles.
            handles: HandleCodec::try_random()?,
            replay: Arc::new(ReplayCache::new(
                self.limits.replay_cache_capacity,
                self.limits.replay_cache_max_bytes,
                self.limits.replay_cache_ttl,
            )),
            requests: Arc::new(Semaphore::new(self.limits.max_inflight_requests)),
            request_buffers: Arc::new(Semaphore::new(self.limits.max_buffered_request_bytes)),
            reply_buffers: Arc::new(Semaphore::new(self.limits.max_buffered_reply_bytes)),
            executions: Arc::downgrade(&executions),
            mounts: Arc::new(Mutex::new(Vec::new())),
            local_port,
        });
        Ok((state, executions))
    }
}

async fn run(
    listener: TcpListener,
    prepared_portmapper: Option<portmapper::PreparedPortmapper>,
    mut shutdown: watch::Receiver<bool>,
    state: Arc<ConnectionState>,
    executions: Arc<ExecutionTracker>,
    graceful_deadline: std::time::Duration,
) -> Result<(), ServerError> {
    let connections = Arc::new(Semaphore::new(state.limits.max_connections));
    let mut tasks = JoinSet::new();
    let mut services = JoinSet::new();
    if let Some(portmapper) = prepared_portmapper {
        services.spawn(portmapper::run_portmapper(
            portmapper,
            shutdown.clone(),
            connections.clone(),
            state.limits.clone(),
        ));
    }
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(error = %error, "connection task failed");
            }
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, client_addr) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(client = %client_addr, "connection rejected: limit reached");
                        continue;
                    }
                };
                let active_connections = state.limits.max_connections - connections.available_permits();
                let state = state.clone();
                let connection_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    tracing::debug!(client = %client_addr, active_connections, "connection opened");
                    if let Err(error) = serve_connection(stream, client_addr, state, connection_shutdown).await {
                        tracing::debug!(client = %client_addr, active_connections, error = %error, "connection closed with error");
                    } else {
                        tracing::debug!(client = %client_addr, active_connections, "connection closed");
                    }
                    permit
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "connection task failed");
                }
            }
            Some(result) = services.join_next(), if !services.is_empty() => {
                let result = result.map_err(ServerError::Task)?;
                if *shutdown.borrow() {
                    break;
                }
                return result;
            }
        }
    }
    if timeout(graceful_deadline, async {
        while tasks.join_next().await.is_some() {}
        while services.join_next().await.is_some() {}
        executions.wait().await;
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        services.abort_all();
        while services.join_next().await.is_some() {}
        executions.abort_all();
        executions.wait().await;
    }
    Ok(())
}

impl std::fmt::Debug for NfsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsServer")
            .field("exports", &self.exports.iter().map(|export| (&export.id, &export.path)).collect::<Vec<_>>())
            .field("limits", &self.limits)
            .field("auth_policy", &self.auth_policy)
            .field("portmapper", &self.portmapper)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::rpc::codec::{Decoder, Encoder};
    use crate::rpc::record::{read_record, write_record, RecordLimits};
    use crate::vfs::{
        CreatedObject, FileAttributes, FileType, NfsError, NfsName, NfsTime, ObjectKey, RequestContext,
        VfsCapabilities, VirtualFileSystem,
    };

    struct TestVfs {
        root_id: u64,
        export_id: crate::vfs::ExportId,
    }

    fn root_attributes(file_id: u64) -> FileAttributes {
        FileAttributes {
            file_type: FileType::Directory,
            mode: 0o755,
            links: 2,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: None,
            fs_id: 1,
            file_id,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        }
    }

    #[async_trait]
    impl VirtualFileSystem for TestVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn root(&self) -> ObjectKey {
            ObjectKey {
                file_id: self.root_id,
                generation: 1,
            }
        }

        async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            if object == self.root() && context.export_id == self.export_id {
                Ok(root_attributes(self.root_id))
            } else {
                Err(NfsError::NotFound)
            }
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotFound)
        }
    }

    fn auth_sys_call(xid: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        let mut credential = Encoder::new();
        credential.write_u32(0);
        credential.write_opaque(b"test").unwrap();
        credential.write_u32(1000);
        credential.write_u32(1000);
        credential.write_u32(0);

        let mut call = Encoder::new();
        call.write_u32(xid);
        call.write_u32(0);
        call.write_u32(2);
        call.write_u32(program);
        call.write_u32(version);
        call.write_u32(procedure);
        call.write_u32(crate::rpc::auth::AUTH_SYS);
        call.write_opaque(&credential.into_bytes()).unwrap();
        call.write_u32(crate::rpc::auth::AUTH_NONE);
        call.write_u32(0);
        call.write_fixed(args);
        call.into_bytes()
    }

    fn accepted_body(reply: &[u8]) -> Decoder<'_> {
        let mut decoder = Decoder::new(reply);
        let _xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), 1);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert_eq!(decoder.read_u32().unwrap(), crate::rpc::auth::AUTH_NONE);
        assert!(decoder.read_opaque("verifier", 400).unwrap().is_empty());
        assert_eq!(decoder.read_u32().unwrap(), 0);
        decoder
    }

    #[tokio::test]
    async fn execution_tracker_waits_for_late_spawns_and_aborts_pending_work() {
        let tracker = Arc::new(ExecutionTracker::new());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let (finished, mut finished_receiver) = tokio::sync::mpsc::unbounded_channel();
        let first_finished = finished.clone();
        tracker.spawn(async move {
            let _ = released.await;
            let _ = first_finished.send("first");
        });
        let waiter = {
            let tracker = tracker.clone();
            tokio::spawn(async move { tracker.wait().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        // Work spawned while shutdown is draining is drained too.
        tracker.spawn(async move {
            let _ = finished.send("late");
        });
        release.send(()).unwrap();
        waiter.await.unwrap();
        let mut completed = vec![
            finished_receiver.recv().await.unwrap(),
            finished_receiver.recv().await.unwrap(),
        ];
        completed.sort_unstable();
        assert_eq!(completed, ["first", "late"]);

        let (_never, pending) = tokio::sync::oneshot::channel::<()>();
        tracker.spawn(async move {
            let _ = pending.await;
        });
        tracker.abort_all();
        tokio::time::timeout(std::time::Duration::from_secs(1), tracker.wait())
            .await
            .expect("aborted executions must not keep wait() pending");
    }

    #[tokio::test]
    async fn embedded_server_starts_replies_and_stops() {
        let server = NfsServer::builder(TestVfs {
            root_id: 1,
            export_id: crate::vfs::ExportId(1),
        })
        .build()
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(listener).await.unwrap();
        let info = handle.mount_info();
        assert_ne!(info.nfs_port, 0);

        let mut client = TcpStream::connect(info.server_addr).await.unwrap();
        let null_call = auth_sys_call(7, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 0, &[]);
        write_record(&mut client, &null_call, 1024).await.unwrap();
        let reply = read_record(
            &mut client,
            RecordLimits {
                max_record_size: 1024,
                max_fragment_size: 1024,
                max_fragments: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(&reply[..4], &7u32.to_be_bytes());
        assert_eq!(&reply[20..24], &0u32.to_be_bytes());
        drop(client);

        handle.shutdown().await.unwrap();
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn mount_handle_drives_getattr_and_rejects_forgery() {
        let server = NfsServer::builder(TestVfs {
            root_id: 1,
            export_id: crate::vfs::ExportId(1),
        })
        .build()
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(listener).await.unwrap();
        let mut client = TcpStream::connect(handle.mount_info().server_addr).await.unwrap();
        let limits = RecordLimits {
            max_record_size: 2048,
            max_fragment_size: 2048,
            max_fragments: 1,
        };

        let mut mount_args = Encoder::new();
        mount_args.write_opaque(b"/").unwrap();
        let mount_call = auth_sys_call(
            10,
            crate::mount3::types::PROGRAM,
            crate::mount3::types::VERSION,
            1,
            &mount_args.into_bytes(),
        );
        write_record(&mut client, &mount_call, 2048).await.unwrap();
        let mount_reply = read_record(&mut client, limits).await.unwrap();
        let mut body = accepted_body(&mount_reply);
        assert_eq!(body.read_u32().unwrap(), 0);
        let root_handle = body.read_opaque("handle", 64).unwrap();
        assert_eq!(body.read_u32().unwrap(), 1);
        assert_eq!(body.read_u32().unwrap(), crate::rpc::auth::AUTH_SYS);
        body.finish().unwrap();

        let dump_call = auth_sys_call(13, crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, 2, &[]);
        write_record(&mut client, &dump_call, 2048).await.unwrap();
        let dump_reply = read_record(&mut client, limits).await.unwrap();
        let mut dump = accepted_body(&dump_reply);
        assert!(dump.read_bool().unwrap());
        assert!(!dump.read_string("mount host", 64).unwrap().is_empty());
        assert_eq!(dump.read_string("mount path", 1024).unwrap(), b"/");
        assert!(!dump.read_bool().unwrap());
        dump.finish().unwrap();

        let mut getattr_args = Encoder::new();
        getattr_args.write_opaque(&root_handle).unwrap();
        let getattr_call =
            auth_sys_call(11, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &getattr_args.into_bytes());
        write_record(&mut client, &getattr_call, 2048).await.unwrap();
        let getattr_reply = read_record(&mut client, limits).await.unwrap();
        let mut body = accepted_body(&getattr_reply);
        assert_eq!(body.read_u32().unwrap(), 0);
        assert_eq!(body.read_u32().unwrap(), 2);

        let mut write_args = Encoder::new();
        write_args.write_opaque(&root_handle).unwrap();
        write_args.write_u64(0);
        write_args.write_u32(1);
        write_args.write_u32(0);
        write_args.write_opaque(&[1]).unwrap();
        let write_call =
            auth_sys_call(15, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 7, &write_args.into_bytes());
        write_record(&mut client, &write_call, 2048).await.unwrap();
        let write_reply = read_record(&mut client, limits).await.unwrap();
        assert_eq!(accepted_body(&write_reply).read_u32().unwrap(), 30);

        let mut forged = root_handle;
        forged[15] ^= 1;
        let mut forged_args = Encoder::new();
        forged_args.write_opaque(&forged).unwrap();
        let forged_call =
            auth_sys_call(12, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &forged_args.into_bytes());
        write_record(&mut client, &forged_call, 2048).await.unwrap();
        let forged_reply = read_record(&mut client, limits).await.unwrap();
        assert_eq!(accepted_body(&forged_reply).read_u32().unwrap(), 10001);

        let mut unmount_args = Encoder::new();
        unmount_args.write_opaque(b"/").unwrap();
        let unmount_call = auth_sys_call(
            14,
            crate::mount3::types::PROGRAM,
            crate::mount3::types::VERSION,
            3,
            &unmount_args.into_bytes(),
        );
        write_record(&mut client, &unmount_call, 2048).await.unwrap();
        let unmount_reply = read_record(&mut client, limits).await.unwrap();
        accepted_body(&unmount_reply).finish().unwrap();

        drop(client);
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_instances_have_independent_ports_and_state() {
        for _ in 0..3 {
            let server = NfsServer::builder(TestVfs {
                root_id: 1,
                export_id: crate::vfs::ExportId(1),
            })
            .build()
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let handle = server.start(listener).await.unwrap();
            assert_ne!(handle.mount_info().nfs_port, 0);
            handle.shutdown().await.unwrap();
            handle.wait().await.unwrap();
        }
    }

    #[tokio::test]
    async fn independent_exports_route_contexts_and_handles() {
        let server = NfsServer::builder(TestVfs {
            root_id: 11,
            export_id: crate::vfs::ExportId(1),
        })
        .export_name("one")
        .add_export(
            crate::vfs::ExportId(2),
            "two",
            TestVfs {
                root_id: 22,
                export_id: crate::vfs::ExportId(2),
            },
        )
        .build()
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(listener).await.unwrap();
        assert_eq!(handle.mount_infos().len(), 2);
        assert_eq!(handle.mount_infos()[0].export_path, "/one");
        assert_eq!(handle.mount_infos()[1].export_path, "/two");
        let mut client = TcpStream::connect(handle.mount_info().server_addr).await.unwrap();
        let limits = RecordLimits {
            max_record_size: 2048,
            max_fragment_size: 2048,
            max_fragments: 1,
        };
        let mut file_handles = Vec::new();
        for (xid, path) in [(30, b"/one".as_slice()), (31, b"/two".as_slice())] {
            let mut mount_args = Encoder::new();
            mount_args.write_opaque(path).unwrap();
            let call = auth_sys_call(
                xid,
                crate::mount3::types::PROGRAM,
                crate::mount3::types::VERSION,
                1,
                &mount_args.into_bytes(),
            );
            write_record(&mut client, &call, 2048).await.unwrap();
            let reply = read_record(&mut client, limits).await.unwrap();
            let mut body = accepted_body(&reply);
            assert_eq!(body.read_u32().unwrap(), 0);
            file_handles.push(body.read_opaque("handle", 64).unwrap());
        }
        assert_ne!(file_handles[0], file_handles[1]);

        for (xid, file_handle) in [(32, &file_handles[0]), (33, &file_handles[1])] {
            let mut args = Encoder::new();
            args.write_opaque(file_handle).unwrap();
            let call =
                auth_sys_call(xid, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &args.into_bytes());
            write_record(&mut client, &call, 2048).await.unwrap();
            let reply = read_record(&mut client, limits).await.unwrap();
            assert_eq!(accepted_body(&reply).read_u32().unwrap(), 0);
        }

        drop(client);
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }
}
