use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};
use tracing::Instrument;

use super::limits::MAXIMUM_FIXED_REPLY_SIZE;
use super::{AuthPolicy, ExecutionTracker, ExportState, PortmapperMode, ServerError, ServerLimits};
use crate::handles::{HandleCodec, HandleError};
use crate::mount3::codec::EncodeMountResult;
use crate::mount3::types::{DumpResult, ExportEntry, ExportResult, MountEntry, MountResult, MountStatus, MAX_PATH};
use crate::nfs3::codec::{encode_post_attributes, encode_readdir_reply, EncodeNfsResult, ReadDirLimits};
use crate::nfs3::dispatch::Procedure;
use crate::nfs3::procedures::{
    AccessResult, CommitResult, CreateResult, DirectoryOperationArgs, FsInfoResult, FsStatResult, GetAttrResult,
    LinkResult, LookupResult, NfsArguments, PathConfResult, ReadArgs, ReadDirEntry, ReadDirEntryExtension,
    ReadDirResult, ReadLinkResult, ReadResult, RenameResult, SetAttrResult, WccResult, WriteRequest, WriteResult,
};
use crate::nfs3::types::{NfsStatus, WccData};
use crate::replay::{ReplayDecision, ReplayKey, RequestFingerprint};
use crate::rpc::auth::{decode_principal, AUTH_NONE, AUTH_SYS};
use crate::rpc::codec::{Decoder, EncodeError};
use crate::rpc::message::{self, AcceptStatus, AuthStatus, CallHeader, VersionRange, ACCEPTED_REPLY_HEADER_SIZE};
use crate::rpc::record::{read_record_budgeted, validate_record_length, write_record_segments_limited, RecordLimits};
use crate::rpc::reply::EncodedReply;
use crate::vfs::{
    CreatedObject, ExportId, FileAttributes, FileType, FsInfo, MutationResult, NfsError, NfsName, ObjectKey, Principal,
    RequestContext, VirtualFileSystem, WriteStability,
};

/// RFC 5531 `MAX_AUTH_BYTES`.
const MAX_AUTH_BYTES: usize = 400;
/// The six RFC 1813 `ACCESS3_*` bits.
const ACCESS_MASK: u32 = 0x3f;
/// RFC 1813 `FSINFO` property bits.
const FSF3_LINK: u32 = 0x0001;
const FSF3_SYMLINK: u32 = 0x0002;
const FSF3_HOMOGENEOUS: u32 = 0x0008;
const FSF3_CANSETTIME: u32 = 0x0010;
/// The smallest READDIR `count` that can hold an empty listing.
const MINIMUM_READDIR_COUNT: usize = 20;

pub(crate) struct ConnectionState {
    pub exports: Arc<Vec<ExportState>>,
    pub limits: ServerLimits,
    pub auth_policy: AuthPolicy,
    pub portmapper: PortmapperMode,
    pub handles: HandleCodec,
    pub replay: Arc<crate::replay::ReplayCache>,
    pub requests: Arc<Semaphore>,
    pub request_buffers: Arc<Semaphore>,
    pub reply_buffers: Arc<Semaphore>,
    pub executions: Weak<ExecutionTracker>,
    pub mounts: MountTable,
    pub local_port: u16,
}

type MountTable = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

struct QueuedRequest {
    record: Vec<u8>,
    budget: OwnedSemaphorePermit,
    deadline: Instant,
}

struct QueuedReply {
    reply: EncodedReply,
    _budget: Arc<OwnedSemaphorePermit>,
}

pub(crate) async fn serve_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    stream.set_nodelay(true)?;
    let record_limits = state.limits.record_limits();
    let queue_capacity = state.limits.max_requests_per_connection;
    let (request_sender, request_receiver) = mpsc::channel(queue_capacity);
    let (reply_sender, reply_receiver) = mpsc::channel(queue_capacity);
    let (read_half, write_half) = stream.into_split();

    let reader = connection_reader(
        read_half,
        request_sender,
        record_limits,
        state.limits.idle_connection_timeout,
        state.limits.request_timeout,
        state.request_buffers.clone(),
        shutdown.clone(),
    );
    let processor = connection_processor(request_receiver, reply_sender, client_addr, state.clone(), shutdown);
    let writer = connection_writer(write_half, reply_receiver, record_limits, state.limits.request_timeout);
    tokio::try_join!(reader, processor, writer)?;
    Ok(())
}

async fn connection_reader(
    mut reader: OwnedReadHalf,
    sender: mpsc::Sender<QueuedRequest>,
    limits: RecordLimits,
    idle_timeout: Duration,
    progress_timeout: Duration,
    request_buffers: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let read = timeout(idle_timeout, read_record_budgeted(&mut reader, limits, request_buffers.clone()));
        let (record, budget) = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            },
            result = read => match result {
                Err(_) => return Ok(()),
                Ok(Err(crate::rpc::record::RecordError::Io(error)))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) => return Ok(()),
                Ok(Err(error)) => return Err(ServerError::Record(error)),
                Ok(Ok(record)) => record,
            },
        };
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            },
            result = timeout(progress_timeout, sender.send(QueuedRequest {
                record,
                budget,
                deadline: Instant::now() + progress_timeout,
            })) => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => return Err(ServerError::RequestTimeout),
                }
            },
        }
    }
}

async fn connection_processor(
    mut receiver: mpsc::Receiver<QueuedRequest>,
    reply_sender: mpsc::Sender<QueuedReply>,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let mut requests = JoinSet::new();
    let mut shutting_down = *shutdown.borrow();
    if shutting_down {
        receiver.close();
    }
    loop {
        if receiver.is_closed() && receiver.is_empty() && requests.is_empty() {
            return Ok(());
        }
        tokio::select! {
            changed = shutdown.changed(), if !shutting_down => {
                if changed.is_err() || *shutdown.borrow() {
                    shutting_down = true;
                    receiver.close();
                }
            },
            request = receiver.recv(), if requests.len() < state.limits.max_requests_per_connection
                && (!receiver.is_closed() || !receiver.is_empty()) => {
                if let Some(request) = request {
                    requests.spawn(handle_request(request, client_addr, state.clone(), reply_sender.clone()));
                }
            },
            joined = requests.join_next(), if !requests.is_empty() => {
                if let Some(result) = joined {
                    result.map_err(ServerError::Task)??;
                }
            },
        }
    }
}

async fn connection_writer(
    mut writer: OwnedWriteHalf,
    mut receiver: mpsc::Receiver<QueuedReply>,
    limits: RecordLimits,
    progress_timeout: Duration,
) -> Result<(), ServerError> {
    while let Some(reply) = receiver.recv().await {
        match timeout(progress_timeout, write_record_segments_limited(&mut writer, reply.reply.segments(), limits))
            .await
        {
            Ok(result) => result?,
            Err(_) => return Err(ServerError::RequestTimeout),
        }
    }
    Ok(())
}

/// The fixed RPC call header plus the locations of the credential body and
/// the procedure arguments within the record.
struct RpcCall {
    header: CallHeader,
    credential_flavor: u32,
    credential: Range<usize>,
    verifier_is_none: bool,
    arguments_offset: usize,
}

impl RpcCall {
    fn decode(record: &[u8]) -> Result<Self, ServerError> {
        let mut decoder = Decoder::new(record);
        let xid = decoder.read_u32()?;
        if decoder.read_u32()? != message::CALL {
            return Err(ServerError::Protocol("received an RPC reply on a server connection"));
        }
        let rpc_version = decoder.read_u32()?;
        let program = decoder.read_u32()?;
        let version = decoder.read_u32()?;
        let procedure = decoder.read_u32()?;
        let credential_flavor = decoder.read_u32()?;
        let credential_start = decoder.position() + 4;
        let credential_length = decoder.read_opaque_slice("RPC credential", MAX_AUTH_BYTES)?.len();
        let verifier_flavor = decoder.read_u32()?;
        let verifier = decoder.read_opaque_slice("RPC verifier", MAX_AUTH_BYTES)?;
        Ok(Self {
            header: CallHeader {
                xid,
                rpc_version,
                program,
                version,
                procedure,
            },
            credential_flavor,
            credential: credential_start..credential_start + credential_length,
            verifier_is_none: verifier_flavor == AUTH_NONE && verifier.is_empty(),
            arguments_offset: decoder.position(),
        })
    }
}

/// Runs one queued call to completion: reserves the reply bytes it may need,
/// dispatches it, and queues its reply for the connection writer.
async fn handle_request(
    request: QueuedRequest,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    reply_sender: mpsc::Sender<QueuedReply>,
) -> Result<(), ServerError> {
    let QueuedRequest {
        record,
        budget: request_budget,
        deadline,
    } = request;
    let record = Bytes::from(record);
    let xid = record
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let call = RpcCall::decode(&record);
    let reservation = match &call {
        Ok(call) => {
            let CallHeader {
                program,
                version,
                procedure,
                ..
            } = call.header;
            state
                .limits
                .reply_reservation(program, version, procedure, &record[call.arguments_offset..])
        },
        Err(_) => MAXIMUM_FIXED_REPLY_SIZE,
    };
    // Reservations never exceed the record limit, which is validated to fit
    // in a `u32`.
    let reply_budget = timeout_at(deadline, state.reply_buffers.clone().acquire_many_owned(reservation as u32))
        .await
        .map_err(|_| ServerError::RequestTimeout)?
        .map_err(|_| ServerError::ShuttingDown)?;
    let reply_budget = Arc::new(reply_budget);
    let reply = match call {
        Ok(call) => {
            let execution = Execution {
                request_budget,
                reply_budget: reply_budget.clone(),
                reply_limit: reservation,
                deadline,
            };
            dispatch_record(record, call, client_addr, &state, execution).await
        },
        Err(error) => Err(error),
    };
    let reply = reply.unwrap_or_else(|error| {
        tracing::debug!(client = %client_addr, error = %error, "RPC request rejected");
        message::accepted_reply(xid, AcceptStatus::SystemError, &[]).into()
    });
    let queued = QueuedReply {
        reply,
        _budget: reply_budget,
    };
    // A closed reply channel only means that the connection already ended.
    match timeout_at(deadline, reply_sender.send(queued)).await {
        Ok(_) => Ok(()),
        Err(_) => Err(ServerError::RequestTimeout),
    }
}

/// Resources that a call's tracked execution holds until it finishes.
struct Execution {
    request_budget: OwnedSemaphorePermit,
    reply_budget: Arc<OwnedSemaphorePermit>,
    reply_limit: usize,
    deadline: Instant,
}

async fn dispatch_record(
    record: Bytes,
    call: RpcCall,
    client_addr: SocketAddr,
    state: &Arc<ConnectionState>,
    execution: Execution,
) -> Result<EncodedReply, ServerError> {
    let header = call.header;
    let xid = header.xid;
    if !call.verifier_is_none {
        return Ok(message::auth_error(xid, AuthStatus::BadVerifier).into());
    }
    let Ok(principal) = decode_principal(call.credential_flavor, &record[call.credential]) else {
        return Ok(message::auth_error(xid, AuthStatus::BadCredential).into());
    };
    if header.rpc_version != message::RPC_VERSION {
        return Ok(message::rpc_mismatch(xid).into());
    }
    if header.program != crate::portmap::PROGRAM && !principal_allowed(state.auth_policy, &principal) {
        return Ok(message::auth_error(xid, AuthStatus::TooWeak).into());
    }

    let arguments = record.slice(call.arguments_offset..);
    let export_id = request_export_id(header.program, header.procedure, &arguments, state);
    let lease = if requires_replay_protection(header) {
        let replay_key = ReplayKey {
            client_addr: SocketAddr::new(client_addr.ip(), 0),
            export_id,
            xid,
        };
        match state
            .replay
            .begin(replay_key, request_fingerprint(header, &arguments, &principal))?
        {
            ReplayDecision::Replay(reply) => {
                tracing::debug!(xid, client = %client_addr, replay = "hit", "RPC reply replayed");
                return Ok(reply);
            },
            ReplayDecision::Wait(waiter) => {
                tracing::debug!(xid, client = %client_addr, replay = "wait", "waiting for in-flight duplicate");
                return match timeout_at(execution.deadline, waiter).await {
                    Ok(reply) => Ok(reply??),
                    Err(_) => {
                        tracing::warn!(client = %client_addr, xid, "duplicate RPC request timed out");
                        Err(ServerError::RequestTimeout)
                    },
                };
            },
            ReplayDecision::Execute(lease) => {
                tracing::trace!(xid, client = %client_addr, replay = "miss", "new RPC request");
                Some(lease)
            },
        }
    } else {
        None
    };

    let context = RequestContext {
        principal,
        client_addr,
        export_id,
    };
    let request_bytes = record.len();
    let Execution {
        request_budget,
        reply_budget,
        reply_limit,
        deadline,
    } = execution;
    let permit = match timeout_at(deadline, state.requests.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(ServerError::ShuttingDown),
        Err(_) => {
            tracing::warn!(client = %client_addr, xid, "RPC request timed out waiting for execution capacity");
            return Err(ServerError::RequestTimeout);
        },
    };
    let executions = state.executions.upgrade().ok_or(ServerError::ShuttingDown)?;
    let execution_state = state.clone();
    let (send, receive) = oneshot::channel();
    executions.spawn(async move {
        // The execution tracker outlives a disconnected connection. Keep
        // both aggregate buffer charges until its request bytes and any
        // constructed reply have been released.
        let _permit = permit;
        let _request_budget = request_budget;
        let _reply_budget = reply_budget;
        let execution = execute_request(header, arguments, context, request_bytes, reply_limit, execution_state);
        let result = match timeout_at(deadline, execution).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(client = %client_addr, xid, "RPC execution reached its deadline and was cancelled");
                Err(ServerError::RequestTimeout)
            },
        };
        // Store the reply before callers attempt socket delivery so that a
        // retransmission after a lost reply replays it.
        if let Some(lease) = lease {
            match &result {
                Ok(reply) => lease.complete(reply.clone()),
                Err(_) => lease.cancel(),
            }
        }
        let _ = send.send(result);
    });
    drop(executions);
    receive.await?
}

/// Only non-idempotent NFS procedures pass through the duplicate-request
/// cache. Idempotent calls, including every MOUNT and portmapper call, are
/// executed again when retransmitted, so bulk READ and READDIR payloads are
/// never fingerprinted, copied into, or retained by the cache.
fn requires_replay_protection(header: CallHeader) -> bool {
    header.program == crate::nfs3::types::PROGRAM
        && header.version == crate::nfs3::types::VERSION
        && Procedure::from_wire(header.procedure).is_some_and(Procedure::is_non_idempotent)
}

fn request_fingerprint(header: CallHeader, arguments: &[u8], principal: &Principal) -> RequestFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(header.program.to_be_bytes());
    hasher.update(header.version.to_be_bytes());
    hasher.update(header.procedure.to_be_bytes());
    hasher.update(arguments);
    hash_principal(&mut hasher, principal);
    RequestFingerprint(hasher.finalize().into())
}

async fn execute_request(
    header: CallHeader,
    arguments: Bytes,
    context: RequestContext,
    request_bytes: usize,
    reply_limit: usize,
    state: Arc<ConnectionState>,
) -> Result<EncodedReply, ServerError> {
    let CallHeader {
        xid,
        program,
        version,
        procedure,
        ..
    } = header;
    let client_addr = context.client_addr;
    let procedure_name = procedure_name(program, procedure);
    let started_at = std::time::Instant::now();
    let span = tracing::info_span!(
        "rpc_request",
        xid,
        client = %client_addr,
        program,
        version,
        procedure,
        procedure_name,
        request_bytes,
    );
    let reply = match dispatch_call(header, &arguments, &context, &state).instrument(span).await {
        Ok(reply) => reply,
        Err(ServerError::Decode(_)) => message::accepted_reply(xid, AcceptStatus::GarbageArguments, &[]).into(),
        Err(ServerError::Encode(error)) => {
            tracing::warn!(client = %client_addr, xid, error = %error, "RPC result could not be encoded");
            message::accepted_reply(xid, AcceptStatus::SystemError, &[]).into()
        },
        Err(error) => return Err(error),
    };
    // The reply must fit the transport and the reply-buffer bytes reserved
    // for this call before it executed.
    let limits = RecordLimits {
        max_record_size: reply_limit,
        ..state.limits.record_limits()
    };
    if let Err(error) = validate_record_length(reply.len(), limits) {
        tracing::warn!(client = %client_addr, xid, error = %error, "RPC result exceeded outbound limits");
        return Ok(message::accepted_reply(xid, AcceptStatus::SystemError, &[]).into());
    }
    let reply_prefix = reply.prefix();
    let protocol_status = if (program == crate::nfs3::types::PROGRAM || program == crate::mount3::types::PROGRAM)
        && reply_prefix.len() >= ACCEPTED_REPLY_HEADER_SIZE + 4
    {
        u32::from_be_bytes(reply_prefix[24..28].try_into().unwrap_or_default())
    } else {
        0
    };
    tracing::debug!(
        xid,
        client = %client_addr,
        procedure = procedure_name,
        duration_micros = started_at.elapsed().as_micros(),
        protocol_status,
        request_bytes,
        reply_bytes = reply.len(),
        active_requests = state.limits.max_inflight_requests - state.requests.available_permits(),
        "RPC request completed"
    );
    Ok(reply)
}

fn hash_principal(hasher: &mut Sha256, principal: &Principal) {
    match principal {
        Principal::Anonymous => hasher.update([0]),
        Principal::AuthSys {
            uid,
            gid,
            supplementary_gids,
            machine_name,
        } => {
            hasher.update([1]);
            hasher.update(uid.to_be_bytes());
            hasher.update(gid.to_be_bytes());
            hasher.update((supplementary_gids.len() as u32).to_be_bytes());
            for group in supplementary_gids {
                hasher.update(group.to_be_bytes());
            }
            hasher.update((machine_name.len() as u32).to_be_bytes());
            hasher.update(machine_name);
        },
    }
}

fn procedure_name(program: u32, procedure: u32) -> &'static str {
    match program {
        crate::nfs3::types::PROGRAM => Procedure::from_wire(procedure).map_or("UNKNOWN_NFS", Procedure::name),
        crate::mount3::types::PROGRAM => match procedure {
            0 => "MOUNT_NULL",
            1 => "MNT",
            2 => "DUMP",
            3 => "UMNT",
            4 => "UMNTALL",
            5 => "EXPORT",
            _ => "UNKNOWN_MOUNT",
        },
        crate::portmap::PROGRAM => match procedure {
            0 => "PMAP_NULL",
            3 => "GETPORT",
            _ => "UNKNOWN_PORTMAP",
        },
        _ => "UNKNOWN_RPC",
    }
}

/// Selects the export a call addresses, for routing and replay keys. NFS
/// calls use the export ID inside their first file handle without verifying
/// its tag; `decode_object` authenticates every handle before the VFS sees it.
fn request_export_id(program: u32, procedure: u32, args: &[u8], state: &ConnectionState) -> ExportId {
    if program == crate::nfs3::types::PROGRAM && procedure != Procedure::Null as u32 {
        let handle = Decoder::new(args).read_opaque_slice("NFS file handle", 64);
        return handle
            .ok()
            .and_then(|handle| state.handles.peek_export(handle).ok())
            .unwrap_or_else(|| state.exports.first().map_or(ExportId(0), |export| export.id));
    }
    if program == crate::mount3::types::PROGRAM && matches!(procedure, 1 | 3) {
        if let Ok(path) = Decoder::new(args).read_opaque_slice("MOUNT path", MAX_PATH) {
            if let Some(export) = select_export(state, path) {
                return export.id;
            }
        }
    }
    ExportId(0)
}

fn select_export<'a>(state: &'a ConnectionState, requested: &[u8]) -> Option<&'a ExportState> {
    state
        .exports
        .iter()
        .filter(|export| crate::mount3::dispatch::export_matches(export.path.as_bytes(), requested))
        .max_by_key(|export| export.path.len())
}

async fn dispatch_call(
    header: CallHeader,
    args: &Bytes,
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<EncodedReply, ServerError> {
    let CallHeader {
        xid,
        program,
        version,
        procedure,
        ..
    } = header;
    match program {
        crate::nfs3::types::PROGRAM => {
            if version != crate::nfs3::types::VERSION {
                return Ok(message::program_mismatch(xid, VersionRange::exact(crate::nfs3::types::VERSION)).into());
            }
            dispatch_nfs(xid, procedure, args, context, state).await
        },
        crate::mount3::types::PROGRAM => {
            if version != crate::mount3::types::VERSION {
                return Ok(message::program_mismatch(xid, VersionRange::exact(crate::mount3::types::VERSION)).into());
            }
            dispatch_mount(xid, procedure, args, context, state).await.map(Into::into)
        },
        crate::portmap::PROGRAM if state.portmapper == PortmapperMode::Enabled => {
            if version != crate::portmap::VERSION {
                return Ok(message::program_mismatch(xid, VersionRange::exact(crate::portmap::VERSION)).into());
            }
            dispatch_portmap(xid, procedure, args, state).map(Into::into)
        },
        _ => Ok(message::accepted_reply(xid, AcceptStatus::ProgramUnavailable, &[]).into()),
    }
}

/// Why an NFS call ended without its procedure-specific reply.
enum NfsFailure {
    /// The call failed before or inside the VFS with a status whose result arm
    /// carries no post-operation data; `nfs_failure_reply` encodes it.
    Status(NfsStatus),
    Server(ServerError),
}

impl From<NfsStatus> for NfsFailure {
    fn from(status: NfsStatus) -> Self {
        Self::Status(status)
    }
}

impl From<NfsError> for NfsFailure {
    fn from(error: NfsError) -> Self {
        Self::Status(error.into())
    }
}

impl From<EncodeError> for NfsFailure {
    fn from(error: EncodeError) -> Self {
        Self::Server(error.into())
    }
}

async fn dispatch_nfs(
    xid: u32,
    procedure: u32,
    args: &Bytes,
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<EncodedReply, ServerError> {
    let Some(procedure) = Procedure::from_wire(procedure) else {
        return Ok(message::accepted_reply(xid, AcceptStatus::ProcedureUnavailable, &[]).into());
    };
    let max_variable_size = state.limits.max_rpc_record_size;
    let result = if procedure == Procedure::Write {
        // WRITE data stays a zero-copy slice of the retained RPC record.
        let arguments = WriteRequest::decode(args.clone(), max_variable_size)?;
        match export_vfs(state, context.export_id) {
            Ok(vfs) => dispatch_write(xid, arguments, context, state, vfs).await,
            Err(status) => Err(status.into()),
        }
    } else {
        let arguments = NfsArguments::decode(procedure as u32, args, max_variable_size)?;
        execute_nfs(xid, arguments, context, state).await
    };
    match result {
        Ok(reply) => Ok(reply),
        Err(NfsFailure::Status(status)) => Ok(nfs_failure_reply(xid, procedure, status)?.into()),
        Err(NfsFailure::Server(error)) => Err(error),
    }
}

fn export_vfs(state: &ConnectionState, export_id: ExportId) -> Result<&dyn VirtualFileSystem, NfsStatus> {
    state
        .exports
        .iter()
        .find(|export| export.id == export_id)
        .map(|export| export.vfs.as_ref())
        .ok_or(NfsStatus::BadHandle)
}

async fn execute_nfs(
    xid: u32,
    arguments: NfsArguments,
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<EncodedReply, NfsFailure> {
    let vfs = match arguments {
        NfsArguments::Null => return Ok(message::accepted_reply(xid, AcceptStatus::Success, &[]).into()),
        _ => export_vfs(state, context.export_id)?,
    };
    let reply = match arguments {
        NfsArguments::Null => message::accepted_reply(xid, AcceptStatus::Success, &[]),
        NfsArguments::GetAttr(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let attributes = vfs.getattr(context, object).await?;
            nfs_reply(xid, &GetAttrResult::Ok { attributes })?
        },
        NfsArguments::SetAttr(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let result = vfs.setattr(context, object, arguments.attributes, arguments.guard).await?;
            let ((), object_wcc) = split_wcc(result);
            nfs_reply(xid, &SetAttrResult::Ok { object_wcc })?
        },
        NfsArguments::Lookup(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments)?;
            let found = vfs.lookup(context, parent, &name).await;
            let directory_attributes = vfs.getattr(context, parent).await.ok();
            let result = match found {
                Ok(found) => LookupResult::Ok {
                    object_handle: encode_handle(state, context, found.object),
                    object_attributes: found.attributes,
                    directory_attributes,
                },
                Err(error) => LookupResult::Err {
                    status: error.into(),
                    directory_attributes,
                },
            };
            nfs_reply(xid, &result)?
        },
        NfsArguments::Access(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let requested = arguments.requested & ACCESS_MASK;
            let allowed = vfs.access(context, object, requested).await;
            let attributes = vfs.getattr(context, object).await.ok();
            let result = match allowed {
                Ok(allowed) => AccessResult::Ok {
                    attributes,
                    access: allowed & requested,
                },
                Err(error) => AccessResult::Err {
                    status: error.into(),
                    attributes,
                },
            };
            nfs_reply(xid, &result)?
        },
        NfsArguments::ReadLink(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let path = vfs.readlink(context, object).await;
            let attributes = vfs.getattr(context, object).await.ok();
            let result = match path {
                Ok(path) => ReadLinkResult::Ok { attributes, path },
                Err(error) => ReadLinkResult::Err {
                    status: error.into(),
                    attributes,
                },
            };
            nfs_reply(xid, &result)?
        },
        NfsArguments::Read(arguments) => return dispatch_read(xid, arguments, context, state, vfs).await,
        NfsArguments::Write(arguments) => return dispatch_write(xid, arguments.into(), context, state, vfs).await,
        NfsArguments::Create(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments.target)?;
            let created = vfs.create(context, parent, &name, arguments.attributes, arguments.mode).await?;
            create_reply(xid, state, context, created)?
        },
        NfsArguments::Mkdir(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments.target)?;
            let created = vfs.mkdir(context, parent, &name, arguments.attributes).await?;
            create_reply(xid, state, context, created)?
        },
        NfsArguments::Symlink(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments.target)?;
            let created = vfs
                .symlink(context, parent, &name, &arguments.path, arguments.attributes)
                .await?;
            create_reply(xid, state, context, created)?
        },
        NfsArguments::Mknod(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments.target)?;
            let created = vfs
                .mknod(context, parent, &name, arguments.node_type, arguments.attributes)
                .await?;
            create_reply(xid, state, context, created)?
        },
        NfsArguments::Remove(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments)?;
            let ((), object_wcc) = split_wcc(vfs.remove(context, parent, &name).await?);
            nfs_reply(xid, &WccResult::Ok { object_wcc })?
        },
        NfsArguments::Rmdir(arguments) => {
            let (parent, name) = decode_directory_operation(state, context, arguments)?;
            let ((), object_wcc) = split_wcc(vfs.rmdir(context, parent, &name).await?);
            nfs_reply(xid, &WccResult::Ok { object_wcc })?
        },
        NfsArguments::Rename(arguments) => {
            let (from_parent, from_name) = decode_directory_operation(state, context, arguments.from)?;
            let (to_parent, to_name) = decode_directory_operation(state, context, arguments.to)?;
            let (from, to) = vfs.rename(context, from_parent, &from_name, to_parent, &to_name).await?;
            nfs_reply(
                xid,
                &RenameResult::Ok {
                    from_directory_wcc: split_wcc(from).1,
                    to_directory_wcc: split_wcc(to).1,
                },
            )?
        },
        NfsArguments::Link(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let (parent, name) = decode_directory_operation(state, context, arguments.target)?;
            let ((), directory_wcc) = split_wcc(vfs.link(context, object, parent, &name).await?);
            let object_attributes = vfs.getattr(context, object).await.ok();
            nfs_reply(
                xid,
                &LinkResult::Ok {
                    object_attributes,
                    directory_wcc,
                },
            )?
        },
        NfsArguments::ReadDir(arguments) => {
            let directory = decode_object(state, context, &arguments.directory)?;
            let request = ReadDirRequest {
                directory,
                cookie: arguments.cookie,
                verifier: arguments.verifier,
                max_count: arguments.count,
                directory_count: None,
            };
            readdir_reply(xid, request, context, state, vfs).await?
        },
        NfsArguments::ReadDirPlus(arguments) => {
            let directory = decode_object(state, context, &arguments.directory)?;
            let request = ReadDirRequest {
                directory,
                cookie: arguments.cookie,
                verifier: arguments.verifier,
                max_count: arguments.max_count,
                directory_count: Some(arguments.directory_count),
            };
            readdir_reply(xid, request, context, state, vfs).await?
        },
        NfsArguments::FsStat(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let info = vfs.fsstat(context, object).await?;
            let attributes = vfs.getattr(context, object).await.ok();
            nfs_reply(xid, &FsStatResult::Ok { attributes, info })?
        },
        NfsArguments::FsInfo(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let info = vfs.fsinfo(context, object).await?;
            let attributes = vfs.getattr(context, object).await.ok();
            let capabilities = vfs.capabilities();
            let properties = [
                (capabilities.hard_links, FSF3_LINK),
                (capabilities.symbolic_links, FSF3_SYMLINK),
                (capabilities.homogeneous, FSF3_HOMOGENEOUS),
                (capabilities.can_set_time, FSF3_CANSETTIME),
            ]
            .into_iter()
            .filter(|(supported, _)| *supported)
            .fold(0, |properties, (_, bit)| properties | bit);
            // Transfer sizes are clamped to what the transport can carry.
            let max_read = info.max_read.min(state.limits.max_read_size);
            let max_write = info.max_write.min(state.limits.max_write_size);
            let info = FsInfo {
                max_read,
                preferred_read: info.preferred_read.min(max_read),
                read_multiple: info.read_multiple.min(max_read),
                max_write,
                preferred_write: info.preferred_write.min(max_write),
                write_multiple: info.write_multiple.min(max_write),
                preferred_readdir: info.preferred_readdir.min(state.limits.max_readdir_response_size),
                ..info
            };
            nfs_reply(
                xid,
                &FsInfoResult::Ok {
                    attributes,
                    info,
                    properties,
                },
            )?
        },
        NfsArguments::PathConf(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let mut info = vfs.pathconf(context, object).await?;
            let attributes = vfs.getattr(context, object).await.ok();
            info.max_name_length = info.max_name_length.min(NfsName::MAX_LEN as u32);
            nfs_reply(xid, &PathConfResult::Ok { attributes, info })?
        },
        NfsArguments::Commit(arguments) => {
            let object = decode_object(state, context, &arguments.object)?;
            let result = vfs.commit(context, object, arguments.offset, arguments.count).await?;
            let ((), file_wcc) = split_wcc(result);
            nfs_reply(
                xid,
                &CommitResult::Ok {
                    file_wcc,
                    verifier: state.handles.instance_id(),
                },
            )?
        },
    };
    Ok(reply.into())
}

async fn dispatch_read(
    xid: u32,
    arguments: ReadArgs,
    context: &RequestContext,
    state: &ConnectionState,
    vfs: &dyn VirtualFileSystem,
) -> Result<EncodedReply, NfsFailure> {
    let object = decode_object(state, context, &arguments.object)?;
    let count = arguments.count.min(state.limits.max_read_size);
    let mut result = vfs.read_bytes(context, object, arguments.offset, count).await?;
    // `Bytes::truncate` keeps sharing the backend allocation; the segmented
    // reply holds it through socket I/O without copying the payload.
    result.data.truncate(count as usize);
    Ok(read_success_reply(xid, result.attributes.as_ref(), result.data, result.eof)?)
}

fn read_success_reply(
    xid: u32,
    attributes: Option<&FileAttributes>,
    data: Bytes,
    eof: bool,
) -> Result<EncodedReply, EncodeError> {
    // Encode only the fixed RPC/NFS fields here. The potentially large opaque
    // payload and its static zero padding remain separate transport segments.
    let data_length = u32::try_from(data.len()).map_err(|_| EncodeError::TooLarge(data.len()))?;
    let mut prefix = message::accepted_reply_encoder(xid, AcceptStatus::Success, 128);
    prefix.write_u32(NfsStatus::Ok as u32);
    encode_post_attributes(&mut prefix, attributes)?;
    prefix.write_u32(data_length);
    prefix.write_bool(eof);
    prefix.write_u32(data_length);
    let padding = (4 - data.len() % 4) % 4;
    Ok(EncodedReply::segmented(Bytes::from(prefix.into_bytes()), data, padding))
}

async fn dispatch_write(
    xid: u32,
    arguments: WriteRequest,
    context: &RequestContext,
    state: &ConnectionState,
    vfs: &dyn VirtualFileSystem,
) -> Result<EncodedReply, NfsFailure> {
    arguments.validate()?;
    let object = decode_object(state, context, &arguments.object)?;
    let requested = arguments.requested;
    let permitted_count = arguments.data.len().min(state.limits.max_write_size as usize);
    // `WriteRequest` owns the RPC record, so this borrowed range stays valid
    // for the complete asynchronous backend call without another allocation.
    let data = &arguments.data[..permitted_count];
    let (written, file_wcc) = split_wcc(vfs.write(context, object, arguments.offset, data, requested).await?);
    // Never report more bytes than were offered, no progress for a non-empty
    // write, or weaker durability than the client requested.
    let result = if written.count as usize <= data.len()
        && (data.is_empty() || written.count != 0)
        && durability_satisfies(written.committed, requested)
    {
        WriteResult::Ok {
            file_wcc,
            count: written.count,
            committed: written.committed,
            verifier: state.handles.instance_id(),
        }
    } else {
        WriteResult::Err {
            status: NfsStatus::ServerFault,
            file_wcc,
        }
    };
    Ok(nfs_reply(xid, &result)?.into())
}

fn durability_satisfies(actual: WriteStability, requested: WriteStability) -> bool {
    use WriteStability::{DataSync, FileSync, Unstable};
    matches!((actual, requested), (FileSync, _) | (DataSync, DataSync | Unstable) | (Unstable, Unstable))
}

struct ReadDirRequest {
    directory: ObjectKey,
    cookie: u64,
    verifier: [u8; 8],
    max_count: u32,
    /// READDIRPLUS `dircount`; `None` for READDIR.
    directory_count: Option<u32>,
}

async fn readdir_reply(
    xid: u32,
    request: ReadDirRequest,
    context: &RequestContext,
    state: &ConnectionState,
    vfs: &dyn VirtualFileSystem,
) -> Result<Vec<u8>, NfsFailure> {
    let max_size = request.max_count.min(state.limits.max_readdir_response_size) as usize;
    if max_size < MINIMUM_READDIR_COUNT {
        return Err(NfsStatus::TooSmall.into());
    }
    let limits = ReadDirLimits {
        max_size,
        directory_size: request.directory_count.map(|count| count as usize),
    };
    // Directory entries need at least 32 bytes on the wire; the hint keeps
    // backend pages close to what one reply can carry.
    let hint = (limits.directory_size.map_or(max_size, |count| count.min(max_size)) / 32).clamp(1, 4096);
    let page = vfs
        .readdir(context, request.directory, request.cookie, request.verifier, hint)
        .await?;
    let directory_attributes = vfs.getattr(context, request.directory).await.ok();
    let plus = request.directory_count.is_some();
    // Entries are converted lazily, so file handles are only authenticated
    // for entries that fit in the reply.
    let entries = page.entries.into_iter().map(|entry| ReadDirEntry {
        file_id: entry.file_id,
        name: entry.name.into_bytes(),
        cookie: entry.cookie,
        extension: if plus {
            ReadDirEntryExtension::Plus {
                attributes: entry.attributes,
                handle: Some(encode_handle(state, context, entry.object)),
            }
        } else {
            ReadDirEntryExtension::Basic
        },
    });
    let mut reply = message::accepted_reply_encoder(xid, AcceptStatus::Success, max_size.min(64 * 1024) + 4);
    encode_readdir_reply(&mut reply, directory_attributes.as_ref(), page.verifier, entries, page.eof, limits)?;
    Ok(reply.into_bytes())
}

fn decode_object(state: &ConnectionState, context: &RequestContext, handle: &[u8]) -> Result<ObjectKey, NfsStatus> {
    state.handles.decode(context.export_id, handle).map_err(|error| match error {
        HandleError::StaleInstance => NfsStatus::Stale,
        _ => NfsStatus::BadHandle,
    })
}

fn decode_directory_operation(
    state: &ConnectionState,
    context: &RequestContext,
    arguments: DirectoryOperationArgs,
) -> Result<(ObjectKey, NfsName), NfsStatus> {
    let parent = decode_object(state, context, &arguments.directory)?;
    let name = NfsName::new(arguments.name)?;
    Ok((parent, name))
}

fn encode_handle(state: &ConnectionState, context: &RequestContext, object: ObjectKey) -> Vec<u8> {
    state.handles.encode(context.export_id, object).to_vec()
}

fn split_wcc<T>(result: MutationResult<T>) -> (T, WccData) {
    (
        result.value,
        WccData {
            before: result.before,
            after: result.after,
        },
    )
}

fn create_reply(
    xid: u32,
    state: &ConnectionState,
    context: &RequestContext,
    created: MutationResult<CreatedObject>,
) -> Result<Vec<u8>, EncodeError> {
    let (created, directory_wcc) = split_wcc(created);
    nfs_reply(
        xid,
        &CreateResult::Ok {
            object_handle: Some(encode_handle(state, context, created.object)),
            object_attributes: created.attributes,
            directory_wcc,
        },
    )
}

fn nfs_reply<T: EncodeNfsResult>(xid: u32, result: &T) -> Result<Vec<u8>, EncodeError> {
    let mut reply = message::accepted_reply_encoder(xid, AcceptStatus::Success, 128);
    result.encode_result(&mut reply)?;
    Ok(reply.into_bytes())
}

/// Encodes the failure arm of `procedure` with no post-operation attributes
/// or WCC data.
fn nfs_failure_reply(xid: u32, procedure: Procedure, status: NfsStatus) -> Result<Vec<u8>, EncodeError> {
    let wcc = WccData::default;
    match procedure {
        Procedure::Null => Ok(message::accepted_reply(xid, AcceptStatus::ProcedureUnavailable, &[])),
        Procedure::GetAttr => nfs_reply(xid, &GetAttrResult::Err { status }),
        Procedure::SetAttr => nfs_reply(
            xid,
            &SetAttrResult::Err {
                status,
                object_wcc: wcc(),
            },
        ),
        Procedure::Lookup => nfs_reply(
            xid,
            &LookupResult::Err {
                status,
                directory_attributes: None,
            },
        ),
        Procedure::Access => nfs_reply(
            xid,
            &AccessResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::ReadLink => nfs_reply(
            xid,
            &ReadLinkResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::Read => nfs_reply(
            xid,
            &ReadResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::Write => nfs_reply(
            xid,
            &WriteResult::Err {
                status,
                file_wcc: wcc(),
            },
        ),
        Procedure::Create | Procedure::Mkdir | Procedure::Symlink | Procedure::Mknod => nfs_reply(
            xid,
            &CreateResult::Err {
                status,
                directory_wcc: wcc(),
            },
        ),
        Procedure::Remove | Procedure::Rmdir => nfs_reply(
            xid,
            &WccResult::Err {
                status,
                object_wcc: wcc(),
            },
        ),
        Procedure::Rename => nfs_reply(
            xid,
            &RenameResult::Err {
                status,
                from_directory_wcc: wcc(),
                to_directory_wcc: wcc(),
            },
        ),
        Procedure::Link => nfs_reply(
            xid,
            &LinkResult::Err {
                status,
                object_attributes: None,
                directory_wcc: wcc(),
            },
        ),
        Procedure::ReadDir | Procedure::ReadDirPlus => nfs_reply(
            xid,
            &ReadDirResult::Err {
                status,
                directory_attributes: None,
            },
        ),
        Procedure::FsStat => nfs_reply(
            xid,
            &FsStatResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::FsInfo => nfs_reply(
            xid,
            &FsInfoResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::PathConf => nfs_reply(
            xid,
            &PathConfResult::Err {
                status,
                attributes: None,
            },
        ),
        Procedure::Commit => nfs_reply(
            xid,
            &CommitResult::Err {
                status,
                file_wcc: wcc(),
            },
        ),
    }
}

async fn dispatch_mount(
    xid: u32,
    procedure: u32,
    args: &[u8],
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<Vec<u8>, ServerError> {
    if matches!(procedure, 0 | 2 | 4 | 5) && !args.is_empty() {
        return Ok(message::accepted_reply(xid, AcceptStatus::GarbageArguments, &[]));
    }
    match procedure {
        0 => Ok(message::accepted_reply(xid, AcceptStatus::Success, &[])),
        1 => {
            let mut decoder = Decoder::new(args);
            let path = decoder.read_string("MOUNT path", MAX_PATH)?;
            decoder.finish()?;
            let Some(export) = select_export(state, &path) else {
                return Ok(mount_reply(xid, &MountResult::Err(MountStatus::NotFound))?);
            };
            let request_context = RequestContext {
                principal: context.principal.clone(),
                client_addr: context.client_addr,
                export_id: export.id,
            };
            let root = match resolve_mount_object(export, &request_context, &path).await {
                Ok(object) => object,
                Err(error) => return Ok(mount_reply(xid, &MountResult::Err(mount_status(error)))?),
            };
            let attributes = match export.vfs.getattr(&request_context, root).await {
                Ok(attributes) => attributes,
                Err(error) => return Ok(mount_reply(xid, &MountResult::Err(mount_status(error)))?),
            };
            if attributes.file_type != FileType::Directory {
                return Ok(mount_reply(xid, &MountResult::Err(MountStatus::NotDirectory))?);
            }
            let mut mounts = state.mounts.lock().await;
            let client = context.client_addr.ip();
            if !mounts.iter().any(|entry| entry.0 == client && entry.1 == path) {
                if mounts.len() >= state.limits.max_mounts {
                    return Ok(mount_reply(xid, &MountResult::Err(MountStatus::Io))?);
                }
                mounts.push((client, path));
            }
            drop(mounts);
            let auth_flavors = match state.auth_policy {
                AuthPolicy::Anonymous => vec![AUTH_NONE],
                AuthPolicy::AuthSys => vec![AUTH_SYS],
                AuthPolicy::AuthSysOrAnonymous => vec![AUTH_SYS, AUTH_NONE],
            };
            let result = MountResult::Ok {
                file_handle: state.handles.encode(export.id, root).to_vec(),
                auth_flavors,
            };
            Ok(mount_reply(xid, &result)?)
        },
        2 => {
            let mounts = state.mounts.lock().await;
            // Size the list before building it so that an oversized table
            // never materializes a reply that cannot be sent.
            let encoded_length = mounts
                .iter()
                .try_fold(ACCEPTED_REPLY_HEADER_SIZE + 4, |length, (client, path)| {
                    length
                        .checked_add(4)?
                        .checked_add(xdr_opaque_size(client.to_string().len())?)?
                        .checked_add(xdr_opaque_size(path.len())?)
                });
            if encoded_length.is_none_or(|length| !outbound_length_fits(length, &state.limits)) {
                return Ok(message::accepted_reply(xid, AcceptStatus::SystemError, &[]));
            }
            let result = DumpResult {
                mounts: mounts
                    .iter()
                    .map(|(client, path)| MountEntry {
                        host: client.to_string().into_bytes(),
                        path: path.clone(),
                    })
                    .collect(),
            };
            Ok(mount_reply(xid, &result)?)
        },
        3 => {
            let mut decoder = Decoder::new(args);
            let path = decoder.read_string("MOUNT path", MAX_PATH)?;
            decoder.finish()?;
            let client = context.client_addr.ip();
            state.mounts.lock().await.retain(|entry| entry.0 != client || entry.1 != path);
            Ok(message::accepted_reply(xid, AcceptStatus::Success, &[]))
        },
        4 => {
            let client = context.client_addr.ip();
            state.mounts.lock().await.retain(|entry| entry.0 != client);
            Ok(message::accepted_reply(xid, AcceptStatus::Success, &[]))
        },
        5 => {
            let encoded_length = state.exports.iter().try_fold(ACCEPTED_REPLY_HEADER_SIZE + 4, |length, export| {
                // Each export carries an empty group list terminator.
                length
                    .checked_add(4)?
                    .checked_add(xdr_opaque_size(export.path.len())?)?
                    .checked_add(4)
            });
            if encoded_length.is_none_or(|length| !outbound_length_fits(length, &state.limits)) {
                return Ok(message::accepted_reply(xid, AcceptStatus::SystemError, &[]));
            }
            let result = ExportResult {
                exports: state
                    .exports
                    .iter()
                    .map(|export| ExportEntry {
                        path: export.path.as_bytes().to_vec(),
                        groups: Vec::new(),
                    })
                    .collect(),
            };
            Ok(mount_reply(xid, &result)?)
        },
        _ => Ok(message::accepted_reply(xid, AcceptStatus::ProcedureUnavailable, &[])),
    }
}

fn xdr_opaque_size(length: usize) -> Option<usize> {
    4usize.checked_add(length.checked_next_multiple_of(4)?)
}

fn outbound_length_fits(length: usize, limits: &ServerLimits) -> bool {
    validate_record_length(length, limits.record_limits()).is_ok()
}

fn dispatch_portmap(xid: u32, procedure: u32, args: &[u8], state: &ConnectionState) -> Result<Vec<u8>, ServerError> {
    match procedure {
        0 if args.is_empty() => Ok(message::accepted_reply(xid, AcceptStatus::Success, &[])),
        0 => Ok(message::accepted_reply(xid, AcceptStatus::GarbageArguments, &[])),
        3 => {
            let request = crate::portmap::mapping::decode(args)?;
            let port = crate::portmap::dispatch::get_port(&request, state.local_port, state.local_port);
            Ok(message::accepted_reply(xid, AcceptStatus::Success, &port.to_be_bytes()))
        },
        _ => Ok(message::accepted_reply(xid, AcceptStatus::ProcedureUnavailable, &[])),
    }
}

fn principal_allowed(policy: AuthPolicy, principal: &Principal) -> bool {
    matches!(
        (policy, principal),
        (AuthPolicy::AuthSys, Principal::AuthSys { .. })
            | (AuthPolicy::Anonymous, Principal::Anonymous)
            | (AuthPolicy::AuthSysOrAnonymous, _)
    )
}

async fn resolve_mount_object(
    export: &ExportState,
    context: &RequestContext,
    requested: &[u8],
) -> Result<ObjectKey, NfsError> {
    let export_path = export.path.as_bytes();
    let suffix = if export_path == b"/" {
        requested.strip_prefix(b"/").ok_or(NfsError::NotFound)?
    } else {
        requested
            .strip_prefix(export_path)
            .ok_or(NfsError::NotFound)?
            .strip_prefix(b"/")
            .unwrap_or_default()
    };
    let mut object = export.vfs.root();
    for component in suffix.split(|byte| *byte == b'/').filter(|component| !component.is_empty()) {
        let name = NfsName::new(component.to_vec())?;
        object = export.vfs.lookup(context, object, &name).await?.object;
    }
    Ok(object)
}

fn mount_status(error: NfsError) -> MountStatus {
    match error {
        NfsError::Permission => MountStatus::Permission,
        NfsError::NotFound => MountStatus::NotFound,
        NfsError::Io => MountStatus::Io,
        NfsError::Access => MountStatus::Access,
        NfsError::NotDirectory => MountStatus::NotDirectory,
        NfsError::Invalid => MountStatus::Invalid,
        NfsError::NameTooLong => MountStatus::NameTooLong,
        NfsError::NotSupported => MountStatus::NotSupported,
        _ => MountStatus::ServerFault,
    }
}

fn mount_reply<T: EncodeMountResult>(xid: u32, result: &T) -> Result<Vec<u8>, EncodeError> {
    let mut reply = message::accepted_reply_encoder(xid, AcceptStatus::Success, 64);
    result.encode_result(&mut reply)?;
    Ok(reply.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::WccAttributes;

    #[test]
    fn durability_is_never_weaker_than_requested() {
        use WriteStability::{DataSync, FileSync, Unstable};
        for (actual, requested, satisfied) in [
            (Unstable, Unstable, true),
            (Unstable, DataSync, false),
            (Unstable, FileSync, false),
            (DataSync, Unstable, true),
            (DataSync, DataSync, true),
            (DataSync, FileSync, false),
            (FileSync, Unstable, true),
            (FileSync, DataSync, true),
            (FileSync, FileSync, true),
        ] {
            assert_eq!(durability_satisfies(actual, requested), satisfied, "{actual:?} for {requested:?}");
        }
    }

    #[test]
    fn only_non_idempotent_nfs_v3_calls_use_the_replay_cache() {
        let header = |program, version, procedure| CallHeader {
            xid: 1,
            rpc_version: 2,
            program,
            version,
            procedure,
        };
        let nfs = crate::nfs3::types::PROGRAM;
        for procedure in 0..crate::nfs3::types::PROCEDURE_COUNT {
            let expected = Procedure::from_wire(procedure).unwrap().is_non_idempotent();
            assert_eq!(requires_replay_protection(header(nfs, 3, procedure)), expected);
            assert!(!requires_replay_protection(header(nfs, 2, procedure)));
        }
        assert!(!requires_replay_protection(header(nfs, 3, 99)));
        for procedure in 0..6 {
            assert!(!requires_replay_protection(header(crate::mount3::types::PROGRAM, 3, procedure)));
        }
        assert!(!requires_replay_protection(header(crate::portmap::PROGRAM, 2, 3)));
    }

    #[test]
    fn every_failure_arm_is_a_complete_result_without_post_operation_data() {
        for procedure in (1..crate::nfs3::types::PROCEDURE_COUNT).filter_map(Procedure::from_wire) {
            let reply = nfs_failure_reply(9, procedure, NfsStatus::BadHandle).unwrap();
            let mut decoder = Decoder::new(&reply[ACCEPTED_REPLY_HEADER_SIZE..]);
            assert_eq!(decoder.read_u32(), Ok(NfsStatus::BadHandle as u32), "{}", procedure.name());
            // Every remaining word is an absent post-op attribute or WCC arm.
            while decoder.remaining() > 0 {
                assert_eq!(decoder.read_bool(), Ok(false), "{}", procedure.name());
            }
            let wcc_arms = match procedure {
                Procedure::GetAttr => 0,
                Procedure::SetAttr
                | Procedure::Write
                | Procedure::Create
                | Procedure::Mkdir
                | Procedure::Symlink
                | Procedure::Mknod
                | Procedure::Remove
                | Procedure::Rmdir
                | Procedure::Commit => 2,
                Procedure::Rename => 4,
                Procedure::Link => 3,
                _ => 1,
            };
            assert_eq!(reply.len(), ACCEPTED_REPLY_HEADER_SIZE + 4 + 4 * wcc_arms, "{}", procedure.name());
        }
    }

    #[test]
    fn mutation_wcc_data_is_moved_into_the_wire_result() {
        let before = WccAttributes {
            size: 1,
            modify_time: Default::default(),
            change_time: Default::default(),
        };
        let (value, wcc) = split_wcc(MutationResult {
            value: 7,
            before: Some(before),
            after: None,
        });
        assert_eq!(value, 7);
        assert_eq!(wcc.before, Some(before));
        assert_eq!(wcc.after, None);
    }

    #[test]
    fn xdr_list_sizes_include_padding_and_reject_overflow() {
        assert_eq!(xdr_opaque_size(0), Some(4));
        assert_eq!(xdr_opaque_size(1), Some(8));
        assert_eq!(xdr_opaque_size(4), Some(8));
        assert_eq!(xdr_opaque_size(usize::MAX), None);
        let limits = ServerLimits::production_defaults();
        assert!(outbound_length_fits(limits.max_rpc_record_size, &limits));
        assert!(!outbound_length_fits(limits.max_rpc_record_size + 1, &limits));
    }

    #[test]
    fn procedure_names_cover_every_served_program() {
        assert_eq!(procedure_name(crate::nfs3::types::PROGRAM, 17), "READDIRPLUS");
        assert_eq!(procedure_name(crate::nfs3::types::PROGRAM, 22), "UNKNOWN_NFS");
        assert_eq!(procedure_name(crate::mount3::types::PROGRAM, 1), "MNT");
        assert_eq!(procedure_name(crate::mount3::types::PROGRAM, 6), "UNKNOWN_MOUNT");
        assert_eq!(procedure_name(crate::portmap::PROGRAM, 3), "GETPORT");
        assert_eq!(procedure_name(crate::portmap::PROGRAM, 1), "UNKNOWN_PORTMAP");
        assert_eq!(procedure_name(1, 0), "UNKNOWN_RPC");
    }
}
