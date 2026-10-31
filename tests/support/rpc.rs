use std::net::SocketAddr;
use std::sync::Arc;

use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::rpc::record::{read_record, write_record, RecordLimits};
use nfsembed::server::{AuthPolicy, NfsServer, PortmapperMode, ServerHandle, ServerLimits};
use nfsembed::vfs::VirtualFileSystem;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub const NFS_PROGRAM: u32 = 100_003;
pub const NFS_VERSION: u32 = 3;
pub const MOUNT_PROGRAM: u32 = 100_005;
pub const MOUNT_VERSION: u32 = 3;
pub const PORTMAP_PROGRAM: u32 = 100_000;
pub const PORTMAP_VERSION: u32 = 2;

/// Like the Linux, macOS, and FreeBSD clients, send each call as one fragment.
const CALL_FRAGMENT_SIZE: usize = 0x7fff_ffff;

const RECORD_LIMITS: RecordLimits = RecordLimits {
    max_record_size: 4 * 1024 * 1024,
    max_fragment_size: 2 * 1024 * 1024,
    max_fragments: 32,
};

#[derive(Clone, Debug)]
pub enum Auth {
    Sys,
    None,
    Raw { flavor: u32, body: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcOutcome {
    Accepted {
        xid: u32,
        status: u32,
        payload: Vec<u8>,
    },
    Denied {
        xid: u32,
        reject_status: u32,
        details: Vec<u8>,
    },
}

impl RpcOutcome {
    pub fn accepted(self) -> (u32, Vec<u8>) {
        match self {
            Self::Accepted { status, payload, .. } => (status, payload),
            other => panic!("expected accepted RPC reply, got {other:?}"),
        }
    }
}

pub struct RpcClient {
    stream: TcpStream,
    next_xid: u32,
    auth: Auth,
}

impl RpcClient {
    pub async fn connect(address: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(address).await.unwrap(),
            next_xid: 1,
            auth: Auth::Sys,
        }
    }

    pub fn set_auth(&mut self, auth: Auth) {
        self.auth = auth;
    }

    pub async fn call(&mut self, program: u32, version: u32, procedure: u32, arguments: &[u8]) -> RpcOutcome {
        let xid = self.next_xid;
        self.next_xid += 1;
        self.call_with_xid(xid, program, version, procedure, arguments).await
    }

    pub async fn call_with_xid(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call(xid, 2, program, version, procedure, arguments, &self.auth);
        write_record(&mut self.stream, &request, CALL_FRAGMENT_SIZE).await.unwrap();
        self.read_reply().await
    }

    pub async fn call_with_rpc_version(
        &mut self,
        xid: u32,
        rpc_version: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call(xid, rpc_version, program, version, procedure, arguments, &self.auth);
        write_record(&mut self.stream, &request, CALL_FRAGMENT_SIZE).await.unwrap();
        self.read_reply().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn call_with_verifier(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
        verifier_flavor: u32,
        verifier: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call_with_verifier(
            xid,
            2,
            program,
            version,
            procedure,
            arguments,
            &self.auth,
            verifier_flavor,
            verifier,
        );
        write_record(&mut self.stream, &request, CALL_FRAGMENT_SIZE).await.unwrap();
        self.read_reply().await
    }

    pub async fn send_without_reading(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) {
        let request = rpc_call(xid, 2, program, version, procedure, arguments, &self.auth);
        write_record(&mut self.stream, &request, CALL_FRAGMENT_SIZE).await.unwrap();
    }

    pub async fn read_reply(&mut self) -> RpcOutcome {
        let record = read_record(&mut self.stream, RECORD_LIMITS).await.unwrap();
        parse_reply(&record)
    }

    pub async fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

pub struct RunningServer {
    pub handle: ServerHandle,
    pub address: SocketAddr,
}

impl RunningServer {
    pub async fn shutdown(self) {
        self.handle.shutdown().await.unwrap();
        self.handle.wait().await.unwrap();
    }
}

pub async fn start_server(vfs: Arc<dyn VirtualFileSystem>) -> RunningServer {
    start_server_with(vfs, ServerLimits::production_defaults(), AuthPolicy::AuthSys, PortmapperMode::Disabled).await
}

pub async fn start_server_with(
    vfs: Arc<dyn VirtualFileSystem>,
    limits: ServerLimits,
    auth_policy: AuthPolicy,
    portmapper: PortmapperMode,
) -> RunningServer {
    let server = NfsServer::builder_arc(vfs)
        .limits(limits)
        .auth_policy(auth_policy)
        .portmapper(portmapper)
        .build()
        .unwrap();
    start_built_server(server).await
}

pub async fn start_built_server(server: NfsServer) -> RunningServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let handle = server.start(listener).await.unwrap();
    let address = handle.mount_info().server_addr;
    RunningServer { handle, address }
}

pub fn rpc_call(
    xid: u32,
    rpc_version: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
    auth: &Auth,
) -> Vec<u8> {
    rpc_call_with_verifier(xid, rpc_version, program, version, procedure, arguments, auth, 0, &[])
}

#[allow(clippy::too_many_arguments)]
pub fn rpc_call_with_verifier(
    xid: u32,
    rpc_version: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
    auth: &Auth,
    verifier_flavor: u32,
    verifier: &[u8],
) -> Vec<u8> {
    let (credential_flavor, credential_body) = match auth {
        Auth::Sys => (1, auth_sys_body()),
        Auth::None => (0, Vec::new()),
        Auth::Raw { flavor, body } => (*flavor, body.clone()),
    };
    let mut call = Encoder::new();
    call.write_u32(xid);
    call.write_u32(0);
    call.write_u32(rpc_version);
    call.write_u32(program);
    call.write_u32(version);
    call.write_u32(procedure);
    call.write_u32(credential_flavor);
    call.write_opaque(&credential_body).unwrap();
    call.write_u32(verifier_flavor);
    call.write_opaque(verifier).unwrap();
    call.write_fixed(arguments);
    call.into_bytes()
}

pub fn auth_sys_body() -> Vec<u8> {
    let mut auth = Encoder::new();
    auth.write_u32(0x1234_5678);
    auth.write_opaque(b"e2e-client").unwrap();
    auth.write_u32(1000);
    auth.write_u32(100);
    auth.write_u32(2);
    auth.write_u32(10);
    auth.write_u32(20);
    auth.into_bytes()
}

pub fn parse_reply(record: &[u8]) -> RpcOutcome {
    let mut decoder = Decoder::new(record);
    let xid = decoder.read_u32().unwrap();
    assert_eq!(decoder.read_u32().unwrap(), 1, "server returned an RPC call instead of a reply");
    match decoder.read_u32().unwrap() {
        0 => {
            let _verifier_flavor = decoder.read_u32().unwrap();
            let _verifier = decoder.read_opaque("reply verifier", 400).unwrap();
            let status = decoder.read_u32().unwrap();
            RpcOutcome::Accepted {
                xid,
                status,
                payload: record[decoder.position()..].to_vec(),
            }
        },
        1 => {
            let reject_status = decoder.read_u32().unwrap();
            RpcOutcome::Denied {
                xid,
                reject_status,
                details: record[decoder.position()..].to_vec(),
            }
        },
        value => panic!("invalid RPC reply discriminant {value}"),
    }
}

pub fn nfs_args_handle(handle: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(handle).unwrap();
    encoder.into_bytes()
}

pub fn nfs_args_directory(handle: &[u8], name: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(handle).unwrap();
    encoder.write_opaque(name).unwrap();
    encoder.into_bytes()
}

/// SETATTR arguments that change nothing and carry no guard: the cheapest
/// non-idempotent call, used to exercise the replay cache.
pub fn nfs_args_setattr(handle: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(handle).unwrap();
    encode_empty_set_attributes(&mut encoder);
    encoder.write_bool(false);
    encoder.into_bytes()
}

pub fn encode_empty_set_attributes(encoder: &mut Encoder) {
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_u32(0);
    encoder.write_u32(0);
}

pub async fn mount_root(client: &mut RpcClient, path: &[u8]) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_opaque(path).unwrap();
    let (rpc_status, payload) = client
        .call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &arguments.into_bytes())
        .await
        .accepted();
    assert_eq!(rpc_status, 0);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let handle = decoder.read_opaque("mount handle", 64).unwrap();
    let flavors = decoder.read_u32().unwrap();
    assert!(flavors >= 1);
    for _ in 0..flavors {
        let _ = decoder.read_u32().unwrap();
    }
    decoder.finish().unwrap();
    handle
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireAttributes {
    pub file_type: u32,
    pub mode: u32,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub fs_id: u64,
    pub file_id: u64,
}

pub fn decode_attributes(decoder: &mut Decoder<'_>) -> WireAttributes {
    let file_type = decoder.read_u32().unwrap();
    let mode = decoder.read_u32().unwrap();
    let links = decoder.read_u32().unwrap();
    let uid = decoder.read_u32().unwrap();
    let gid = decoder.read_u32().unwrap();
    let size = decoder.read_u64().unwrap();
    let used = decoder.read_u64().unwrap();
    let rdev_major = decoder.read_u32().unwrap();
    let rdev_minor = decoder.read_u32().unwrap();
    let fs_id = decoder.read_u64().unwrap();
    let file_id = decoder.read_u64().unwrap();
    for _ in 0..3 {
        let _seconds = decoder.read_u32().unwrap();
        let _nanoseconds = decoder.read_u32().unwrap();
    }
    WireAttributes {
        file_type,
        mode,
        links,
        uid,
        gid,
        size,
        used,
        rdev_major,
        rdev_minor,
        fs_id,
        file_id,
    }
}

pub fn decode_post_attributes(decoder: &mut Decoder<'_>) -> Option<WireAttributes> {
    decoder.read_bool().unwrap().then(|| decode_attributes(decoder))
}

pub fn decode_wcc(decoder: &mut Decoder<'_>) -> (bool, bool) {
    let before = decoder.read_bool().unwrap();
    if before {
        let _size = decoder.read_u64().unwrap();
        for _ in 0..2 {
            let _seconds = decoder.read_u32().unwrap();
            let _nanoseconds = decoder.read_u32().unwrap();
        }
    }
    let after = decode_post_attributes(decoder).is_some();
    (before, after)
}

pub fn nfs_payload(outcome: RpcOutcome) -> Vec<u8> {
    let (rpc_status, payload) = outcome.accepted();
    assert_eq!(rpc_status, 0, "RPC layer rejected NFS request");
    payload
}

pub fn assert_nfs_status(outcome: RpcOutcome, expected: u32) -> Vec<u8> {
    let payload = nfs_payload(outcome);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), expected);
    payload
}

pub fn record_header(length: usize, last: bool) -> [u8; 4] {
    let length = u32::try_from(length).unwrap();
    (length | if last { 0x8000_0000 } else { 0 }).to_be_bytes()
}
