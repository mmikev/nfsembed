mod support;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use nfsembed::rpc::codec::Encoder;
use nfsembed::vfs::ExportId;
use support::rpc::{
    mount_root, nfs_args_directory, nfs_args_handle, start_server, RpcClient, NFS_PROGRAM, NFS_VERSION,
};
use support::vfs::ConformanceVfs;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct BufferWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct BufferMakeWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for BufferMakeWriter {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter {
            buffer: self.buffer.clone(),
        }
    }
}

#[tokio::test]
async fn tracing_contains_stable_operational_fields_without_sensitive_payloads() {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_ansi(false)
        .with_writer(BufferMakeWriter { buffer: buffer.clone() })
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let lookup = client
        .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(&root, b"file"))
        .await;
    let payload = support::rpc::nfs_payload(lookup);
    let mut decoder = nfsembed::rpc::codec::Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let file = decoder.read_opaque("file handle", 64).unwrap();

    let _ = client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&file)).await;

    // A retransmitted mutation is answered from the replay cache.
    const SECRET: &[u8] = b"never-log-this-file-content";
    let mut write = Encoder::new();
    write.write_opaque(&file).unwrap();
    write.write_u64(0);
    write.write_u32(SECRET.len() as u32);
    write.write_u32(0);
    write.write_opaque(SECRET).unwrap();
    let write = write.into_bytes();
    let _ = client.call_with_xid(900, NFS_PROGRAM, NFS_VERSION, 7, &write).await;
    let _ = client.call_with_xid(900, NFS_PROGRAM, NFS_VERSION, 7, &write).await;

    server.shutdown().await;

    let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    for required in [
        "connection opened",
        "connection closed",
        "active_connections",
        "RPC request completed",
        "procedure",
        "duration_micros",
        "protocol_status",
        "request_bytes",
        "reply_bytes",
        "active_requests",
        "RPC reply replayed",
        "replay=\"hit\"",
    ] {
        assert!(output.contains(required), "missing tracing field/event {required:?}:\n{output}");
    }
    assert!(!output.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(!output.contains("e2e-client"), "AUTH_SYS machine name leaked into normal logs");
}
