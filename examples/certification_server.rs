#[allow(dead_code)]
#[path = "../tests/support/certification_vfs.rs"]
mod certification_vfs;
#[path = "mirrorfs.rs"]
mod mirrorfs_backend;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use certification_vfs::{CertificationProfile, CertificationVfs};
use nfsembed::rpc::codec::Decoder;
use nfsembed::rpc::record::{read_record, write_record_limited, RecordLimits};
use nfsembed::{AuthPolicy, ExportId, NfsServer, PortmapperSockets, ServerLimits, VirtualFileSystem};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let listen = arguments.next().unwrap_or_else(|| "127.0.0.1:0".to_owned());
    let ready_file = PathBuf::from(arguments.next().ok_or("missing ready-file argument")?);
    let shutdown_file = PathBuf::from(arguments.next().ok_or("missing shutdown-file argument")?);
    let profile = arguments.next().unwrap_or_else(|| "read-write".to_owned());
    let restart_file = arguments.next().map(PathBuf::from);
    let portmapper_listen = arguments.next();
    let backend_root = arguments.next().map(PathBuf::from);

    let (vfs, lose_first_write_reply): (Arc<dyn VirtualFileSystem>, bool) = match profile.as_str() {
        "read-write" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite)), false),
        "lost-reply" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite)), true),
        "read-only" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadOnly)), false),
        "case-insensitive" => {
            (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::CaseInsensitive)), false)
        },
        "mirror" => (
            Arc::new(mirrorfs_backend::MirrorFs::new(backend_root.ok_or("mirror profile requires a backend root")?)),
            false,
        ),
        _ => return Err("unknown certification profile".into()),
    };
    let server = NfsServer::builder_arc(vfs)
        .auth_policy(AuthPolicy::AuthSysOrAnonymous)
        .build()?;
    if lose_first_write_reply {
        return serve_with_lost_write_reply(
            &server,
            &listen,
            &ready_file,
            &shutdown_file,
            portmapper_listen.as_deref(),
        )
        .await;
    }
    let mut bind_address = listen;

    loop {
        let listener = TcpListener::bind(&bind_address).await?;
        let address = listener.local_addr()?;
        bind_address = address.to_string();
        let handle = if let Some(portmapper_listen) = portmapper_listen.as_deref() {
            server
                .start_with_portmapper(listener, bind_portmapper(portmapper_listen, address.port()).await?)
                .await?
        } else {
            server.start(listener).await?
        };
        std::fs::write(&ready_file, address.port().to_string())?;
        while !shutdown_file.exists() && !restart_file.as_ref().is_some_and(|restart| restart.exists()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.shutdown().await?;
        handle.wait().await?;
        if shutdown_file.exists() || restart_file.is_none() {
            break;
        }
        if let Some(restart) = &restart_file {
            let _ = std::fs::remove_file(restart);
        }
    }
    Ok(())
}

async fn serve_with_lost_write_reply(
    server: &NfsServer,
    listen: &str,
    ready_file: &Path,
    shutdown_file: &Path,
    portmapper_listen: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let public_listener = TcpListener::bind(listen).await?;
    let public_port = public_listener.local_addr()?.port();
    let server_handle = if let Some(portmapper_listen) = portmapper_listen {
        server
            .start_with_portmapper(upstream_listener, bind_portmapper(portmapper_listen, public_port).await?)
            .await?
    } else {
        server.start(upstream_listener).await?
    };
    std::fs::write(ready_file, public_port.to_string())?;
    let lose_reply = Arc::new(AtomicBool::new(true));
    let mut proxies = JoinSet::new();

    loop {
        tokio::select! {
            accepted = public_listener.accept() => {
                let (client, _) = accepted?;
                let lose_reply = lose_reply.clone();
                proxies.spawn(async move {
                    let _ = proxy_connection(client, upstream_address, lose_reply).await;
                });
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if shutdown_file.exists() {
                    break;
                }
            },
            Some(_) = proxies.join_next(), if !proxies.is_empty() => {},
        }
    }

    proxies.abort_all();
    while proxies.join_next().await.is_some() {}
    server_handle.shutdown().await?;
    server_handle.wait().await?;
    Ok(())
}

async fn bind_portmapper(address: &str, advertised_port: u16) -> Result<PortmapperSockets, std::io::Error> {
    let tcp = TcpListener::bind(address).await?;
    let udp = UdpSocket::bind(tcp.local_addr()?).await?;
    Ok(PortmapperSockets::new(tcp, udp).advertised_ports(advertised_port, advertised_port))
}

async fn proxy_connection(
    mut client: TcpStream,
    upstream_address: std::net::SocketAddr,
    lose_reply: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut upstream = TcpStream::connect(upstream_address).await?;
    // The server runs with the default limits; the proxy must pass every call
    // and reply that they allow, such as a 1 MiB WRITE or READ reply sent as
    // one fragment just over 1 MiB.
    let server_limits = ServerLimits::production_defaults();
    let limits = RecordLimits {
        max_record_size: server_limits.max_rpc_record_size,
        max_fragment_size: server_limits.max_rpc_fragment_size,
        max_fragments: server_limits.max_fragments_per_record,
    };
    loop {
        let request = read_record(&mut client, limits).await?;
        let is_write = is_nfs_write(&request);
        write_record_limited(&mut upstream, &request, limits).await?;
        let reply = read_record(&mut upstream, limits).await?;
        if is_write && lose_reply.swap(false, Ordering::SeqCst) {
            // The backend completed and the reply cache was populated, but
            // the native client observes a lost TCP reply and must reconnect.
            return Ok(());
        }
        write_record_limited(&mut client, &reply, limits).await?;
    }
}

fn is_nfs_write(record: &[u8]) -> bool {
    let mut decoder = Decoder::new(record);
    decoder.read_u32().is_ok()
        && decoder.read_u32() == Ok(0)
        && decoder.read_u32() == Ok(2)
        && decoder.read_u32() == Ok(nfsembed::nfs3::types::PROGRAM)
        && decoder.read_u32() == Ok(nfsembed::nfs3::types::VERSION)
        && decoder.read_u32() == Ok(7)
}
