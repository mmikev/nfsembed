use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::{ServerError, ServerLimits};
use crate::portmap::mapping;
use crate::rpc::auth::{decode_principal, AUTH_NONE};
use crate::rpc::codec::Decoder;
use crate::rpc::message::{self, AcceptStatus, AuthStatus, VersionRange};
use crate::rpc::record::{read_record, write_record_limited, RecordLimits};

const PORTMAP_NULL: u32 = 0;
const PORTMAP_GETPORT: u32 = 3;
const MAX_PORTMAP_RECORD_SIZE: usize = 4096;
const MAX_PORTMAP_FRAGMENTS: usize = 16;
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

/// Caller-owned TCP and UDP sockets for a standalone portmapper v2 endpoint.
///
/// Windows Client for NFS discovers NFSv3 and MOUNTv3 through portmapper on
/// TCP and UDP port 111. Applications remain responsible for binding that
/// privileged port and pass both sockets to [`crate::NfsServer`].
pub struct PortmapperSockets {
    tcp: TcpListener,
    udp: UdpSocket,
    advertised_ports: Option<(u16, u16)>,
}

impl PortmapperSockets {
    pub fn new(tcp: TcpListener, udp: UdpSocket) -> Self {
        Self {
            tcp,
            udp,
            advertised_ports: None,
        }
    }

    /// Overrides the NFS and MOUNT ports returned by `GETPORT`.
    ///
    /// By default both mappings use the primary NFS listener's bound port.
    /// This override is useful when a transport proxy sits in front of the
    /// embedded server.
    pub fn advertised_ports(mut self, nfs_port: u16, mount_port: u16) -> Self {
        self.advertised_ports = Some((nfs_port, mount_port));
        self
    }

    pub(crate) fn prepare(self, primary_port: u16) -> Result<PreparedPortmapper, ServerError> {
        let tcp_addr = self.tcp.local_addr()?;
        let udp_addr = self.udp.local_addr()?;
        if tcp_addr != udp_addr {
            return Err(ServerError::InvalidConfiguration(
                "portmapper TCP and UDP sockets must use the same local address",
            ));
        }
        if tcp_addr.port() == 0 || primary_port == 0 {
            return Err(ServerError::InvalidConfiguration("listener ports must be bound and non-zero"));
        }
        let (nfs_port, mount_port) = self.advertised_ports.unwrap_or((primary_port, primary_port));
        if nfs_port == 0 || mount_port == 0 {
            return Err(ServerError::InvalidConfiguration("advertised NFS and MOUNT ports must be non-zero"));
        }
        Ok(PreparedPortmapper {
            tcp: self.tcp,
            udp: self.udp,
            local_addr: tcp_addr,
            nfs_port,
            mount_port,
        })
    }
}

pub(crate) struct PreparedPortmapper {
    tcp: TcpListener,
    udp: UdpSocket,
    pub local_addr: SocketAddr,
    nfs_port: u16,
    mount_port: u16,
}

pub(crate) async fn run_portmapper(
    portmapper: PreparedPortmapper,
    mut shutdown: watch::Receiver<bool>,
    connections: Arc<Semaphore>,
    limits: ServerLimits,
) -> Result<(), ServerError> {
    let PreparedPortmapper {
        tcp,
        udp,
        local_addr,
        nfs_port,
        mount_port,
    } = portmapper;
    tracing::debug!(address = %local_addr, nfs_port, mount_port, "portmapper started");
    let mut tasks = JoinSet::new();
    // Winsock reports WSAEMSGSIZE instead of returning a truncated length when
    // the receive buffer is too small. A maximum-size buffer lets every valid
    // UDP datagram be received and rejected as a packet-local protocol error.
    let mut datagram = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(error = %error, "portmapper connection task failed");
            }
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = tcp.accept() => {
                let (stream, client_addr) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(client = %client_addr, "portmapper connection rejected: limit reached");
                        continue;
                    }
                };
                let connection_shutdown = shutdown.clone();
                let connection_limits = limits.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_tcp_connection(
                        stream,
                        client_addr,
                        nfs_port,
                        mount_port,
                        connection_shutdown,
                        &connection_limits,
                    ).await {
                        tracing::debug!(client = %client_addr, error = %error, "portmapper connection closed with error");
                    }
                });
            }
            received = udp.recv_from(&mut datagram) => {
                let (length, client_addr) = match received {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tracing::debug!(error = %error, "portmapper UDP peer became unreachable");
                        continue;
                    },
                    Err(error) => return Err(error.into()),
                };
                if length > MAX_PORTMAP_RECORD_SIZE {
                    tracing::debug!(client = %client_addr, bytes = length, "oversized portmapper datagram dropped");
                    continue;
                }
                if let Some(reply) = dispatch_record(&datagram[..length], nfs_port, mount_port) {
                    match timeout(limits.request_timeout, udp.send_to(&reply, client_addr)).await {
                        Ok(Ok(_)) => {},
                        Ok(Err(error)) => tracing::debug!(client = %client_addr, error = %error, "portmapper UDP reply failed"),
                        Err(_) => tracing::debug!(client = %client_addr, "portmapper UDP reply timed out"),
                    }
                }
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "portmapper connection task failed");
                }
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    tracing::debug!(address = %local_addr, "portmapper stopped");
    Ok(())
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    nfs_port: u16,
    mount_port: u16,
    mut shutdown: watch::Receiver<bool>,
    limits: &ServerLimits,
) -> Result<(), ServerError> {
    stream.set_nodelay(true)?;
    let record_limits = RecordLimits {
        max_record_size: MAX_PORTMAP_RECORD_SIZE,
        max_fragment_size: MAX_PORTMAP_RECORD_SIZE,
        max_fragments: MAX_PORTMAP_FRAGMENTS,
    };
    loop {
        let record = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = timeout(limits.idle_connection_timeout, read_record(&mut stream, record_limits)) => {
                match result {
                    Err(_) => return Ok(()),
                    Ok(Err(crate::rpc::record::RecordError::Io(error)))
                        if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) =>
                    {
                        return Ok(())
                    },
                    Ok(Err(error)) => return Err(error.into()),
                    Ok(Ok(record)) => record,
                }
            }
        };
        let Some(reply) = dispatch_record(&record, nfs_port, mount_port) else {
            tracing::debug!(client = %client_addr, "malformed portmapper record dropped");
            continue;
        };
        match timeout(limits.request_timeout, write_record_limited(&mut stream, &reply, record_limits)).await {
            Ok(result) => result?,
            Err(_) => return Err(ServerError::RequestTimeout),
        }
    }
}

fn dispatch_record(record: &[u8], nfs_port: u16, mount_port: u16) -> Option<Vec<u8>> {
    let garbage = |xid| Some(message::accepted_reply(xid, AcceptStatus::GarbageArguments, &[]));
    let mut decoder = Decoder::new(record);
    let xid = decoder.read_u32().ok()?;
    let Ok(message_type) = decoder.read_u32() else {
        return garbage(xid);
    };
    if message_type != message::CALL {
        return None;
    }
    let Ok(rpc_version) = decoder.read_u32() else {
        return garbage(xid);
    };
    if rpc_version != message::RPC_VERSION {
        return Some(message::rpc_mismatch(xid));
    }
    let (Ok(program), Ok(version), Ok(procedure), Ok(credential_flavor)) =
        (decoder.read_u32(), decoder.read_u32(), decoder.read_u32(), decoder.read_u32())
    else {
        return garbage(xid);
    };
    let credential_valid = decoder
        .read_opaque_slice("RPC credential", 400)
        .is_ok_and(|credential| decode_principal(credential_flavor, credential).is_ok());
    if !credential_valid {
        return Some(message::auth_error(xid, AuthStatus::BadCredential));
    }
    let verifier_valid = decoder.read_u32().is_ok_and(|flavor| flavor == AUTH_NONE)
        && decoder.read_opaque_slice("RPC verifier", 400).is_ok_and(<[u8]>::is_empty);
    if !verifier_valid {
        return Some(message::auth_error(xid, AuthStatus::BadVerifier));
    }
    if program != crate::portmap::PROGRAM {
        return Some(message::accepted_reply(xid, AcceptStatus::ProgramUnavailable, &[]));
    }
    if version != crate::portmap::VERSION {
        return Some(message::program_mismatch(xid, VersionRange::exact(crate::portmap::VERSION)));
    }
    let args = &record[decoder.position()..];
    match procedure {
        PORTMAP_NULL if args.is_empty() => Some(message::accepted_reply(xid, AcceptStatus::Success, &[])),
        PORTMAP_GETPORT => {
            let Ok(request) = mapping::decode(args) else {
                return garbage(xid);
            };
            let port = crate::portmap::dispatch::get_port(&request, nfs_port, mount_port);
            Some(message::accepted_reply(xid, AcceptStatus::Success, &port.to_be_bytes()))
        },
        PORTMAP_NULL => garbage(xid),
        _ => Some(message::accepted_reply(xid, AcceptStatus::ProcedureUnavailable, &[])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::codec::Encoder;

    fn call(xid: u32, rpc_version: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        let mut request = Encoder::new();
        request.write_u32(xid);
        request.write_u32(message::CALL);
        request.write_u32(rpc_version);
        request.write_u32(program);
        request.write_u32(version);
        request.write_u32(procedure);
        request.write_u32(AUTH_NONE);
        request.write_u32(0);
        request.write_u32(AUTH_NONE);
        request.write_u32(0);
        request.write_fixed(args);
        request.into_bytes()
    }

    fn outcome(reply: &[u8]) -> (u32, u32, Vec<u8>) {
        let mut decoder = Decoder::new(reply);
        let xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), message::REPLY);
        let reply_status = decoder.read_u32().unwrap();
        if reply_status == message::MSG_ACCEPTED {
            assert_eq!(decoder.read_u32().unwrap(), AUTH_NONE);
            assert!(decoder.read_opaque("verifier", 400).unwrap().is_empty());
        }
        let status = decoder.read_u32().unwrap();
        (xid, status, reply[decoder.position()..].to_vec())
    }

    #[test]
    fn getport_and_rpc_error_shapes_are_exact() {
        let mut args = Encoder::new();
        args.write_u32(crate::nfs3::types::PROGRAM);
        args.write_u32(crate::nfs3::types::VERSION);
        args.write_u32(crate::portmap::IPPROTO_TCP);
        args.write_u32(0);
        let reply = dispatch_record(
            &call(7, 2, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_GETPORT, &args.into_bytes()),
            40_049,
            40_048,
        )
        .unwrap();
        let (xid, status, body) = outcome(&reply);
        assert_eq!((xid, status), (7, AcceptStatus::Success as u32));
        assert_eq!(u32::from_be_bytes(body.try_into().unwrap()), 40_049);

        let mismatch =
            dispatch_record(&call(8, 1, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_NULL, &[]), 1, 1)
                .unwrap();
        let mut decoder = Decoder::new(&mismatch);
        assert_eq!(decoder.read_u32().unwrap(), 8);
        assert_eq!(decoder.read_u32().unwrap(), message::REPLY);
        assert_eq!(decoder.read_u32().unwrap(), message::MSG_DENIED);
        assert_eq!(decoder.read_u32().unwrap(), message::RPC_MISMATCH);
        assert_eq!((decoder.read_u32().unwrap(), decoder.read_u32().unwrap()), (2, 2));
        decoder.finish().unwrap();

        let unavailable = dispatch_record(&call(9, 2, 999_999, 1, 0, &[]), 1, 1).unwrap();
        assert_eq!(outcome(&unavailable).1, AcceptStatus::ProgramUnavailable as u32);
        let bad_args =
            dispatch_record(&call(10, 2, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_GETPORT, &[]), 1, 1)
                .unwrap();
        assert_eq!(outcome(&bad_args).1, AcceptStatus::GarbageArguments as u32);
    }
}
