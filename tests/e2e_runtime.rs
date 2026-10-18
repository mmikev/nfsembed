mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::server::{AuthPolicy, NfsServer, PortmapperMode, PortmapperSockets, ServerLimits};
use nfsembed::vfs::ExportId;
use support::rpc::{
    assert_nfs_status, encode_empty_set_attributes, mount_root, nfs_args_directory, nfs_args_handle, nfs_args_setattr,
    nfs_payload, parse_reply, record_header, rpc_call, start_built_server, start_server, start_server_with, Auth,
    RpcClient, RpcOutcome, MOUNT_PROGRAM, MOUNT_VERSION, NFS_PROGRAM, NFS_VERSION, PORTMAP_PROGRAM, PORTMAP_VERSION,
};
use support::vfs::ConformanceVfs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

async fn lookup_handle(client: &mut RpcClient, root: &[u8], name: &[u8]) -> Vec<u8> {
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(root, name)).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    decoder.read_opaque("lookup handle", 64).unwrap()
}

fn portmap_arguments(program: u32, version: u32, protocol: u32) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_u32(program);
    arguments.write_u32(version);
    arguments.write_u32(protocol);
    arguments.write_u32(0);
    arguments.into_bytes()
}

#[test]
fn builder_rejects_every_unbounded_or_ambiguous_configuration() {
    let base = ServerLimits::production_defaults();
    let mut invalid_limits = Vec::new();
    let mut limits = base.clone();
    limits.max_connections = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_requests_per_connection = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_inflight_requests = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_connections = tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1);
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_requests_per_connection = tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1);
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_inflight_requests = tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1);
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_rpc_fragment_size = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_rpc_record_size = limits.max_rpc_fragment_size - 1;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_fragments_per_record = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_rpc_record_size = 303;
    limits.max_rpc_fragment_size = 303;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_rpc_record_size = 304;
    limits.max_rpc_fragment_size = 100;
    limits.max_fragments_per_record = 3;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.replay_cache_capacity = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.replay_cache_max_bytes = 0;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_buffered_request_bytes = limits.max_rpc_record_size - 1;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_buffered_reply_bytes = limits.max_rpc_record_size - 1;
    invalid_limits.push(limits);
    let mut limits = base.clone();
    limits.max_rpc_record_size = 1024;
    limits.max_rpc_fragment_size = 1024;
    limits.max_read_size = 100;
    limits.max_write_size = 494;
    limits.max_readdir_response_size = 100;
    invalid_limits.push(limits);
    let mut limits = base;
    limits.max_mounts = 0;
    invalid_limits.push(limits);

    for limits in invalid_limits {
        assert!(NfsServer::builder(ConformanceVfs::new(ExportId(1)))
            .limits(limits)
            .build()
            .is_err());
    }

    assert!(NfsServer::builder(ConformanceVfs::new(ExportId(1)))
        .export_name("bad/")
        .build()
        .is_err());
    assert!(NfsServer::builder(ConformanceVfs::new(ExportId(1)))
        .export_name("same")
        .add_export(ExportId(1), "other", ConformanceVfs::new(ExportId(1)))
        .build()
        .is_err());
    assert!(NfsServer::builder(ConformanceVfs::new(ExportId(1)))
        .export_name("same")
        .add_export(ExportId(2), "same", ConformanceVfs::new(ExportId(2)))
        .build()
        .is_err());
}

#[tokio::test]
async fn optional_portmapper_only_returns_supported_tcp_mappings() {
    let disabled_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let disabled = start_server(disabled_vfs).await;
    let mut client = RpcClient::connect(disabled.address).await;
    let (status, payload) = client.call(PORTMAP_PROGRAM, PORTMAP_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 1);
    assert!(payload.is_empty());
    disabled.shutdown().await;

    let enabled_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let enabled = start_server_with(
        enabled_vfs,
        ServerLimits::production_defaults(),
        AuthPolicy::AuthSys,
        PortmapperMode::Enabled,
    )
    .await;
    let mut client = RpcClient::connect(enabled.address).await;
    client.set_auth(Auth::None);
    let (status, payload) = client.call(PORTMAP_PROGRAM, PORTMAP_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());
    let (status, payload) = client.call(PORTMAP_PROGRAM, PORTMAP_VERSION, 0, &[0, 0, 0, 0]).await.accepted();
    assert_eq!(status, 4);
    assert!(payload.is_empty());

    for (program, version, protocol, expected) in [
        (NFS_PROGRAM, NFS_VERSION, 6, enabled.address.port() as u32),
        (MOUNT_PROGRAM, MOUNT_VERSION, 6, enabled.address.port() as u32),
        (NFS_PROGRAM, NFS_VERSION, 17, 0),
        (NFS_PROGRAM, 2, 6, 0),
        (999_999, 1, 6, 0),
    ] {
        let (status, payload) = client
            .call(PORTMAP_PROGRAM, PORTMAP_VERSION, 3, &portmap_arguments(program, version, protocol))
            .await
            .accepted();
        assert_eq!(status, 0);
        assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()), expected);
    }

    enabled.shutdown().await;
}

#[tokio::test]
async fn standalone_portmapper_serves_tcp_and_udp_and_shares_server_lifecycle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nfs_addr = listener.local_addr().unwrap();
    let portmapper_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portmapper_addr = portmapper_tcp.local_addr().unwrap();
    let portmapper_udp = UdpSocket::bind(portmapper_addr).await.unwrap();
    let server = NfsServer::builder(ConformanceVfs::new(ExportId(1))).build().unwrap();
    let handle = server
        .start_with_portmapper(
            listener,
            PortmapperSockets::new(portmapper_tcp, portmapper_udp).advertised_ports(40_049, 40_048),
        )
        .await
        .unwrap();
    assert_eq!(handle.portmapper_addr(), Some(portmapper_addr));

    let mut tcp = RpcClient::connect(portmapper_addr).await;
    tcp.set_auth(Auth::None);
    for (program, version, protocol, expected) in [
        (NFS_PROGRAM, NFS_VERSION, 6, 40_049),
        (MOUNT_PROGRAM, MOUNT_VERSION, 6, 40_048),
        (NFS_PROGRAM, NFS_VERSION, 17, 0),
        (NFS_PROGRAM, 2, 6, 0),
    ] {
        let (status, payload) = tcp
            .call(PORTMAP_PROGRAM, PORTMAP_VERSION, 3, &portmap_arguments(program, version, protocol))
            .await
            .accepted();
        assert_eq!(status, 0);
        assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()), expected);
    }

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&vec![0xa5; 8192], portmapper_addr).await.unwrap();
    let abandoned = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let abandoned_request = rpc_call(
        70,
        2,
        PORTMAP_PROGRAM,
        PORTMAP_VERSION,
        3,
        &portmap_arguments(NFS_PROGRAM, NFS_VERSION, 6),
        &Auth::None,
    );
    abandoned.send_to(&abandoned_request, portmapper_addr).await.unwrap();
    drop(abandoned);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let request = rpc_call(
        71,
        2,
        PORTMAP_PROGRAM,
        PORTMAP_VERSION,
        3,
        &portmap_arguments(NFS_PROGRAM, NFS_VERSION, 6),
        &Auth::None,
    );
    udp.send_to(&request, portmapper_addr).await.unwrap();
    let mut reply = [0u8; 4096];
    let (length, source) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, portmapper_addr);
    let RpcOutcome::Accepted { xid, status, payload } = parse_reply(&reply[..length]) else {
        panic!("portmapper returned a denied UDP reply");
    };
    assert_eq!((xid, status), (71, 0));
    assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()), 40_049);

    // Neither malformed traffic nor an unreachable UDP peer may terminate the
    // shared NFS lifecycle.
    let mut nfs = RpcClient::connect(nfs_addr).await;
    assert!(!mount_root(&mut nfs, b"/").await.is_empty());
    handle.shutdown().await.unwrap();
    handle.wait().await.unwrap();

    TcpListener::bind(portmapper_addr).await.unwrap();
    UdpSocket::bind(portmapper_addr).await.unwrap();
}

#[tokio::test]
async fn standalone_portmapper_rejects_mismatched_socket_addresses() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portmapper_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut same_port_sockets = Vec::new();
    let portmapper_udp = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if socket.local_addr().unwrap() != portmapper_tcp.local_addr().unwrap() {
            break socket;
        }
        // Keep the colliding UDP port occupied so the next ephemeral bind
        // must select another numeric port.
        same_port_sockets.push(socket);
    };
    assert_ne!(portmapper_tcp.local_addr().unwrap(), portmapper_udp.local_addr().unwrap());
    let server = NfsServer::builder(ConformanceVfs::new(ExportId(1))).build().unwrap();
    assert!(server
        .start_with_portmapper(listener, PortmapperSockets::new(portmapper_tcp, portmapper_udp))
        .await
        .is_err());
}

#[tokio::test]
async fn restart_of_same_server_configuration_rotates_handles_and_write_verifier() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = NfsServer::builder_arc(vfs).build().unwrap();

    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_handle = server.start(first_listener).await.unwrap();
    let mut first_client = RpcClient::connect(first_handle.mount_info().server_addr).await;
    let first_root = mount_root(&mut first_client, b"/").await;
    let first_file = lookup_handle(&mut first_client, &first_root, b"file").await;
    let first_verifier = write_and_decode_verifier(&mut first_client, &first_file, 900).await;
    first_handle.shutdown().await.unwrap();
    first_handle.wait().await.unwrap();

    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_handle = server.start(second_listener).await.unwrap();
    let mut second_client = RpcClient::connect(second_handle.mount_info().server_addr).await;
    let stale = nfs_payload(
        second_client
            .call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&first_root))
            .await,
    );
    assert_eq!(u32::from_be_bytes(stale[..4].try_into().unwrap()), 70);
    let second_root = mount_root(&mut second_client, b"/").await;
    let second_file = lookup_handle(&mut second_client, &second_root, b"file").await;
    let second_verifier = write_and_decode_verifier(&mut second_client, &second_file, 901).await;
    assert_ne!(first_root, second_root);
    assert_ne!(first_verifier, second_verifier);
    second_handle.shutdown().await.unwrap();
    second_handle.wait().await.unwrap();
}

#[tokio::test]
async fn auth_sys_stamp_changes_do_not_bypass_completed_replay() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let baseline = vfs.call_count("setattr");
    let first = client
        .call_with_xid(910, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;

    let mut credential = support::rpc::auth_sys_body();
    credential[..4].copy_from_slice(&0x8765_4321u32.to_be_bytes());
    client.set_auth(Auth::Raw {
        flavor: 1,
        body: credential,
    });
    let replay = client
        .call_with_xid(910, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(first, replay);
    assert_eq!(vfs.call_count("setattr"), baseline + 1);
    server.shutdown().await;
}

#[tokio::test]
async fn idempotent_retransmissions_are_executed_again_instead_of_cached() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    vfs.set_data(vec![0x5a; 4096]);
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;
    let mut read = Encoder::new();
    read.write_opaque(&file).unwrap();
    read.write_u64(0);
    read.write_u32(4096);
    let read = read.into_bytes();

    for (procedure, operation, arguments) in [
        (1, "getattr", nfs_args_handle(&root)),
        (3, "lookup", nfs_args_directory(&root, b"file")),
        (6, "read", read),
    ] {
        let baseline = vfs.call_count(operation);
        let first = client
            .call_with_xid(700 + procedure, NFS_PROGRAM, NFS_VERSION, procedure, &arguments)
            .await;
        let retransmitted = client
            .call_with_xid(700 + procedure, NFS_PROGRAM, NFS_VERSION, procedure, &arguments)
            .await;
        assert_eq!(first, retransmitted, "{operation} results differ");
        assert_eq!(vfs.call_count(operation), baseline + 2, "{operation} was not executed again");
    }

    // A mutation with the same XID is still answered from the cache.
    let baseline = vfs.call_count("setattr");
    for _ in 0..2 {
        let _ = client
            .call_with_xid(710, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
            .await;
    }
    assert_eq!(vfs.call_count("setattr"), baseline + 1);
    server.shutdown().await;
}

#[tokio::test]
async fn timed_out_mutation_is_cancelled_and_same_xid_can_execute_again() {
    let mut limits = ServerLimits::production_defaults();
    limits.request_timeout = Duration::from_millis(30);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;
    vfs.delay_after("write", Duration::from_millis(80));
    let arguments = write_arguments(&file, b"once");

    assert!(matches!(
        client.call_with_xid(920, NFS_PROGRAM, NFS_VERSION, 7, &arguments).await,
        RpcOutcome::Accepted { status: 5, .. }
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(vfs.active_delays(), 0);
    vfs.clear_delay_after("write");
    let replay = client.call_with_xid(920, NFS_PROGRAM, NFS_VERSION, 7, &arguments).await;
    assert_eq!(u32::from_be_bytes(nfs_payload(replay)[..4].try_into().unwrap()), 0);
    assert_eq!(vfs.call_count("write"), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn never_returning_vfs_calls_release_the_global_execution_permit() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_inflight_requests = 1;
    limits.request_timeout = Duration::from_millis(30);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    vfs.delay("getattr", Duration::from_secs(60));
    let baseline = vfs.call_count("getattr");
    let started = Instant::now();

    for xid in [921, 922] {
        assert!(matches!(
            client
                .call_with_xid(xid, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
                .await,
            RpcOutcome::Accepted { status: 5, .. }
        ));
    }
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(vfs.call_count("getattr"), baseline + 2);
    assert_eq!(vfs.active_delays(), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn wait_is_cancellation_safe_and_concurrent_waiters_observe_termination() {
    let mut limits = ServerLimits::production_defaults();
    limits.request_timeout = Duration::from_secs(1);
    limits.graceful_shutdown_timeout = Duration::from_secs(1);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let running = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(running.address).await;
    let root = mount_root(&mut client, b"/").await;
    vfs.delay("getattr", Duration::from_millis(120));
    client
        .send_without_reading(930, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
        .await;
    while vfs.call_count("getattr") < 2 {
        tokio::task::yield_now().await;
    }

    let handle = Arc::new(running.handle);
    handle.shutdown().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(20), handle.wait()).await.is_err());
    let started = Instant::now();
    let (first, second) = tokio::join!(handle.wait(), handle.wait());
    first.unwrap();
    second.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(70));
}

#[tokio::test]
async fn oversized_and_overfragmented_outbound_replies_become_system_errors() {
    for (record_size, fragment_size, fragments) in [(640, 640, 8), (1024, 256, 3)] {
        let mut limits = ServerLimits::production_defaults();
        limits.max_rpc_record_size = record_size;
        limits.max_rpc_fragment_size = fragment_size;
        limits.max_fragments_per_record = fragments;
        limits.max_read_size = 100;
        limits.max_write_size = 100;
        limits.max_readdir_response_size = 600;
        let mut builder = NfsServer::builder(ConformanceVfs::new(ExportId(1))).limits(limits);
        for id in 2..=24 {
            builder = builder.add_export(
                ExportId(id),
                format!("export-{id}-with-a-long-name"),
                ConformanceVfs::new(ExportId(id)),
            );
        }
        let running = start_built_server(builder.build().unwrap()).await;
        let mut client = RpcClient::connect(running.address).await;
        for id in 2..=20 {
            let mut path = Encoder::new();
            path.write_opaque(format!("/export-{id}-with-a-long-name").as_bytes()).unwrap();
            assert_eq!(
                u32::from_be_bytes(
                    nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &path.into_bytes()).await)[..4]
                        .try_into()
                        .unwrap()
                ),
                0
            );
        }
        assert!(matches!(
            client.call(MOUNT_PROGRAM, MOUNT_VERSION, 2, &[]).await,
            RpcOutcome::Accepted { status: 5, .. }
        ));
        assert!(matches!(
            client.call(MOUNT_PROGRAM, MOUNT_VERSION, 5, &[]).await,
            RpcOutcome::Accepted { status: 5, .. }
        ));
        running.shutdown().await;
    }
}

#[tokio::test]
async fn configuration_rejects_a_transport_that_cannot_carry_mutation_results() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_rpc_record_size = 128;
    limits.max_rpc_fragment_size = 128;
    assert!(NfsServer::builder(ConformanceVfs::new(ExportId(1)))
        .limits(limits)
        .build()
        .is_err());
}

#[tokio::test]
async fn fsinfo_transfer_values_fit_the_effective_transport_capacity() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_rpc_record_size = 1024;
    limits.max_rpc_fragment_size = 1024;
    limits.max_read_size = 800;
    limits.max_write_size = 400;
    limits.max_readdir_response_size = 900;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs, limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 19, &nfs_args_handle(&root)).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(support::rpc::decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), 800);
    assert_eq!(decoder.read_u32().unwrap(), 800);
    assert_eq!(decoder.read_u32().unwrap(), 800);
    assert_eq!(decoder.read_u32().unwrap(), 400);
    assert_eq!(decoder.read_u32().unwrap(), 400);
    assert_eq!(decoder.read_u32().unwrap(), 400);
    assert_eq!(decoder.read_u32().unwrap(), 900);
    server.shutdown().await;
}

#[tokio::test]
async fn dropping_handle_aborts_tracked_executions_without_a_reference_cycle() {
    let mut limits = ServerLimits::production_defaults();
    limits.request_timeout = Duration::from_secs(60);
    limits.graceful_shutdown_timeout = Duration::from_secs(60);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let running = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(running.address).await;
    let root = mount_root(&mut client, b"/").await;
    vfs.delay("getattr", Duration::from_secs(60));
    client
        .send_without_reading(950, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
        .await;
    while vfs.active_delays() == 0 {
        tokio::task::yield_now().await;
    }

    drop(running.handle);
    tokio::time::timeout(Duration::from_secs(1), async {
        while vfs.active_delays() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tracked VFS execution leaked after ServerHandle drop");
}

#[tokio::test]
async fn mount_advertises_every_accepted_auth_flavor() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let running = start_server_with(
        vfs,
        ServerLimits::production_defaults(),
        AuthPolicy::AuthSysOrAnonymous,
        PortmapperMode::Disabled,
    )
    .await;
    let mut client = RpcClient::connect(running.address).await;
    let mut path = Encoder::new();
    path.write_opaque(b"/").unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &path.into_bytes()).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let _handle = decoder.read_opaque("mount handle", 64).unwrap();
    assert_eq!(decoder.read_u32().unwrap(), 2);
    assert_eq!(decoder.read_u32().unwrap(), 1);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    decoder.finish().unwrap();
    running.shutdown().await;
}

fn write_arguments(file: &[u8], data: &[u8]) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_opaque(file).unwrap();
    arguments.write_u64(0);
    arguments.write_u32(data.len() as u32);
    arguments.write_u32(0);
    arguments.write_opaque(data).unwrap();
    arguments.into_bytes()
}

async fn write_and_decode_verifier(client: &mut RpcClient, file: &[u8], xid: u32) -> [u8; 8] {
    let payload = nfs_payload(
        client
            .call_with_xid(xid, NFS_PROGRAM, NFS_VERSION, 7, &write_arguments(file, b"data"))
            .await,
    );
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let _ = support::rpc::decode_wcc(&mut decoder);
    assert_eq!(decoder.read_u32().unwrap(), 4);
    let _committed = decoder.read_u32().unwrap();
    decoder.read_fixed().unwrap()
}

#[tokio::test]
async fn mount_matching_preserves_boundaries_lengths_types_and_backend_errors() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = NfsServer::builder_arc(vfs.clone()).export_name("data").build().unwrap();
    let running = start_built_server(server).await;
    let mut client = RpcClient::connect(running.address).await;
    let _root = mount_root(&mut client, b"/data").await;

    for path in [b"/database".as_slice(), b"/data ".as_slice()] {
        let mut arguments = Encoder::new();
        arguments.write_opaque(path).unwrap();
        let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &arguments.into_bytes()).await);
        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 2);
    }

    let raw_component = [b'/', b'd', b'a', b't', b'a', b'/', 0xff];
    let mut raw_path = Encoder::new();
    raw_path.write_opaque(&raw_component).unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &raw_path.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 2);
    assert_eq!(vfs.last_lookup_name(), Some(vec![0xff]));

    let mut file_path = Encoder::new();
    file_path.write_opaque(b"/data/file").unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &file_path.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 20);

    vfs.fail("lookup", nfsembed::vfs::NfsError::Access);
    let mut denied_path = Encoder::new();
    denied_path.write_opaque(b"/data/file").unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &denied_path.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 13);
    vfs.clear_failure("lookup");

    vfs.fail("lookup", nfsembed::vfs::NfsError::NameTooLong);
    let mut long_name = Encoder::new();
    long_name.write_opaque(b"/data/file").unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &long_name.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 63);
    vfs.clear_failure("lookup");

    let mut overlong_component = b"/data/".to_vec();
    overlong_component.extend(std::iter::repeat_n(b'x', 256));
    let mut overlong_name = Encoder::new();
    overlong_name.write_opaque(&overlong_component).unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &overlong_name.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 63);

    let mut oversized = Encoder::new();
    oversized.write_opaque(&vec![b'x'; 1025]).unwrap();
    assert!(matches!(
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &oversized.into_bytes()).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));

    running.shutdown().await;
}

#[tokio::test]
async fn completed_inflight_lost_reply_and_xid_reuse_paths_are_end_to_end_correct() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut first = RpcClient::connect(server.address).await;
    let root = mount_root(&mut first, b"/").await;
    let file = lookup_handle(&mut first, &root, b"file").await;

    let baseline = vfs.call_count("setattr");
    let reply1 = first
        .call_with_xid(500, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    let reply2 = first
        .call_with_xid(500, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(reply1, reply2);
    assert_eq!(vfs.call_count("setattr"), baseline + 1);

    let _reused = first
        .call_with_xid(500, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&file))
        .await;
    assert_eq!(vfs.call_count("setattr"), baseline + 2, "different arguments must be XID reuse");
    let _reused_again = first
        .call_with_xid(500, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(vfs.call_count("setattr"), baseline + 3, "A-B-A XID reuse replayed stale A");

    let lost_baseline = vfs.call_count("setattr");
    first
        .send_without_reading(501, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    drop(first);
    for _ in 0..50 {
        if vfs.call_count("setattr") == lost_baseline + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(vfs.call_count("setattr"), lost_baseline + 1);
    let mut reconnected = RpcClient::connect(server.address).await;
    let replayed = reconnected
        .call_with_xid(501, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_nfs_status(replayed, 0);
    assert_eq!(vfs.call_count("setattr"), lost_baseline + 1, "lost reply was not replayed");

    let mut other = RpcClient::connect(server.address).await;
    vfs.delay("setattr", Duration::from_millis(100));
    vfs.reset_concurrency_observation();
    let inflight_baseline = vfs.call_count("setattr");
    let args1 = nfs_args_setattr(&root);
    let args2 = args1.clone();
    let (first_reply, second_reply) = tokio::join!(
        reconnected.call_with_xid(502, NFS_PROGRAM, NFS_VERSION, 2, &args1),
        other.call_with_xid(502, NFS_PROGRAM, NFS_VERSION, 2, &args2),
    );
    assert_eq!(first_reply, second_reply);
    assert_eq!(vfs.call_count("setattr"), inflight_baseline + 1);

    server.shutdown().await;
}

#[tokio::test]
async fn replay_ttl_and_capacity_bound_completed_entries() {
    let mut limits = ServerLimits::production_defaults();
    limits.replay_cache_ttl = Duration::from_millis(40);
    limits.replay_cache_capacity = 1;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let baseline = vfs.call_count("setattr");

    let _ = client
        .call_with_xid(550, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    let _ = client
        .call_with_xid(551, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    let _ = client
        .call_with_xid(550, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(vfs.call_count("setattr"), baseline + 3, "capacity did not evict the oldest reply");

    let _ = client
        .call_with_xid(550, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(vfs.call_count("setattr"), baseline + 3, "the retained reply was not replayed");
    tokio::time::sleep(Duration::from_millis(60)).await;
    let _ = client
        .call_with_xid(550, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
        .await;
    assert_eq!(vfs.call_count("setattr"), baseline + 4, "TTL did not expire the cached reply");

    server.shutdown().await;
}

#[tokio::test]
async fn replay_byte_budget_skips_replies_that_cannot_fit() {
    let mut limits = ServerLimits::production_defaults();
    limits.replay_cache_max_bytes = 32;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let baseline = vfs.call_count("setattr");
    for _ in 0..2 {
        let payload = nfs_payload(
            client
                .call_with_xid(555, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&root))
                .await,
        );
        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 0);
    }
    assert_eq!(vfs.call_count("setattr"), baseline + 2);
    server.shutdown().await;
}

#[tokio::test]
async fn connection_and_global_request_limits_backpressure_without_affecting_host() {
    let mut connection_limits = ServerLimits::production_defaults();
    connection_limits.max_connections = 1;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs, connection_limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut first = RpcClient::connect(server.address).await;
    let (status, _) = first.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    let mut rejected = TcpStream::connect(server.address).await.unwrap();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .unwrap();
    assert_eq!(read.unwrap(), 0);
    let (status, _) = first.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    drop(first);
    server.shutdown().await;

    let mut request_limits = ServerLimits::production_defaults();
    request_limits.max_inflight_requests = 1;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), request_limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut first = RpcClient::connect(server.address).await;
    let mut second = RpcClient::connect(server.address).await;
    let root = mount_root(&mut first, b"/").await;
    let second_root = mount_root(&mut second, b"/").await;
    vfs.delay("getattr", Duration::from_millis(100));
    vfs.reset_concurrency_observation();
    let first_args = nfs_args_handle(&root);
    let second_args = nfs_args_handle(&second_root);
    let started = Instant::now();
    let (first_reply, second_reply) = tokio::join!(
        first.call_with_xid(560, NFS_PROGRAM, NFS_VERSION, 1, &first_args),
        second.call_with_xid(561, NFS_PROGRAM, NFS_VERSION, 1, &second_args),
    );
    assert!(matches!(first_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert!(matches!(second_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert!(started.elapsed() >= Duration::from_millis(180), "global request limit did not serialize work");
    assert_eq!(vfs.max_concurrency_observed(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn aggregate_byte_budgets_bound_large_records_across_connections() {
    const RECORD_SIZE: usize = 128 * 1024;
    const WRITE_SIZE: usize = 64 * 1024;
    let mut limits = ServerLimits::production_defaults();
    limits.max_rpc_record_size = RECORD_SIZE;
    limits.max_rpc_fragment_size = RECORD_SIZE;
    limits.max_buffered_request_bytes = RECORD_SIZE;
    limits.max_buffered_reply_bytes = 2 * RECORD_SIZE;
    limits.max_inflight_requests = 2;
    limits.max_write_size = WRITE_SIZE as u32;
    limits.max_read_size = WRITE_SIZE as u32;
    limits.max_readdir_response_size = WRITE_SIZE as u32;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut first = RpcClient::connect(server.address).await;
    let mut second = RpcClient::connect(server.address).await;
    let first_root = mount_root(&mut first, b"/").await;
    let second_root = mount_root(&mut second, b"/").await;
    let first_file = lookup_handle(&mut first, &first_root, b"file").await;
    let second_file = lookup_handle(&mut second, &second_root, b"file").await;
    vfs.delay("write", Duration::from_millis(75));
    vfs.reset_concurrency_observation();
    let data = vec![0x5a; WRITE_SIZE];
    let first_args = write_arguments(&first_file, &data);
    let second_args = write_arguments(&second_file, &data);
    let started = Instant::now();

    let (first_reply, second_reply) = tokio::join!(
        first.call_with_xid(580, NFS_PROGRAM, NFS_VERSION, 7, &first_args),
        second.call_with_xid(581, NFS_PROGRAM, NFS_VERSION, 7, &second_args),
    );
    assert!(matches!(first_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert!(matches!(second_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert!(started.elapsed() >= Duration::from_millis(130));
    assert_eq!(vfs.max_concurrency_observed(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn small_requests_reserve_only_the_buffer_bytes_they_can_use() {
    // Byte budgets that fit exactly one maximum-size record. Reserving the
    // full record size for every call would serialize these GETATTRs; sizing
    // reservations to the actual request and its bounded reply lets them run
    // concurrently.
    const CLIENTS: usize = 8;
    let mut limits = ServerLimits::production_defaults();
    limits.max_buffered_request_bytes = limits.max_rpc_record_size;
    limits.max_buffered_reply_bytes = limits.max_rpc_record_size;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut clients = Vec::new();
    for _ in 0..CLIENTS {
        clients.push(RpcClient::connect(server.address).await);
    }
    let root = mount_root(&mut clients[0], b"/").await;
    vfs.delay("getattr", Duration::from_millis(100));
    vfs.reset_concurrency_observation();
    let started = Instant::now();
    let replies: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(index, mut client)| {
            let arguments = nfs_args_handle(&root);
            tokio::spawn(async move {
                client
                    .call_with_xid(800 + index as u32, NFS_PROGRAM, NFS_VERSION, 1, &arguments)
                    .await
            })
        })
        .collect();
    for reply in replies {
        assert!(matches!(reply.await.unwrap(), RpcOutcome::Accepted { status: 0, .. }));
    }
    assert_eq!(vfs.max_concurrency_observed(), CLIENTS);
    assert!(started.elapsed() < Duration::from_millis(100 * CLIENTS as u64 / 2));
    server.shutdown().await;
}

#[tokio::test]
async fn slow_reader_is_disconnected_and_releases_its_connection_slot() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_connections = 1;
    limits.max_requests_per_connection = 4;
    limits.max_inflight_requests = 4;
    limits.max_buffered_reply_bytes = limits.max_rpc_record_size;
    limits.request_timeout = Duration::from_millis(50);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    vfs.set_data(vec![0x7a; 1024 * 1024]);
    let server = start_server_with(vfs, limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut slow = RpcClient::connect(server.address).await;
    let root = mount_root(&mut slow, b"/").await;
    let file = lookup_handle(&mut slow, &root, b"file").await;
    let mut read = Encoder::new();
    read.write_opaque(&file).unwrap();
    read.write_u64(0);
    read.write_u32(1024 * 1024);
    let read = read.into_bytes();
    for xid in 590..606 {
        slow.send_without_reading(xid, NFS_PROGRAM, NFS_VERSION, 6, &read).await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut replacement = RpcClient::connect(server.address).await;
    let (status, payload) = replacement.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());
    drop(slow);
    server.shutdown().await;
}

#[tokio::test]
async fn per_connection_request_limit_controls_pipelined_concurrency() {
    for (limit, expected_concurrency) in [(1, 1), (2, 2)] {
        let mut limits = ServerLimits::production_defaults();
        limits.max_requests_per_connection = limit;
        limits.max_inflight_requests = 2;
        let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
        let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
        let mut client = RpcClient::connect(server.address).await;
        let root = mount_root(&mut client, b"/").await;
        let file = lookup_handle(&mut client, &root, b"file").await;
        vfs.delay("getattr", Duration::from_millis(75));
        vfs.reset_concurrency_observation();

        client
            .send_without_reading(565, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
            .await;
        client
            .send_without_reading(566, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&file))
            .await;
        assert!(matches!(client.read_reply().await, RpcOutcome::Accepted { status: 0, .. }));
        assert!(matches!(client.read_reply().await, RpcOutcome::Accepted { status: 0, .. }));
        assert_eq!(vfs.max_concurrency_observed(), expected_concurrency);

        server.shutdown().await;
    }
}

#[tokio::test]
async fn concurrent_mutations_run_within_limit_and_shutdown_deadline_cancels_slow_request() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_inflight_requests = 2;
    limits.graceful_shutdown_timeout = Duration::from_millis(100);
    limits.request_timeout = Duration::from_secs(10);
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut first = RpcClient::connect(server.address).await;
    let mut second = RpcClient::connect(server.address).await;
    let root = mount_root(&mut first, b"/").await;
    let second_root = mount_root(&mut second, b"/").await;
    let file = lookup_handle(&mut first, &root, b"file").await;
    let second_file = lookup_handle(&mut second, &second_root, b"file").await;
    vfs.delay("write", Duration::from_millis(100));
    vfs.reset_concurrency_observation();

    let write_args = |handle: &[u8], data: &[u8]| {
        let mut arguments = Encoder::new();
        arguments.write_opaque(handle).unwrap();
        arguments.write_u64(0);
        arguments.write_u32(data.len() as u32);
        arguments.write_u32(0);
        arguments.write_opaque(data).unwrap();
        arguments.into_bytes()
    };
    let first_write = write_args(&file, b"one");
    let second_write = write_args(&second_file, b"two");
    let (first_reply, second_reply) = tokio::join!(
        first.call_with_xid(570, NFS_PROGRAM, NFS_VERSION, 7, &first_write),
        second.call_with_xid(571, NFS_PROGRAM, NFS_VERSION, 7, &second_write),
    );
    assert!(matches!(first_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert!(matches!(second_reply, RpcOutcome::Accepted { status: 0, .. }));
    assert_eq!(vfs.max_concurrency_observed(), 2);
    assert_eq!(vfs.call_count("write"), 2);

    vfs.delay("getattr", Duration::from_secs(5));
    let getattr_baseline = vfs.call_count("getattr");
    first
        .send_without_reading(572, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
        .await;
    for _ in 0..50 {
        if vfs.call_count("getattr") > getattr_baseline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let shutdown_started = Instant::now();
    server.handle.shutdown().await.unwrap();
    server.handle.wait().await.unwrap();
    assert!(shutdown_started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn handles_are_scoped_to_server_export_and_integrity_tag() {
    let first_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let second_vfs = Arc::new(ConformanceVfs::new(ExportId(2)));
    let server = NfsServer::builder_arc(first_vfs.clone())
        .export_name("first")
        .add_export_arc(ExportId(2), "second", second_vfs.clone())
        .build()
        .unwrap();
    let running = start_built_server(server).await;
    assert_eq!(running.handle.mount_infos().len(), 2);
    let mut client = RpcClient::connect(running.address).await;
    let first_root = mount_root(&mut client, b"/first").await;
    let second_root = mount_root(&mut client, b"/second").await;
    assert_ne!(first_root, second_root);

    // Replay entries are scoped by export: the same XID addresses two
    // independent mutations, and only the exact retransmission is replayed.
    let baseline_first = first_vfs.call_count("setattr");
    let baseline_second = second_vfs.call_count("setattr");
    let _ = client
        .call_with_xid(600, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&first_root))
        .await;
    let _ = client
        .call_with_xid(600, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&second_root))
        .await;
    let _ = client
        .call_with_xid(600, NFS_PROGRAM, NFS_VERSION, 2, &nfs_args_setattr(&second_root))
        .await;
    assert_eq!(first_vfs.call_count("setattr"), baseline_first + 1);
    assert_eq!(second_vfs.call_count("setattr"), baseline_second + 1);

    let mut cross_export = Encoder::new();
    cross_export.write_opaque(&first_root).unwrap();
    cross_export.write_opaque(b"from").unwrap();
    cross_export.write_opaque(&second_root).unwrap();
    cross_export.write_opaque(b"to").unwrap();
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 14, &cross_export.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 10001);
    assert_eq!(first_vfs.call_count("rename"), 0);
    assert_eq!(second_vfs.call_count("rename"), 0);

    let mut forged = first_root.clone();
    forged[15] ^= 0x40;
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&forged)).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 10001);

    drop(client);
    running.shutdown().await;

    let replacement_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let replacement = start_server(replacement_vfs).await;
    let mut replacement_client = RpcClient::connect(replacement.address).await;
    let payload = nfs_payload(
        replacement_client
            .call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&first_root))
            .await,
    );
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 70);
    replacement.shutdown().await;
}

#[tokio::test]
async fn transfer_directory_timeout_idle_and_mount_limits_are_enforced() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_read_size = 4;
    limits.max_write_size = 4;
    limits.max_readdir_response_size = 160;
    limits.request_timeout = Duration::from_millis(50);
    limits.idle_connection_timeout = Duration::from_millis(80);
    limits.max_mounts = 1;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mut repeated_mount = Encoder::new();
    repeated_mount.write_opaque(b"/").unwrap();
    assert_eq!(
        u32::from_be_bytes(
            nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &repeated_mount.into_bytes()).await)[..4]
                .try_into()
                .unwrap()
        ),
        0,
        "an existing mount must remain idempotent when the table is full"
    );

    let mut read = Encoder::new();
    read.write_opaque(&file).unwrap();
    read.write_u64(0);
    read.write_u32(100);
    let payload = assert_nfs_status(client.call(NFS_PROGRAM, NFS_VERSION, 6, &read.into_bytes()).await, 0);
    assert_eq!(vfs.last_read(), Some((0, 4)));
    assert!(payload.len() <= 112);

    let mut oversized_write = Encoder::new();
    oversized_write.write_opaque(&file).unwrap();
    oversized_write.write_u64(0);
    oversized_write.write_u32(5);
    oversized_write.write_u32(0);
    oversized_write.write_opaque(b"12345").unwrap();
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &oversized_write.into_bytes()).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let _ = support::rpc::decode_wcc(&mut decoder);
    assert_eq!(decoder.read_u32().unwrap(), 4);
    assert_eq!(vfs.call_count("write"), 1);
    assert_eq!(vfs.last_write().unwrap().data, b"1234");

    let mut readdir = Encoder::new();
    readdir.write_opaque(&root).unwrap();
    readdir.write_u64(0);
    readdir.write_fixed(&[0; 8]);
    readdir.write_u32(4096);
    let payload = assert_nfs_status(client.call(NFS_PROGRAM, NFS_VERSION, 16, &readdir.into_bytes()).await, 0);
    assert!(payload.len() - 4 <= 160);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let _ = support::rpc::decode_post_attributes(&mut decoder);
    let _verifier = decoder.read_fixed::<8>().unwrap();
    let mut count = 0;
    while decoder.read_bool().unwrap() {
        let _ = decoder.read_u64().unwrap();
        let _ = decoder.read_opaque("entry", 255).unwrap();
        let _ = decoder.read_u64().unwrap();
        count += 1;
    }
    assert!(!decoder.read_bool().unwrap(), "truncated directory page incorrectly reported EOF");
    assert_eq!(count, 2);

    let mut second_mount = Encoder::new();
    second_mount.write_opaque(b"/dir").unwrap();
    let payload = nfs_payload(client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &second_mount.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 5);

    vfs.delay("getattr", Duration::from_millis(200));
    let timeout_reply = client
        .call_with_xid(700, NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
        .await;
    assert!(matches!(timeout_reply, RpcOutcome::Accepted { status: 5, .. }));

    let mut idle = TcpStream::connect(server.address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut byte = [0];
    assert_eq!(idle.read(&mut byte).await.unwrap(), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn large_read_and_write_records_cross_transport_without_truncation() {
    const TRANSFER_SIZE: usize = 256 * 1024;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let read_data = (0..TRANSFER_SIZE).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    vfs.set_data(read_data.clone());
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mut read = Encoder::new();
    read.write_opaque(&file).unwrap();
    read.write_u64(0);
    read.write_u32(TRANSFER_SIZE as u32);
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 6, &read.into_bytes()).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(support::rpc::decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), TRANSFER_SIZE as u32);
    assert!(decoder.read_bool().unwrap());
    assert_eq!(decoder.read_opaque("large read", TRANSFER_SIZE).unwrap(), read_data);
    decoder.finish().unwrap();

    let write_data = vec![0x5a; TRANSFER_SIZE];
    let mut write = Encoder::new();
    write.write_opaque(&file).unwrap();
    write.write_u64(4096);
    write.write_u32(TRANSFER_SIZE as u32);
    write.write_u32(2);
    write.write_opaque(&write_data).unwrap();
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &write.into_bytes()).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let _ = support::rpc::decode_wcc(&mut decoder);
    assert_eq!(decoder.read_u32().unwrap(), TRANSFER_SIZE as u32);
    assert_eq!(decoder.read_u32().unwrap(), 2);
    let _write_verifier = decoder.read_fixed::<8>().unwrap();
    decoder.finish().unwrap();
    let observed = vfs.last_write().unwrap();
    assert_eq!(observed.offset, 4096);
    assert_eq!(observed.requested, nfsembed::vfs::WriteStability::FileSync);
    assert_eq!(observed.data, write_data);

    server.shutdown().await;
}

#[tokio::test]
async fn hostile_fragments_close_only_their_connection_and_server_stays_healthy() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_rpc_fragment_size = 256;
    limits.max_rpc_record_size = 640;
    limits.max_fragments_per_record = 3;
    limits.max_read_size = 100;
    limits.max_write_size = 100;
    limits.max_readdir_response_size = 600;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs, limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;

    let mut oversized = TcpStream::connect(server.address).await.unwrap();
    oversized.write_all(&record_header(257, true)).await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(1), oversized.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));

    let mut fragmented = TcpStream::connect(server.address).await.unwrap();
    let mut fragments = Vec::new();
    for value in [1u8, 2, 3, 4] {
        fragments.extend_from_slice(&record_header(1, false));
        fragments.push(value);
    }
    fragmented.write_all(&fragments).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), fragmented.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));

    let mut healthy = RpcClient::connect(server.address).await;
    let (status, payload) = healthy.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn lifecycle_is_waitable_idempotent_nonspawning_and_cancels_idle_connections() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let _idle = TcpStream::connect(server.address).await.unwrap();
    let started = Instant::now();
    server.handle.shutdown().await.unwrap();
    server.handle.shutdown().await.unwrap();
    server.handle.wait().await.unwrap();
    server.handle.wait().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));

    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let nfs_server = NfsServer::builder_arc(vfs).build().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_send, shutdown_receive) = oneshot::channel::<()>();
    let application_task = tokio::spawn(async move {
        nfs_server
            .serve(listener, async {
                let _ = shutdown_receive.await;
            })
            .await
    });
    let mut client = RpcClient::connect(address).await;
    let (status, payload) = client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());
    shutdown_send.send(()).unwrap();
    application_task.await.unwrap().unwrap();

    for _ in 0..3 {
        let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
        let instance = start_server(vfs).await;
        assert_ne!(instance.address.port(), 0);
        instance.shutdown().await;
    }
}

#[tokio::test]
async fn read_only_case_policy_reconnect_and_pipelining_profiles_work() {
    let read_only = Arc::new(ConformanceVfs::read_only(ExportId(1)));
    let read_only_server = start_server(read_only.clone()).await;
    let mut client = RpcClient::connect(read_only_server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;
    let mut write = Encoder::new();
    write.write_opaque(&file).unwrap();
    write.write_u64(0);
    write.write_u32(1);
    write.write_u32(0);
    write.write_opaque(b"x").unwrap();
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &write.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 30);
    let mut create = Encoder::new();
    create.write_opaque(&root).unwrap();
    create.write_opaque(b"must-not-exist").unwrap();
    create.write_u32(0);
    encode_empty_set_attributes(&mut create);
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 8, &create.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 30);
    assert_eq!(read_only.call_count("create"), 1);
    let payload = nfs_payload(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 12, &nfs_args_directory(&root, b"file"))
            .await,
    );
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 30);
    assert_eq!(read_only.call_count("remove"), 1);
    read_only_server.shutdown().await;

    for (vfs, expected_uppercase_status) in [
        (Arc::new(ConformanceVfs::new(ExportId(1))), 2),
        (Arc::new(ConformanceVfs::case_insensitive(ExportId(1))), 0),
    ] {
        let server = start_server(vfs).await;
        let mut first = RpcClient::connect(server.address).await;
        let root = mount_root(&mut first, b"/").await;
        let payload = nfs_payload(
            first
                .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(&root, b"FILE"))
                .await,
        );
        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), expected_uppercase_status);

        first.send_without_reading(800, NFS_PROGRAM, NFS_VERSION, 0, &[]).await;
        first.send_without_reading(801, NFS_PROGRAM, NFS_VERSION, 0, &[]).await;
        assert!(matches!(first.read_reply().await, RpcOutcome::Accepted { status: 0, .. }));
        assert!(matches!(first.read_reply().await, RpcOutcome::Accepted { status: 0, .. }));
        drop(first);

        let mut reconnected = RpcClient::connect(server.address).await;
        let (status, _) = reconnected.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
        assert_eq!(status, 0);
        server.shutdown().await;
    }
}
