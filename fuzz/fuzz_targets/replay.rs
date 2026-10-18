#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nfsembed::replay::{ReplayCache, ReplayDecision, ReplayKey, RequestFingerprint};
use nfsembed::vfs::ExportId;
use tokio::runtime::{Builder, Runtime};

fuzz_target!(|data: &[u8]| {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| Builder::new_current_thread().build().unwrap());
    runtime.block_on(async {
        let replay_key = |xid| ReplayKey {
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            export_id: ExportId(1),
            xid,
        };

        // Drive completion, cancellation, closed receivers, and zero-TTL
        // transitions on every iteration before exploring the fuzzed state
        // machine below.
        let transitions = Arc::new(ReplayCache::new(2, 4096, Duration::ZERO));
        let fingerprint = RequestFingerprint([data.first().copied().unwrap_or_default(); 32]);
        if let Ok(ReplayDecision::Execute(leader)) = transitions.begin(replay_key(100), fingerprint) {
            if let Ok(ReplayDecision::Wait(waiter)) = transitions.begin(replay_key(100), fingerprint) {
                let task = tokio::spawn(async move { waiter.await });
                tokio::task::yield_now().await;
                leader.complete(Bytes::copy_from_slice(data.get(..data.len().min(32)).unwrap_or_default()));
                let _ = task.await;
            }
        }
        if let Ok(ReplayDecision::Execute(leader)) = transitions.begin(replay_key(101), fingerprint) {
            if let Ok(ReplayDecision::Wait(waiter)) = transitions.begin(replay_key(101), fingerprint) {
                drop(leader);
                let _ = waiter.await;
            }
        }
        if let Ok(ReplayDecision::Execute(leader)) = transitions.begin(replay_key(102), fingerprint) {
            if let Ok(ReplayDecision::Wait(waiter)) = transitions.begin(replay_key(102), fingerprint) {
                drop(waiter);
            }
            drop(leader);
        }

        let capacity = usize::from(data.first().copied().unwrap_or(1) % 16) + 1;
        let cache = Arc::new(ReplayCache::new(capacity, 4096, Duration::from_millis(10)));
        let mut leases = Vec::new();
        let mut waiters = Vec::new();
        for chunk in data.get(1..).unwrap_or_default().chunks(3).take(64) {
            let xid = u32::from(chunk.first().copied().unwrap_or_default() % 8);
            let marker = chunk.get(1).copied().unwrap_or_default();
            let action = chunk.get(2).copied().unwrap_or_default();
            let decision = cache.begin(replay_key(xid), RequestFingerprint([marker; 32]));
            match decision {
                Ok(ReplayDecision::Execute(lease)) if action & 1 == 0 => {
                    lease.complete(Bytes::copy_from_slice(chunk));
                },
                Ok(ReplayDecision::Execute(lease)) => leases.push(lease),
                Ok(ReplayDecision::Wait(waiter)) => waiters.push(waiter),
                Ok(ReplayDecision::Replay(_)) | Err(_) => {},
            }
            if action & 2 != 0 {
                leases.pop();
            }
        }
        drop(leases);
        for mut waiter in waiters {
            let _ = waiter.try_recv();
        }
    });
});
