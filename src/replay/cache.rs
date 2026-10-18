use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg(test)]
use bytes::Bytes;
use tokio::sync::oneshot;

use crate::rpc::reply::EncodedReply;
use crate::vfs::ExportId;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReplayKey {
    pub client_addr: SocketAddr,
    pub export_id: ExportId,
    pub xid: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestFingerprint(pub [u8; 32]);

pub enum ReplayDecision {
    Execute(ReplayLease),
    Replay(EncodedReply),
    Wait(oneshot::Receiver<Result<EncodedReply, ReplayError>>),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayError {
    #[error("replay cache capacity is exhausted by in-flight requests")]
    Capacity,
    #[error("the original request was cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayEntryKey {
    request: ReplayKey,
    fingerprint: RequestFingerprint,
    generation: u64,
}

#[derive(Clone, Copy)]
struct LatestGeneration {
    fingerprint: RequestFingerprint,
    generation: u64,
}

enum ReplayState {
    InFlight {
        waiters: Vec<oneshot::Sender<Result<EncodedReply, ReplayError>>>,
    },
    Completed {
        encoded_reply: EncodedReply,
        retained_bytes: usize,
        completed_at: Instant,
    },
}

/// Ownership token for an in-flight replay entry. Dropping an unfinished
/// lease cancels the entry and releases all exact-duplicate waiters.
pub struct ReplayLease {
    cache: Arc<ReplayCache>,
    key: ReplayEntryKey,
    finished: bool,
}

impl ReplayLease {
    pub fn complete(mut self, reply: impl Into<EncodedReply>) {
        let reply = reply.into();
        self.cache.complete(&self.key, reply);
        self.finished = true;
    }

    pub fn cancel(mut self) {
        self.cache.cancel(&self.key);
        self.finished = true;
    }
}

impl Drop for ReplayLease {
    fn drop(&mut self) {
        if !self.finished {
            self.cache.cancel(&self.key);
        }
    }
}

pub struct ReplayCache {
    capacity: usize,
    max_completed_bytes: usize,
    ttl: Duration,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    entries: HashMap<ReplayEntryKey, ReplayState>,
    latest: HashMap<ReplayKey, LatestGeneration>,
    completed_order: VecDeque<ReplayEntryKey>,
    completed_bytes: usize,
    next_generation: u64,
}

impl ReplayCache {
    pub fn new(capacity: usize, max_completed_bytes: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            max_completed_bytes,
            ttl,
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                latest: HashMap::new(),
                completed_order: VecDeque::new(),
                completed_bytes: 0,
                next_generation: 0,
            }),
        }
    }

    /// Classifies one request: the first caller executes it, exact duplicates
    /// of an in-flight request wait for its reply, and exact duplicates of a
    /// completed request replay the retained reply.
    pub fn begin(
        self: &Arc<Self>,
        key: ReplayKey,
        fingerprint: RequestFingerprint,
    ) -> Result<ReplayDecision, ReplayError> {
        let now = Instant::now();
        let mut inner = self.inner();
        Self::expire(&mut inner, now, self.ttl);
        if let Some(latest) = inner.latest.get(&key).copied() {
            if latest.fingerprint == fingerprint {
                let entry_key = ReplayEntryKey {
                    request: key.clone(),
                    fingerprint,
                    generation: latest.generation,
                };
                if let Some(state) = inner.entries.get_mut(&entry_key) {
                    match state {
                        ReplayState::InFlight { waiters } => {
                            // Duplicate callers share only the current
                            // generation. Closed waiters are discarded before
                            // adding the new receiver so a disconnected client
                            // cannot consume cache capacity.
                            waiters.retain(|waiter| !waiter.is_closed());
                            let (send, receive) = oneshot::channel();
                            waiters.push(send);
                            return Ok(ReplayDecision::Wait(receive));
                        },
                        ReplayState::Completed { encoded_reply, .. } => {
                            return Ok(ReplayDecision::Replay(encoded_reply.clone()));
                        },
                    }
                }
            }
        }

        Self::remove_completed_for_request(&mut inner, &key);
        if inner.entries.len() >= self.capacity && !Self::evict_oldest_completed(&mut inner) {
            return Err(ReplayError::Capacity);
        }
        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        let entry_key = ReplayEntryKey {
            request: key.clone(),
            fingerprint,
            generation,
        };
        inner.latest.insert(
            key,
            LatestGeneration {
                fingerprint,
                generation,
            },
        );
        inner
            .entries
            .insert(entry_key.clone(), ReplayState::InFlight { waiters: Vec::new() });
        Ok(ReplayDecision::Execute(ReplayLease {
            cache: self.clone(),
            key: entry_key,
            finished: false,
        }))
    }

    /// Stores the reply before callers attempt socket delivery.
    fn complete(&self, key: &ReplayEntryKey, reply: EncodedReply) {
        let cacheable_wire_size = reply.len() <= self.max_completed_bytes;
        // Unknown `Bytes` owners must be compacted before retention. Check
        // generation eligibility first so an already-stale large READ cannot
        // force a payload-sized copy. The second check under the lock below is
        // still required because XID reuse can race the copy.
        let eligible_before_copy = cacheable_wire_size
            && (!reply.replay_storage_requires_copy() || {
                let inner = self.inner();
                Self::is_latest(&inner, key) && matches!(inner.entries.get(key), Some(ReplayState::InFlight { .. }))
            });
        let replay_storage = eligible_before_copy.then(|| reply.replay_storage());
        let mut inner = self.inner();
        let waiters = match inner.entries.remove(key) {
            Some(ReplayState::InFlight { waiters }) => waiters,
            Some(state) => {
                inner.entries.insert(key.clone(), state);
                return;
            },
            None => return,
        };
        let is_latest = Self::is_latest(&inner, key);
        let mut retained = false;
        if let (true, Some((encoded_reply, retained_bytes))) = (is_latest, replay_storage) {
            // Reject a single over-budget backing allocation before eviction;
            // otherwise an uncacheable reply could flush useful entries.
            if retained_bytes <= self.max_completed_bytes {
                while inner.completed_bytes.saturating_add(retained_bytes) > self.max_completed_bytes {
                    if !Self::evict_oldest_completed(&mut inner) {
                        break;
                    }
                }
                if inner.completed_bytes.saturating_add(retained_bytes) <= self.max_completed_bytes {
                    inner.completed_bytes = inner.completed_bytes.saturating_add(retained_bytes);
                    inner.entries.insert(
                        key.clone(),
                        ReplayState::Completed {
                            encoded_reply,
                            retained_bytes,
                            completed_at: Instant::now(),
                        },
                    );
                    inner.completed_order.push_back(key.clone());
                    Self::compact_completion_order(&mut inner);
                    retained = true;
                }
            }
        }
        if is_latest && !retained {
            inner.latest.remove(&key.request);
        }
        for waiter in waiters {
            let _ = waiter.send(Ok(reply.clone()));
        }
    }

    fn cancel(&self, key: &ReplayEntryKey) {
        let mut inner = self.inner();
        let waiters = match inner.entries.remove(key) {
            Some(ReplayState::InFlight { waiters }) => waiters,
            Some(state) => {
                inner.entries.insert(key.clone(), state);
                Vec::new()
            },
            None => Vec::new(),
        };
        if Self::is_latest(&inner, key) {
            inner.latest.remove(&key.request);
        }
        for waiter in waiters {
            let _ = waiter.send(Err(ReplayError::Cancelled));
        }
    }

    pub fn len(&self) -> usize {
        self.inner().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner().entries.is_empty()
    }

    pub fn retained_bytes(&self) -> usize {
        self.inner().completed_bytes
    }

    fn inner(&self) -> MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn expire(inner: &mut CacheInner, now: Instant, ttl: Duration) {
        loop {
            let Some(oldest) = inner.completed_order.front() else {
                return;
            };
            match inner.entries.get(oldest) {
                Some(ReplayState::Completed { completed_at, .. }) if now.duration_since(*completed_at) < ttl => {
                    return;
                },
                Some(ReplayState::Completed { .. }) => {
                    let oldest = inner.completed_order.pop_front().expect("front entry exists");
                    Self::remove_completed(inner, &oldest);
                },
                // Entries removed because of XID reuse or byte-pressure
                // eviction leave a cheap tombstone in the order queue.
                Some(ReplayState::InFlight { .. }) | None => {
                    inner.completed_order.pop_front();
                },
            }
        }
    }

    fn remove_completed_for_request(inner: &mut CacheInner, request: &ReplayKey) {
        let Some(latest) = inner.latest.get(request).copied() else {
            return;
        };
        let key = ReplayEntryKey {
            request: request.clone(),
            fingerprint: latest.fingerprint,
            generation: latest.generation,
        };
        if matches!(inner.entries.get(&key), Some(ReplayState::Completed { .. })) {
            Self::remove_completed(inner, &key);
        }
    }

    fn remove_completed(inner: &mut CacheInner, key: &ReplayEntryKey) {
        if let Some(ReplayState::Completed { retained_bytes, .. }) = inner.entries.remove(key) {
            inner.completed_bytes = inner.completed_bytes.saturating_sub(retained_bytes);
        }
        if Self::is_latest(inner, key) {
            inner.latest.remove(&key.request);
        }
    }

    fn is_latest(inner: &CacheInner, key: &ReplayEntryKey) -> bool {
        inner
            .latest
            .get(&key.request)
            .is_some_and(|latest| latest.generation == key.generation && latest.fingerprint == key.fingerprint)
    }

    fn compact_completion_order(inner: &mut CacheInner) {
        // Lazy deletion makes the hot path constant-time, but repeated reuse
        // of a newer XID can leave tombstones behind an older live entry.
        // Compact infrequently to keep that auxiliary memory bounded while
        // preserving amortized O(1) updates.
        let compact_at = inner.entries.len().saturating_mul(2).max(64);
        if inner.completed_order.len() > compact_at {
            let entries = &inner.entries;
            inner
                .completed_order
                .retain(|key| matches!(entries.get(key), Some(ReplayState::Completed { .. })));
        }
    }

    fn evict_oldest_completed(inner: &mut CacheInner) -> bool {
        while let Some(oldest) = inner.completed_order.pop_front() {
            if matches!(inner.entries.get(&oldest), Some(ReplayState::Completed { .. })) {
                Self::remove_completed(inner, &oldest);
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(xid: u32) -> ReplayKey {
        ReplayKey {
            client_addr: "127.0.0.1:1234".parse().unwrap(),
            export_id: ExportId(1),
            xid,
        }
    }

    #[tokio::test]
    async fn duplicates_wait_then_replay() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([7; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let waiter = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected waiter"),
        };
        lease.complete(Bytes::from_static(b"reply"));
        assert_eq!(waiter.await.unwrap().unwrap(), Bytes::from_static(b"reply"));
        assert!(matches!(cache.begin(key(1), fingerprint).unwrap(), ReplayDecision::Replay(_)));
    }

    #[tokio::test]
    async fn segmented_replies_are_compacted_before_replay_retention() {
        let cache = Arc::new(ReplayCache::new(2, 2048, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([8; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let waiter = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected waiter"),
        };
        let mut oversized = Vec::with_capacity(1024 * 1024);
        oversized.resize(1024, 0x5a);
        let payload = Bytes::from(oversized);
        let payload_pointer = payload.as_ptr();
        lease.complete(EncodedReply::segmented(Bytes::from_static(b"prefix"), payload, 2));

        let waited = waiter.await.unwrap().unwrap();
        assert_eq!(waited.segments()[1].as_ptr(), payload_pointer);
        let replayed = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Replay(reply) => reply,
            _ => panic!("expected completed replay"),
        };
        assert_ne!(replayed.segments()[1].as_ptr(), payload_pointer);
        assert_eq!(cache.retained_bytes(), 1032);
    }

    #[tokio::test]
    async fn different_fingerprint_is_xid_reuse() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let second = match cache.begin(key(1), RequestFingerprint([2; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected XID reuse execution"),
        };
        drop((first, second));
    }

    #[tokio::test]
    async fn cancelled_leader_releases_waiters_and_capacity() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([3; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let waiter = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected waiter"),
        };
        drop(lease);
        assert_eq!(waiter.await.unwrap(), Err(ReplayError::Cancelled));
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn capacity_one_allows_completed_xid_reuse() {
        let cache = Arc::new(ReplayCache::new(1, 1024, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        first.complete(Bytes::from_static(b"first"));
        assert!(matches!(cache.begin(key(1), RequestFingerprint([2; 32])).unwrap(), ReplayDecision::Execute(_)));
    }

    #[tokio::test]
    async fn xid_reuse_history_treats_a_b_a_as_three_generations() {
        let cache = Arc::new(ReplayCache::new(4, 1024, Duration::from_secs(10)));
        let fingerprint_a = RequestFingerprint([1; 32]);
        let fingerprint_b = RequestFingerprint([2; 32]);
        let first = match cache.begin(key(1), fingerprint_a).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let first_waiter = match cache.begin(key(1), fingerprint_a).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected a waiter for the first A generation"),
        };
        let second = match cache.begin(key(1), fingerprint_b).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected B execution"),
        };
        let third = match cache.begin(key(1), fingerprint_a).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected a new A execution instead of waiting for the old generation"),
        };
        let third_waiter = match cache.begin(key(1), fingerprint_a).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected a waiter for the latest A generation"),
        };

        first.complete(Bytes::from_static(b"first-a"));
        assert_eq!(first_waiter.await.unwrap().unwrap(), Bytes::from_static(b"first-a"));
        second.complete(Bytes::from_static(b"b"));
        third.complete(Bytes::from_static(b"third-a"));
        assert_eq!(third_waiter.await.unwrap().unwrap(), Bytes::from_static(b"third-a"));
        assert!(matches!(cache.begin(key(1), fingerprint_a).unwrap(), ReplayDecision::Replay(_)));
    }

    #[tokio::test]
    async fn completed_reply_bytes_evict_old_entries_and_skip_oversized_replies() {
        let cache = Arc::new(ReplayCache::new(4, 5, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        first.complete(Bytes::from_static(b"1234"));
        let second = match cache.begin(key(2), RequestFingerprint([2; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected second execution"),
        };
        second.complete(Bytes::from_static(b"5678"));
        assert_eq!(cache.retained_bytes(), 4);
        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.begin(key(1), RequestFingerprint([1; 32])).unwrap(), ReplayDecision::Execute(_)));

        let oversized = match cache.begin(key(3), RequestFingerprint([3; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected oversized execution"),
        };
        oversized.complete(Bytes::from_static(b"123456"));
        assert!(cache.retained_bytes() <= 5);
        assert!(!matches!(cache.begin(key(3), RequestFingerprint([3; 32])).unwrap(), ReplayDecision::Replay(_)));

        for xid in 10..100 {
            let lease = match cache.begin(key(xid), RequestFingerprint([xid as u8; 32])).unwrap() {
                ReplayDecision::Execute(lease) => lease,
                _ => panic!("expected oversized execution"),
            };
            lease.complete(Bytes::from_static(b"123456"));
        }
        let inner = cache.inner();
        assert!(inner.latest.len() <= inner.entries.len());
        assert!(inner.entries.len() <= cache.capacity);
    }

    #[tokio::test]
    async fn owned_backing_capacity_counts_toward_the_replay_byte_limit() {
        let cache = Arc::new(ReplayCache::new(3, 64, Duration::from_secs(10)));
        let existing_fingerprint = RequestFingerprint([8; 32]);
        let existing = match cache.begin(key(2), existing_fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected existing execution"),
        };
        existing.complete(Vec::from(&b"keep"[..]));

        let fingerprint = RequestFingerprint([9; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let mut allocation = Vec::with_capacity(1024 * 1024);
        allocation.extend_from_slice(b"tiny");
        lease.complete(EncodedReply::from(allocation));

        assert_eq!(cache.retained_bytes(), 4);
        assert!(matches!(cache.begin(key(2), existing_fingerprint).unwrap(), ReplayDecision::Replay(_)));
        assert!(matches!(cache.begin(key(1), fingerprint).unwrap(), ReplayDecision::Execute(_)));
    }

    #[tokio::test]
    async fn stale_segmented_generation_is_not_retained() {
        let cache = Arc::new(ReplayCache::new(3, 2048, Duration::from_secs(10)));
        let stale_fingerprint = RequestFingerprint([10; 32]);
        let stale = match cache.begin(key(1), stale_fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected stale execution"),
        };
        let latest_fingerprint = RequestFingerprint([11; 32]);
        let latest = match cache.begin(key(1), latest_fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected latest execution"),
        };

        stale.complete(EncodedReply::segmented(Bytes::from_static(b"prefix"), Bytes::from(vec![0x5a; 1024]), 0));
        assert_eq!(cache.retained_bytes(), 0);
        assert!(matches!(cache.begin(key(1), latest_fingerprint).unwrap(), ReplayDecision::Wait(_)));
        drop(latest);
    }

    #[tokio::test]
    async fn repeated_xid_reuse_keeps_completion_order_bounded() {
        let cache = Arc::new(ReplayCache::new(4, 1024, Duration::from_secs(10)));
        for generation in 0..1000u32 {
            let fingerprint = RequestFingerprint([generation as u8; 32]);
            let lease = match cache.begin(key(1), fingerprint).unwrap() {
                ReplayDecision::Execute(lease) => lease,
                _ => panic!("expected a new generation"),
            };
            lease.complete(Bytes::from_static(b"reply"));
        }
        let inner = cache.inner();
        assert_eq!(inner.entries.len(), 1);
        assert!(inner.completed_order.len() <= 64);
    }

    #[tokio::test]
    async fn concurrent_xid_reuse_does_not_cancel_exact_waiters() {
        let cache = Arc::new(ReplayCache::new(4, 1024, Duration::from_secs(10)));
        let first_fingerprint = RequestFingerprint([1; 32]);
        let first = match cache.begin(key(1), first_fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let waiter = match cache.begin(key(1), first_fingerprint).unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected exact waiter"),
        };
        let reused = match cache.begin(key(1), RequestFingerprint([2; 32])).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected independent XID reuse"),
        };
        first.complete(Bytes::from_static(b"first"));
        assert_eq!(waiter.await.unwrap().unwrap(), Bytes::from_static(b"first"));
        drop(reused);
    }

    #[tokio::test]
    async fn ttl_never_expires_a_live_leader() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::ZERO));
        let fingerprint = RequestFingerprint([4; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        assert!(matches!(cache.begin(key(1), fingerprint).unwrap(), ReplayDecision::Wait(_)));
        drop(lease);
    }

    #[tokio::test]
    async fn disconnected_duplicate_waiters_do_not_exhaust_entry_capacity() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([5; 32]);
        let lease = match cache.begin(key(1), fingerprint).unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        for _ in 0..8 {
            let waiter = match cache.begin(key(1), fingerprint).unwrap() {
                ReplayDecision::Wait(waiter) => waiter,
                _ => panic!("expected duplicate waiter"),
            };
            drop(waiter);
        }

        assert!(matches!(cache.begin(key(2), RequestFingerprint([6; 32])).unwrap(), ReplayDecision::Execute(_)));
        drop(lease);
    }
}
