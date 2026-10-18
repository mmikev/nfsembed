use std::future::Future;
use std::hint::black_box;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nfsembed::handles::HandleCodec;
use nfsembed::nfs3::codec::{encode_readdir_reply, Encoder, ReadDirLimits};
use nfsembed::nfs3::procedures::{NfsArguments, ReadDirEntry, ReadDirEntryExtension, WriteRequest};
use nfsembed::replay::{ReplayCache, ReplayDecision, ReplayKey, RequestFingerprint};
use nfsembed::rpc::codec::Decoder;
use nfsembed::rpc::record::{read_record, write_record_limited, write_record_segments_limited, RecordLimits};
use nfsembed::rpc::reply::EncodedReply;
use nfsembed::vfs::{
    CreatedObject, DirectoryEntry, ExportId, FileAttributes, FileType, NfsError, NfsName, NfsTime, ObjectKey,
    ReadBytesResult, ReadDirectoryPage, RequestContext, VfsCapabilities, VirtualFileSystem,
};
use nfsembed::{NfsServer, ServerLimits};
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};

const MIB: usize = 1024 * 1024;

// This synthetic writer advertises vectored support and can cap each accepted
// prefix. The assertions ensure benchmarks exercise the intended vectored and
// partial-write branches instead of silently falling back to scalar writes.
struct VectoredSink {
    bytes_written: usize,
    scalar_writes: usize,
    vectored_writes: usize,
    max_write: usize,
}

impl VectoredSink {
    fn with_max_write(max_write: usize) -> Self {
        assert!(max_write > 0);
        Self {
            bytes_written: 0,
            scalar_writes: 0,
            vectored_writes: 0,
            max_write,
        }
    }

    fn verify_record(&self, record_bytes: usize, fragments: usize) {
        assert_eq!(self.bytes_written, record_bytes + fragments * 4);
        assert_eq!(self.scalar_writes, 0);
        assert_eq!(self.vectored_writes, fragments);
    }

    fn verify_partial_record(&self, record_bytes: usize, fragments: usize) {
        assert_eq!(self.bytes_written, record_bytes + fragments * 4);
        assert_eq!(self.scalar_writes, 0);
        assert!(self.vectored_writes > fragments);
    }
}

impl Default for VectoredSink {
    fn default() -> Self {
        Self::with_max_write(usize::MAX)
    }
}

impl AsyncWrite for VectoredSink {
    fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let written = buffer.len().min(self.max_write);
        self.bytes_written += written;
        self.scalar_writes += 1;
        Poll::Ready(Ok(written))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let written = buffers.iter().map(|buffer| buffer.len()).sum::<usize>().min(self.max_write);
        self.bytes_written += written;
        self.vectored_writes += 1;
        Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn codec_benchmarks(c: &mut Criterion) {
    let payload = vec![0x5a; MIB];
    let mut encoded = Encoder::new();
    encoded.write_opaque(&payload).unwrap();
    let encoded = encoded.into_bytes();

    let mut group = c.benchmark_group("rpc_codec");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("encode_opaque_1mib", |b| {
        b.iter(|| {
            let mut encoder = Encoder::new();
            encoder.write_opaque(black_box(&payload)).unwrap();
            black_box(encoder.into_bytes())
        })
    });
    group.bench_function("decode_opaque_1mib", |b| {
        b.iter(|| {
            let mut decoder = Decoder::new(black_box(&encoded));
            let value = decoder.read_opaque("benchmark", MIB).unwrap();
            decoder.finish().unwrap();
            black_box(value)
        })
    });

    let mut write_arguments = Encoder::new();
    write_arguments.write_opaque(&[0x11; 45]).unwrap();
    write_arguments.write_u64(4096);
    write_arguments.write_u32(MIB as u32);
    write_arguments.write_u32(2);
    write_arguments.write_opaque(&payload).unwrap();
    let write_arguments = write_arguments.into_bytes();
    group.bench_function("decode_nfs_write_1mib", |b| {
        b.iter(|| black_box(NfsArguments::decode(7, black_box(&write_arguments), MIB).unwrap()))
    });
    let write_request = Bytes::from(write_arguments.clone());
    group.bench_function("decode_nfs_write_1mib_zero_copy", |b| {
        b.iter(|| black_box(WriteRequest::decode(black_box(write_request.clone()), MIB).unwrap()))
    });
    group.finish();
}

fn record_benchmarks(c: &mut Criterion) {
    let rt = runtime();
    let payload = vec![0x33; MIB];
    let limits = RecordLimits {
        max_record_size: MIB,
        max_fragment_size: 64 * 1024,
        max_fragments: 16,
    };
    let mut framed = Vec::with_capacity(MIB + 16 * 4);
    for (index, fragment) in payload.chunks(limits.max_fragment_size).enumerate() {
        let last = index == limits.max_fragments - 1;
        let header = fragment.len() as u32 | if last { 0x8000_0000 } else { 0 };
        framed.extend_from_slice(&header.to_be_bytes());
        framed.extend_from_slice(fragment);
    }

    let mut group = c.benchmark_group("rpc_record");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("read_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut input = black_box(framed.as_slice());
            black_box(read_record(&mut input, limits).await.unwrap())
        })
    });
    group.bench_function("write_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::default();
            write_record_limited(&mut output, black_box(&payload), limits).await.unwrap();
            output.verify_record(MIB, 16);
            black_box(output)
        })
    });
    let prefix = vec![0x22; 128];
    group.bench_function("write_segmented_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::default();
            write_record_segments_limited(
                &mut output,
                [
                    black_box(prefix.as_slice()),
                    black_box(&payload[..MIB - prefix.len()]),
                    &[],
                ],
                limits,
            )
            .await
            .unwrap();
            output.verify_record(MIB, 16);
            black_box(output)
        })
    });
    group.bench_function("write_segmented_1mib_16_fragments_partial_4k", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::with_max_write(4 * 1024);
            write_record_segments_limited(
                &mut output,
                [
                    black_box(prefix.as_slice()),
                    black_box(&payload[..MIB - prefix.len()]),
                    &[],
                ],
                limits,
            )
            .await
            .unwrap();
            output.verify_partial_record(MIB, 16);
            black_box(output)
        })
    });
    group.finish();
}

fn read_reply_benchmarks(c: &mut Criterion) {
    let prefix = Bytes::from(vec![0x22; 128]);
    let payload = Bytes::from(vec![0x33; MIB]);
    let reply = EncodedReply::segmented(prefix.clone(), payload.clone(), 0);

    let mut group = c.benchmark_group("read_reply");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("assemble_segmented_1mib", |b| {
        b.iter(|| black_box(EncodedReply::segmented(black_box(prefix.clone()), black_box(payload.clone()), 0)))
    });
    group.bench_function("clone_for_replay_1mib", |b| b.iter(|| black_box(EncodedReply::clone(black_box(&reply)))));
    group.finish();
}

fn readdir_entries(entry_count: usize) -> Vec<ReadDirEntry> {
    (0..entry_count)
        .map(|index| ReadDirEntry {
            file_id: index as u64,
            name: format!("entry-{index:08}").into_bytes(),
            cookie: index as u64 + 1,
            extension: ReadDirEntryExtension::Basic,
        })
        .collect()
}

fn readdir_benchmarks(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 4096;
    let entries = readdir_entries(ENTRY_COUNT);
    let unlimited = ReadDirLimits {
        max_size: usize::MAX,
        directory_size: None,
    };
    let mut fully_encoded = Encoder::new();
    encode_readdir_reply(&mut fully_encoded, None, [7; 8], entries.clone(), true, unlimited).unwrap();
    let half = ReadDirLimits {
        max_size: fully_encoded.len() / 2,
        directory_size: None,
    };

    let mut group = c.benchmark_group("readdir");
    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    group.bench_function("encode_4096_entries_truncated_to_half", |b| {
        b.iter_batched(
            || entries.clone(),
            |entries| {
                let mut encoder = Encoder::with_capacity(half.max_size + 8);
                encode_readdir_reply(&mut encoder, None, [7; 8], entries, true, half).unwrap();
                black_box(encoder)
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn replay_key(xid: u32) -> ReplayKey {
    ReplayKey {
        client_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        export_id: ExportId(1),
        xid,
    }
}

fn replay_benchmarks(c: &mut Criterion) {
    const ENTRIES: u32 = 4096;
    let cache = Arc::new(ReplayCache::new(ENTRIES as usize, ENTRIES as usize * 64, Duration::from_secs(3600)));
    for xid in 0..ENTRIES {
        let fingerprint = RequestFingerprint([xid as u8; 32]);
        let ReplayDecision::Execute(lease) = cache.begin(replay_key(xid), fingerprint).unwrap() else {
            unreachable!();
        };
        lease.complete(Bytes::from_static(b"cached reply"));
    }
    let hit_key = replay_key(ENTRIES - 1);
    let hit_fingerprint = RequestFingerprint([(ENTRIES - 1) as u8; 32]);

    let mut group = c.benchmark_group("replay_cache");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("hit_at_capacity", ENTRIES), |b| {
        b.iter(|| match cache.begin(black_box(hit_key.clone()), hit_fingerprint).unwrap() {
            ReplayDecision::Replay(reply) => black_box(reply),
            _ => unreachable!(),
        })
    });
    group.finish();
}

fn handle_benchmarks(c: &mut Criterion) {
    let codec = HandleCodec::random();
    let export = ExportId(17);
    let object = ObjectKey {
        file_id: 0x1234_5678,
        generation: 9,
    };
    let encoded = codec.encode(export, object);

    let mut group = c.benchmark_group("file_handle");
    group.bench_function("encode", |b| b.iter(|| black_box(codec.encode(export, black_box(object)))));
    group.bench_function("decode_and_verify", |b| {
        b.iter(|| black_box(codec.decode(export, black_box(&encoded)).unwrap()))
    });
    group.finish();
}

const BENCH_ROOT: ObjectKey = ObjectKey {
    file_id: 1,
    generation: 1,
};
const BENCH_FILE: ObjectKey = ObjectKey {
    file_id: 2,
    generation: 1,
};
const BENCH_DIRECTORY_ENTRIES: u64 = 1024;

/// In-memory backend for end-to-end request benchmarks. It serves a root
/// directory with `BENCH_DIRECTORY_ENTRIES` children and one shared 1 MiB file
/// whose reads are zero-copy slices, so the measured time is server overhead.
struct BenchVfs {
    data: Bytes,
    backend_latency: Duration,
}

fn bench_attributes(object: ObjectKey) -> FileAttributes {
    FileAttributes {
        file_type: if object == BENCH_ROOT {
            FileType::Directory
        } else {
            FileType::Regular
        },
        mode: 0o755,
        links: 1,
        uid: 1000,
        gid: 1000,
        size: MIB as u64,
        used: MIB as u64,
        device: None,
        fs_id: 1,
        file_id: object.file_id,
        access_time: NfsTime::default(),
        modify_time: NfsTime::default(),
        change_time: NfsTime::default(),
    }
}

#[async_trait]
impl VirtualFileSystem for BenchVfs {
    fn capabilities(&self) -> VfsCapabilities {
        VfsCapabilities::READ_ONLY
    }

    fn root(&self) -> ObjectKey {
        BENCH_ROOT
    }

    async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        if !self.backend_latency.is_zero() {
            tokio::time::sleep(self.backend_latency).await;
        }
        Ok(bench_attributes(object))
    }

    async fn lookup(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        Ok(CreatedObject {
            object: BENCH_FILE,
            attributes: Some(bench_attributes(BENCH_FILE)),
        })
    }

    async fn read_bytes(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadBytesResult, NfsError> {
        let start = (offset as usize).min(self.data.len());
        let end = start.saturating_add(count as usize).min(self.data.len());
        Ok(ReadBytesResult {
            data: self.data.slice(start..end),
            eof: end == self.data.len(),
            attributes: Some(bench_attributes(BENCH_FILE)),
        })
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        _directory: ObjectKey,
        cookie: u64,
        _verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        let entries: Vec<_> = (cookie + 1..=BENCH_DIRECTORY_ENTRIES)
            .take(backend_hint)
            .map(|index| {
                let object = ObjectKey {
                    file_id: index + 10,
                    generation: 1,
                };
                DirectoryEntry {
                    object,
                    file_id: object.file_id,
                    name: NfsName::new(format!("entry-{index:08}")).unwrap(),
                    cookie: index,
                    attributes: Some(bench_attributes(object)),
                }
            })
            .collect();
        let eof = entries.last().is_none_or(|entry| entry.cookie == BENCH_DIRECTORY_ENTRIES);
        Ok(ReadDirectoryPage {
            verifier: [1; 8],
            entries,
            eof,
        })
    }
}

const BENCH_RECORD_LIMITS: RecordLimits = RecordLimits {
    max_record_size: 4 * MIB,
    max_fragment_size: 4 * MIB,
    max_fragments: 8,
};

static NEXT_BENCH_XID: AtomicU32 = AtomicU32::new(1);

/// Sends one AUTH_SYS call with a fresh XID so that no iteration can be served
/// from the duplicate-request cache, and returns the reply record.
async fn bench_call(stream: &mut TcpStream, program: u32, procedure: u32, arguments: &[u8]) -> Vec<u8> {
    let mut credential = Encoder::new();
    credential.write_u32(0);
    credential.write_opaque(b"bench").unwrap();
    credential.write_u32(1000);
    credential.write_u32(1000);
    credential.write_u32(0);
    let mut call = Encoder::new();
    call.write_u32(NEXT_BENCH_XID.fetch_add(1, Ordering::Relaxed));
    call.write_u32(0);
    call.write_u32(2);
    call.write_u32(program);
    call.write_u32(3);
    call.write_u32(procedure);
    call.write_u32(1);
    call.write_opaque(&credential.into_bytes()).unwrap();
    call.write_u32(0);
    call.write_u32(0);
    call.write_fixed(arguments);
    write_record_limited(stream, &call.into_bytes(), BENCH_RECORD_LIMITS)
        .await
        .unwrap();
    let reply = read_record(stream, BENCH_RECORD_LIMITS).await.unwrap();
    // xid, reply, accepted, verifier flavor, verifier length, accept status
    assert_eq!(&reply[20..28], &[0; 8], "benchmark call was not accepted with NFS3_OK");
    reply
}

async fn bench_root_handle(stream: &mut TcpStream) -> Vec<u8> {
    let mut path = Encoder::new();
    path.write_opaque(b"/").unwrap();
    let reply = bench_call(stream, nfsembed::mount3::types::PROGRAM, 1, &path.into_bytes()).await;
    let mut decoder = Decoder::new(&reply[28..]);
    decoder.read_opaque("root handle", 64).unwrap()
}

fn server_benchmarks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (handle, mut stream, root, file) = rt.block_on(async {
        let server = NfsServer::builder(BenchVfs {
            data: Bytes::from(vec![0x42; MIB]),
            backend_latency: Duration::ZERO,
        })
        .build()
        .unwrap();
        let handle = server.start(TcpListener::bind("127.0.0.1:0").await.unwrap()).await.unwrap();
        let mut stream = TcpStream::connect(handle.mount_info().server_addr).await.unwrap();
        let root = bench_root_handle(&mut stream).await;
        let mut lookup = Encoder::new();
        lookup.write_opaque(&root).unwrap();
        lookup.write_opaque(b"file").unwrap();
        let reply = bench_call(&mut stream, nfsembed::nfs3::types::PROGRAM, 3, &lookup.into_bytes()).await;
        let file = Decoder::new(&reply[28..]).read_opaque("file handle", 64).unwrap();
        (handle, stream, root, file)
    });
    let mut getattr = Encoder::new();
    getattr.write_opaque(&root).unwrap();
    let getattr = getattr.into_bytes();
    let mut read = Encoder::new();
    read.write_opaque(&file).unwrap();
    read.write_u64(0);
    read.write_u32(MIB as u32);
    let read = read.into_bytes();
    let mut readdirplus = Encoder::new();
    readdirplus.write_opaque(&root).unwrap();
    readdirplus.write_u64(0);
    readdirplus.write_fixed(&[0; 8]);
    readdirplus.write_u32(64 * 1024);
    readdirplus.write_u32(256 * 1024);
    let readdirplus = readdirplus.into_bytes();

    let mut group = c.benchmark_group("server");
    group.throughput(Throughput::Elements(1));
    group.bench_function("getattr_round_trip", |b| {
        b.iter(|| rt.block_on(bench_call(&mut stream, nfsembed::nfs3::types::PROGRAM, 1, black_box(&getattr))))
    });
    group.bench_function("readdirplus_256k_round_trip", |b| {
        b.iter(|| rt.block_on(bench_call(&mut stream, nfsembed::nfs3::types::PROGRAM, 17, black_box(&readdirplus))))
    });
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("read_1mib_round_trip", |b| {
        b.iter(|| rt.block_on(bench_call(&mut stream, nfsembed::nfs3::types::PROGRAM, 6, black_box(&read))))
    });
    group.finish();
    drop(stream);
    rt.block_on(async {
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    });

    // Many clients issuing small requests against a backend with latency.
    // Byte-budget reservations, not the backend, decide how many of these
    // requests may be in flight at once.
    const CLIENTS: usize = 128;
    let (handle, mut clients, root) = rt.block_on(async {
        let server = NfsServer::builder(BenchVfs {
            data: Bytes::new(),
            backend_latency: Duration::from_millis(2),
        })
        .limits(ServerLimits::production_defaults())
        .build()
        .unwrap();
        let handle = server.start(TcpListener::bind("127.0.0.1:0").await.unwrap()).await.unwrap();
        let mut clients = Vec::with_capacity(CLIENTS);
        for _ in 0..CLIENTS {
            clients.push(TcpStream::connect(handle.mount_info().server_addr).await.unwrap());
        }
        let root = bench_root_handle(&mut clients[0]).await;
        (handle, clients, root)
    });
    let mut getattr = Encoder::new();
    getattr.write_opaque(&root).unwrap();
    let getattr = Arc::new(getattr.into_bytes());
    let mut group = c.benchmark_group("server_concurrency");
    group.throughput(Throughput::Elements(CLIENTS as u64));
    group.sample_size(20);
    group.bench_function(BenchmarkId::new("getattr_2ms_backend", CLIENTS), |b| {
        b.iter(|| {
            rt.block_on(async {
                let calls = clients.iter_mut().map(|stream| {
                    let getattr = getattr.clone();
                    async move { bench_call(stream, nfsembed::nfs3::types::PROGRAM, 1, &getattr).await }
                });
                black_box(futures_join_all(calls).await)
            })
        })
    });
    group.finish();
    drop(clients);
    rt.block_on(async {
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    });
}

/// Minimal `join_all` so the benchmark does not need the `futures` crate.
async fn futures_join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for future in futures {
        set.push(Box::pin(future));
    }
    let mut outputs: Vec<Option<F::Output>> = set.iter().map(|_| None).collect();
    std::future::poll_fn(|context| {
        let mut pending = false;
        for (future, output) in set.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(context) {
                    Poll::Ready(value) => *output = Some(value),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outputs.into_iter().map(Option::unwrap).collect()
}

criterion_group!(
    benches,
    codec_benchmarks,
    record_benchmarks,
    read_reply_benchmarks,
    readdir_benchmarks,
    replay_benchmarks,
    handle_benchmarks,
    server_benchmarks
);
criterion_main!(benches);
