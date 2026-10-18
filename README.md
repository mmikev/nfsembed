Embedded Rust NFSv3 Server
==========================

> This project is an independent fork of [huggingface/nfsserve](https://github.com/huggingface/nfsserve), based on upstream commit `c00c3614184bc79010c0aa3b69c2cdde1c5fca77`.
> 
> It has intentionally diverged from upstream and is not API-compatible with
> the original crate. This project is not affiliated with or endorsed by the
> upstream authors or contributors.

`nfsembed` is an embeddable NFSv3-over-TCP server driven by an
application-provided virtual filesystem. The application owns the Tokio
runtime, listener, process lifecycle, signal handling, and operating-system
mount execution.

The production targets are native Linux, macOS, and Microsoft Windows Client
for NFS. Linux and macOS normally use explicit service ports:

```text
vers=3,tcp,port=<port>,mountport=<port>
```

Windows discovers NFSv3 and MOUNTv3 through portmapper v2, so the embedding
application supplies a TCP listener and UDP socket on port 111 in addition to
its NFS TCP listener.

The minimum supported Rust version is 1.96.

What changed in the fork
========================

The fork is a breaking, production-oriented refactor of the upstream crate.
It preserves the useful protocol definitions and interoperability knowledge,
but replaces the public server lifecycle, VFS contract, wire codec, transport,
retransmission handling, file handles, and test strategy. It is an evolution of
the existing crate rather than a clean-room rewrite.

The high-level API changes are:

| original | fork | Why it changed |
| --- | --- | --- |
| Implement `NFSFileSystem` | Implement `VirtualFileSystem` | The backend can now express identity, atomic mutations, write durability, directory cookies, and all NFSv3 procedures. |
| Create an `NFSTcpListener` that owns its listener and runs forever | Give an application-owned `TcpListener` to `NfsServer::start` or `NfsServer::serve` | The embedding application owns the Tokio runtime, socket binding, shutdown signal, and process lifecycle; `serve` also lets it place the top-level future. |
| Identify backend objects with a bare integer | Return an `ObjectKey { file_id, generation }` | Reused backend IDs can be distinguished and protected inside authenticated NFS handles. |
| Return operation-specific values and let handlers fetch attributes separately | Return `MutationResult<T>` with atomic before/after WCC data | NFS weak-cache-consistency replies no longer race separate `getattr` calls. |
| Treat duplicate XIDs as requests to drop | Wait for or replay the original encoded reply of a non-idempotent call | Retransmitted mutations get at-most-once behavior while the bounded replay entry is retained. |
| Keep the host-filesystem demo in the main API | Ship host-filesystem backends only as examples | The production contract is platform-neutral and does not define policy through a sample host backend. |

Embedded lifecycle
------------------

`NfsServer`, `NfsServerBuilder`, `ServerHandle`, and `MountInfo` replace the old
run-forever listener API. The refactored lifecycle provides:

* `start(listener)` for a managed server task and `serve(listener, signal)` for
  callers that want to own the server future;
* idempotent shutdown and waitable termination;
* a configurable graceful-shutdown deadline;
* cancellation and joining of connection and request tasks;
* the actual bound address and ports, including listeners bound to port zero;
* typed startup and fatal server errors without `process::exit`;
* multiple independent server instances and multiple exports in one process;
* no global Tokio runtime, signal handler, logger, metrics exporter, file-handle
  generation, or replay state.

The library still does not mount filesystems, elevate privileges, install
signals, or manage a daemon. Those remain responsibilities of the embedding
application.

Virtual filesystem contract
---------------------------

The new `VirtualFileSystem` trait is a complete NFSv3 backend boundary:

* Every permission-sensitive operation receives a `RequestContext` containing
  the authenticated `Principal`, client address, and `ExportId`.
* AUTH_SYS exposes UID, primary GID, supplementary groups, and the machine name;
  anonymous access remains an explicit policy choice.
* `ObjectKey` separates backend identity from the opaque NFS file handle.
* `MutationResult<T>` carries atomic before/after weak-cache-consistency data.
* `CreateMode` represents unchecked, guarded, and exclusive creation, including
  the exclusive verifier.
* `WriteStability`, `WriteResult`, and `commit` represent unstable, data-sync,
  and file-sync durability without claiming stronger persistence than the
  backend achieved.
* Directory enumeration uses opaque cookies and verifiers. The backend returns
  a page, while the protocol layer performs exact XDR-size truncation.
* `fsstat`, `fsinfo`, and `pathconf` values come from the backend. `FSINFO`
  transfer sizes are clamped to configured transport limits, and the reported
  `PATHCONF` name limit is capped at the server's validated 255-byte maximum.
* Default mutation methods use the declared read-only capability to return
  `NFS3ERR_ROFS`; otherwise they return `NFS3ERR_NOTSUPP`. Backends that
  override those methods remain responsible for enforcing their own read-only
  and authorization policies.
* Request futures are cancelled at the configured deadline. Backend mutations
  must therefore be cancellation-safe and must not detach untracked work.

The trait covers `GETATTR`, `SETATTR`, `LOOKUP`, `ACCESS`, `READLINK`, `READ`,
`WRITE`, `CREATE`, `MKDIR`, `SYMLINK`, `MKNOD`, `REMOVE`, `RMDIR`, `RENAME`,
`LINK`, `READDIR`, `READDIRPLUS`, `FSSTAT`, `FSINFO`, `PATHCONF`, and `COMMIT`.

Typed and bounded protocol implementation
-----------------------------------------

The manual response-building paths were replaced with typed NFSv3
argument/result unions and typed MOUNTv3 results. MOUNT arguments are small and
decoded directly in their procedure handlers. A handler constructs one complete
result before encoding it, including every legal success and failure arm. This
removes the malformed partial-response paths that existed around WCC data,
attributes, MOUNT replies, and several error branches.

The new RPC/XDR layer:

* bounds records, fragments, fragment counts, opaque fields, strings, arrays,
  AUTH_SYS groups, file handles, names, symlink targets, and transfer sizes;
* reserves aggregate memory before allocating record or reply bodies, sized to
  each call (a single-fragment record reserves its own length; a reply
  reserves the bound of its procedure and requested transfer count);
* uses checked arithmetic and rejects trailing or truncated arguments;
* rejects non-canonical booleans and invalid enum/union discriminants;
* returns decoding errors instead of allocating from unchecked wire lengths or
  panicking on network-controlled input;
* correctly emits RPC version/program/procedure mismatch ranges, authentication
  failures, garbage-argument replies, and `SYSTEM_ERR`.

All 22 NFSv3 procedures and all six MOUNTv3 procedures are implemented. MOUNT
uses a bounded per-run mount table and component-aware export matching.
Minimal portmapper `GETPORT` support is optional and disabled by default; it
returns zero for unsupported program/version/transport combinations and never
registers with the operating-system portmapper.

Resource hardening and request deadlines
----------------------------------------

`ServerLimits` makes resource policy explicit. It bounds connections,
per-connection queued requests, global in-flight executions, RPC record and
fragment sizes, aggregate request and reply buffers, replay entries and bytes,
mount-table entries, transfer sizes, and directory responses.

The connection path now uses bounded channels and semaphores rather than
unrestricted spawning. One absolute request deadline covers queueing, reply
budget acquisition, replay waiting, execution capacity, and the VFS future.
Idle reads use `idle_connection_timeout`; queue and socket-write progress use
`request_timeout`. Slow readers are disconnected, completed connection tasks
are reaped, and buffer permits remain owned by detached tracked executions until
their request/reply memory is gone. No server lock is held while awaiting
application VFS code.

Buffer budgets are charged by size rather than per call. A single-fragment
request reserves exactly its record length, and a fragmented one reserves the
maximum record size before its first body byte is read. A reply reserves an
upper bound derived from the call: READ and READDIR/READDIRPLUS replies scale
with the client's (server-clamped) count; READLINK, DUMP, and EXPORT replies
reserve the record limit; every other reply fits a small fixed bound. A reply
that would exceed its reservation is replaced by `SYSTEM_ERR`. Small metadata
calls therefore never queue behind the byte budget of a maximum-size record.

Replay and file-handle safety
-----------------------------

The old seen-XID tracker was replaced by a per-run reply cache for the
non-idempotent NFSv3 procedures (SETATTR, WRITE, CREATE, MKDIR, SYMLINK, MKNOD,
REMOVE, RMDIR, RENAME, and LINK). Its request fingerprint includes program,
version, procedure, principal identity, and a digest of the arguments. Exact
in-flight duplicates wait; exact completed duplicates receive the cached bytes;
a changed fingerprint is treated as XID reuse. Concurrent XID generations,
cancellation, lost socket replies, capacity, TTL, and retained reply bytes are
all handled explicitly.

Idempotent calls (reads, lookups, attribute and filesystem queries, COMMIT,
MOUNT, and portmapper) are executed again when retransmitted, as in other NFS
servers' duplicate-request caches. They are never fingerprinted or retained,
so bulk READ and READDIR payloads neither cost a copy nor evict the mutation
replies that need at-most-once protection.

NFS file handles now contain a format version, server-instance identity, export
identity, backend file ID, backend generation, and keyed integrity tag while
remaining within the 64-byte NFSv3 limit. Forged handles, cross-export handles,
and handles from a previous server run are rejected before reaching the VFS.
The server-instance write verifier also changes for every `start` or `serve`
run.

Observability and certification
-------------------------------

The production path emits `tracing` request spans and completion events with
procedure, XID, client, duration, protocol status, byte counts, and active
connection/request counts. Additional events cover replay decisions,
connection-limit rejection, execution timeouts and cancellations, and task
failures. The crate never installs a subscriber and avoids logging file data,
raw authentication buffers, complete packets, or pathnames at normal levels.

The test suite was expanded from basic behavior checks into release gates:

* public-API TCP tests cover every NFSv3 and MOUNTv3 procedure, every result
  union, AUTH_SYS, WCC, durability, pagination, replay, handles, lifecycle,
  limits, observability, and multiple exports;
* adversarial suites sweep fragmentation, truncated inputs, field limits,
  invalid discriminants, forged handles, directory response sizes, slow
  readers, connection churn, and bounded-memory/concurrency behavior;
* seven cargo-fuzz targets exercise RPC/XDR, authentication, record marking,
  handles, WRITE, READDIR/READDIRPLUS, and replay transitions;
* Linux, macOS, and Windows kernel clients run read-write, restart, lost-reply,
  read-only, and case-policy profiles in native CI; cross-host macOS/Linux
  helper scripts are also available for local certification;
* CI checks formatting, strict Clippy, tests with default and all features,
  rustdoc warnings, crate packaging, fuzz smoke sessions, and native
  interoperability.

Migration checklist
-------------------

Applications moving from the upstream version should:

1. Replace `NFSFileSystem` with `VirtualFileSystem` and use `ObjectKey` rather
   than exposing raw numeric IDs as NFS handles.
2. Update mutations to return `MutationResult<T>` atomically and implement the
   requested create, write-stability, `COMMIT`, cookie/verifier, and filesystem
   information semantics that the backend supports.
3. Make authorization decisions from `RequestContext` and select an explicit
   `AuthPolicy`.
4. Construct `NfsServer` with the desired exports and `ServerLimits`, bind a
   Tokio `TcpListener` in the application, then call `start` or `serve`.
5. Use `MountInfo` to construct the platform mount command; do not expect the
   library to mount, elevate privileges, or manage signals.
6. Make backend futures cancellation-safe because the server drops them when
   the request deadline expires.
7. Port any remaining `NFSFileSystem` code to `VirtualFileSystem`; the old
   demo API and its `demo` feature have been removed, and there is no automatic
   adapter. `examples/mirrorfs.rs` is a complete host-filesystem backend on the
   production contract.

Usage
=====

Implement `vfs::VirtualFileSystem`, then construct a server without creating a
runtime or binding a socket inside the library:

```rust,ignore
use nfsembed::{AuthPolicy, NfsServer, ServerLimits};
use tokio::net::TcpListener;

let server = NfsServer::builder(vfs)
    .export_name("virtual-fs")
    .limits(ServerLimits::production_defaults())
    .auth_policy(AuthPolicy::AuthSys)
    .build()?;

let listener = TcpListener::bind("127.0.0.1:0").await?;
let handle = server.start(listener).await?;
let mount_info = handle.mount_info();

// The embedding application performs the OS mount.

handle.shutdown().await?;
handle.wait().await?;
```

Applications that want ownership of the top-level server future can use
`server.serve(listener, shutdown_signal).await` instead.

Windows Client for NFS
----------------------

Windows requires portmapper v2 discovery and may query it over either TCP or
UDP. The application remains responsible for binding port 111 (and therefore
for the required privileges and port ownership), then transfers both sockets to
the same server lifecycle:

```rust,ignore
use nfsembed::{NfsServer, PortmapperSockets};
use tokio::net::{TcpListener, UdpSocket};

let nfs = TcpListener::bind("0.0.0.0:2049").await?;
let portmapper_tcp = TcpListener::bind("0.0.0.0:111").await?;
let portmapper_udp = UdpSocket::bind(portmapper_tcp.local_addr()?).await?;
let sockets = PortmapperSockets::new(portmapper_tcp, portmapper_udp);

let handle = server.start_with_portmapper(nfs, sockets).await?;
assert_eq!(handle.portmapper_addr(), Some("0.0.0.0:111".parse()?));
```

The standalone endpoint implements only portmapper v2 `NULL` and `GETPORT`.
It advertises NFSv3 and MOUNTv3 over TCP and returns zero for every unsupported
program, version, or transport. `advertised_ports` can point discovery at a TCP
proxy. Shutdown, fatal errors, task limits, and socket release are shared with
the NFS server handle.

Microsoft Client for NFS must be configured to use TCP (for example,
`nfsadmin client config protocol=TCP`) because NFS-over-UDP remains outside the
crate's scope. The native test runner verifies this setting before mounting.

The Windows host-filesystem demo uses native NTFS semantics without metadata
sidecars: server-owned NFS file IDs, zero UID/GID, approximate POSIX modes from
the read-only flag, native timestamps, case-insensitive identity with preserved
path spelling, and strict UTF-8 Win32-safe names. It reports symlink creation as
unsupported on Windows. These are example-backend policies; production VFS
implementations define their own mappings.

The VFS receives a `RequestContext` containing the authenticated principal,
client address, and export ID. Object keys are wrapped in server-instance and
export-scoped authenticated file handles; backends never parse raw NFS handles.
Additional independent exports can be added with
`NfsServerBuilder::add_export`; `ServerHandle::mount_infos` reports the bound
mount data for every configured export.

Scope
=====

The crate implements NFSv3 and MOUNTv3 over TCP. Optional minimal portmapper
v2 discovery is available on the NFS listener or on caller-owned TCP and UDP
sockets. NFSv4, NFS-over-UDP, NLM, ACL side protocols,
RPCSEC_GSS, mount execution, privilege elevation, and process lifecycle are
outside its scope. Backend operations that are unavailable return the NFS-level
`NFS3ERR_NOTSUPP` result.

End-to-end tests
================

The repository includes a public-API TCP certification harness covering every
NFSv3 procedure, MOUNTv3, replay, authentication, limits, lifecycle,
adversarial inputs, observability, strict documentation and package builds, and
cargo-fuzz smoke sessions. Run the non-privileged repository gate with:

```sh
./tests/run_ci.sh
```

See [`tests/README.md`](tests/README.md) for the coverage matrix and the
network-disabled Linux container command. Privileged Linux/macOS/Windows native-client
runners and local cross-host helper scripts live under
[`tests/native`](tests/native). Their persistent certification filesystem
verifies mutation state, pagination, reconnect, restart, concurrency, read-only
behavior, and case policy through real kernel clients. Same-host native tests
run in their own CI workflow because mounting requires platform privileges.

Performance benchmarks
======================

Criterion benchmarks cover large RPC opaque values, zero-copy WRITE decoding,
segmented READ reply assembly and replay cloning, fragmented record I/O,
streaming READDIR encoding with truncation, full replay-cache hits,
authenticated file-handle encoding and verification, and end-to-end loopback
GETATTR, READ, and READDIRPLUS round trips, including many concurrent clients
against a backend with latency. Run them with:

```sh
cargo bench --bench performance
```

To compare a change against a saved local baseline:

```sh
cargo bench --bench performance -- --save-baseline before
cargo bench --bench performance -- --baseline before
```

Relevant RFCs
=============
 - XDR is the message format: RFC 1014. https://datatracker.ietf.org/doc/html/rfc1014
 - SUN RPC is the RPC wire format: RFC 1057 https://datatracker.ietf.org/doc/html/rfc1057
 - NFS is at RFC 1813 https://datatracker.ietf.org/doc/html/rfc1813
 - NFS Mount Protocol is at RFC 1813 Appendix I. https://datatracker.ietf.org/doc/html/rfc1813#appendix-I
 - PortMapper is at RFC 1057 Appendix A https://datatracker.ietf.org/doc/html/rfc1057#appendix-A

Basic Source Layout
===================

 - `src/server/`: builder, transport-aware limits, lifecycle handle, deadline-bound VFS execution, and byte-budgeted connection tasks.
 - `src/rpc/`: bounded XDR primitives, authentication, and TCP record marking.
 - `src/nfs3/`: NFSv3 types, procedure identities, and codec surface.
 - `src/mount3/`: MOUNTv3 types and export matching.
 - `src/portmap/`: optional minimal portmapper support.
 - `src/vfs/`: request context, object and mutation types, and the VFS contract.
 - `src/replay/`: count-, byte-, TTL-, and XID-generation-bounded duplicate-request reply cache.
 - `src/handles/`: authenticated, instance-scoped file-handle encoding.

The host-filesystem examples run without extra features:
`cargo run --example demo` and `cargo run --example mirrorfs -- <directory>`.


Protocol flow
=============

An RPC call over TCP follows this path:

1. The record-marking layer reads one or more fragments. Each fragment starts
   with a four-byte header containing the final-fragment bit and fragment size.
2. The bounded fragments are assembled into one SUN RPC record.
3. The RPC header selects a program, version, and procedure. This crate serves
   NFS (`100003`), MOUNT (`100005`), and, when enabled, portmapper (`100000`) on
   the same TCP listener.
4. The selected handler decodes and validates the procedure arguments, invokes
   the VFS when needed, and builds a complete protocol result.
5. The result is wrapped in an RPC reply and emitted as one or more bounded TCP
   record fragments.

Portmapper
----------

Traditional ONC RPC services can register with an operating-system portmapper
on TCP/UDP port 111 so clients can discover their ports. This crate does not
register with that daemon or bind port 111 on the application's behalf.

When `PortmapperMode::Enabled` is selected, the embedded server accepts
portmapper `NULL` and `GETPORT` calls on the same application-provided TCP
listener. `GETPORT` reports that listener's port for supported NFSv3 or MOUNTv3
TCP queries and zero for unsupported combinations. It is disabled by default;
Linux and macOS clients can instead use explicit `port` and `mountport` mount
options.

For Microsoft Client for NFS, use `PortmapperSockets` with
`start_with_portmapper` or `serve_with_portmapper`. This exposes the same
minimal service on a caller-bound TCP/UDP address (normally port 111), which
allows the Windows client to discover the NFS and MOUNT TCP ports without
changing the crate's NFS-over-TCP scope.


NFS Basics
==========
NFSv3 exposes two relevant object identifiers:

1. `fileid3`, a 64-bit filesystem-defined ID reported in attributes and
   directory entries.
2. `nfs_fh3`, a variable opaque file handle of up to 64 bytes that clients send
   back in later operations.

Most object operations address their target with an `nfs_fh3`. In this server,
the handle authenticates and encodes the server-run identity, export ID, and
backend `ObjectKey`; clients do not inspect those fields. A handle from an older
`start` or `serve` run is rejected as stale, while a malformed or cross-export
handle is rejected as invalid before the VFS is called.

The first handle normally comes from MOUNT. Later handles can come from
`LOOKUP`, successful object-creation procedures, or `READDIRPLUS`. For example,
after obtaining the exported root handle, a client can resolve `dir/a.txt` with
successive `LOOKUP` calls.

Mount
-----
The MOUNT protocol lists exports and turns a mounted export path into its first
NFS file handle. For a server exporting `/`, `MNT("/")` returns the root handle.
Component-aware matching also permits a path below an export; the server walks
the remaining components through VFS `lookup` calls.

The server maintains a bounded mount table per server run and implements `MNT`,
`DUMP`, `UMNT`, `UMNTALL`, and `EXPORT`. Unmount procedures return the void
MOUNTv3 result required by the protocol.

NFS
---
NFSv3 operations are request-oriented and do not establish a server-side open
file session. The overall implementation is not completely stateless, however:
the application VFS owns filesystem state, and each server run keeps bounded
mount and replay tables. The replay cache is required to give retransmitted
mutations at-most-once behavior while their entries remain retained; idempotent
procedures bypass it.
