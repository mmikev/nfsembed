# End-to-end certification suite

`tests/run_ci.sh` is the repository-level gate intended for future Linux and
macOS CI jobs. The integration tests use only the public embedded-server API
and communicate with the server over real TCP RPC record streams.

| Suite | Coverage |
| --- | --- |
| `e2e_protocol.rs` | Exact successful wire results for all 22 NFSv3 procedures, all MOUNTv3 procedures, AUTH_SYS context propagation, WCC, create modes, durability, cookies, and pagination |
| `e2e_errors.rs` | Every NFSv3 result-union failure shape, all-procedure truncation and trailing-field rejection, invalid discriminants, field limits, RPC mismatch ranges, and authentication policies |
| `e2e_runtime.rs` | Replay hit/wait/lost-reply/XID-generation/TTL/count/byte-budget behavior for mutations, re-execution of idempotent retransmissions, call-sized request/reply buffer reservations, authenticated handle isolation, multiple exports, inline and standalone TCP/UDP portmapper including oversized-datagram recovery, transport-aware transfer limits, in-band `SYSTEM_ERR` for oversized single-fragment calls and prompt disconnection for every other framing violation, aggregate request/reply byte budgets, execution and socket-progress timeouts, slow-reader eviction, concurrency, graceful lifecycle, reconnects, read-only and case policies |
| `e2e_adversarial.rs` | Fragmentation corpus, authentication prefix corpus, WRITE truncation and length corpus, READDIR/READDIRPLUS size sweep, and per-byte file-handle forgery corpus |
| `e2e_observability.rs` | Stable tracing fields and events, one warning per connection for repeated record refusals, plus negative checks for file-content and AUTH_SYS machine-name leakage |
| `e2e_load.rs` | Sustained multi-connection request/mutation load with concurrency, completion-time, operation-count, and Linux RSS-growth thresholds |
| `fuzz/` | cargo-fuzz targets for bounded XDR, AUTH_SYS, RPC records (including budgeted reads of a whole stream, seeded with refused records, where every accepted record, refusal, and error must match an independent model of the framing rules, including each record's bytes, budget reservation, and end, and every budget permit must be returned), handles, production WRITE decoding/validation, production READDIR sizing/encoding, and concurrent replay transitions |
| `native/` | Persistent privileged Linux/macOS kernel-client workload covering all NFSv3/MOUNTv3 procedure numbers, multi-megabyte I/O, namespace mutation verification, pagination, concurrency, reconnect, restart, read-only and case-policy profiles, plus same- and cross-host runners |

Run the platform-executable portion in a cached Linux toolchain container with
networking disabled. Formatting and Clippy remain part of the host/CI toolchain
gate because minimal Rust images may not contain those optional components:

```sh
docker run --rm --network none \
  -v "$PWD:/work:ro" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry:ro" \
  -w /work \
  -e CARGO_TARGET_DIR=/tmp/target \
  rust:1.96-bookworm \
  sh -c 'cargo test --all-targets && cargo test --all-features --all-targets'
```

The standard gate also builds and smoke-runs every cargo-fuzz target. Native
privileged mount interoperability is implemented by `tests/native/` and the
`native-client.yml` workflow. Linux and macOS runners launch the same embedded
certification server, mount using
`vers=3,tcp,port=<port>,mountport=<port>`, execute the shared workload, then
unmount. A Lima Linux VM on the `macos-15-intel` runner automatically covers both
cross-host directions on every pull request and push; no external endpoint is
required. The library itself never performs mount execution or privilege
elevation.
