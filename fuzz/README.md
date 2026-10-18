# Fuzz targets

The cargo-fuzz package exercises the network-controlled codec, authentication,
record-fragmentation, and authenticated-handle surfaces, the production WRITE
argument validation and READDIR/READDIRPLUS reply encoder, and replay-cache
state transitions.

Run bounded smoke sessions locally:

```sh
for target in rpc_codec rpc_auth rpc_record file_handle nfs_write nfs_readdir replay; do
  cargo fuzz run "$target" -- -max_total_time=10
done
```

CI uses short deterministic smoke sessions; longer corpus and sanitizer runs
belong on the scheduled certification runners.
