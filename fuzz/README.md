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

Where `fuzz/seeds/<target>` exists, pass it after the corpus directory, which
libFuzzer requires to exist. Its inputs reach paths that a short run from an
empty corpus does not, such as refused records followed by more records:

```sh
mkdir -p fuzz/corpus/rpc_record
cargo fuzz run rpc_record fuzz/corpus/rpc_record fuzz/seeds/rpc_record -- -max_total_time=10
```

CI uses short deterministic smoke sessions; longer corpus and sanitizer runs
belong on the scheduled certification runners.
