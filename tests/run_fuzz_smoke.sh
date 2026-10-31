#!/bin/sh
set -eu

command -v cargo-fuzz >/dev/null 2>&1 || {
  echo "cargo-fuzz is required for the certification gate" >&2
  exit 1
}

cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo +nightly fuzz build

# A short run from an empty corpus only reaches small inputs, so targets with
# committed seeds start from them as well.
for target in rpc_codec rpc_auth rpc_record file_handle nfs_write nfs_readdir replay; do
  if [ -d "fuzz/seeds/$target" ]; then
    mkdir -p "fuzz/corpus/$target"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- -runs=1000
  else
    cargo +nightly fuzz run "$target" -- -runs=1000
  fi
done
