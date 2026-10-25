#!/bin/bash
# Builds the static Linux binaries for the server in a container (podman), both architectures Hetzner offers.
# Output: dist/pocketcloud-x86_64-unknown-linux-musl and dist/pocketcloud-aarch64-unknown-linux-musl
set -euo pipefail
cd "$(dirname "$0")/.."
targets=("${@:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl}")
read -ra targets <<<"${targets[*]}"
mkdir -p dist
image=ghcr.io/rust-cross/cargo-zigbuild:latest
podman image exists "$image" || podman pull -q "$image" >/dev/null
for t in "${targets[@]}"; do
  echo "building $t"
  podman run --rm -v "$PWD":/io:Z -w /io -e CARGO_HOME=/io/.cargo-container "$image" \
    cargo zigbuild --release --target "$t" --target-dir /io/target-linux
  cp "target-linux/$t/release/pocketcloud" "dist/pocketcloud-$t"
  ls -la "dist/pocketcloud-$t"
done
