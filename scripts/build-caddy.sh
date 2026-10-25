#!/bin/bash
# Builds Caddy with the Coraza WAF plugin for the server, in a container (podman), both architectures Hetzner offers.
# Output: dist/caddy-x86_64-unknown-linux-musl and dist/caddy-aarch64-unknown-linux-musl (static Go binaries;
# the target names mirror the pocketcloud binaries so setup can pick the matching one).
set -euo pipefail
cd "$(dirname "$0")/.."
targets=("${@:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl}")
read -ra targets <<<"${targets[*]}"
mkdir -p dist .caddy-cache
image=docker.io/library/caddy:builder
podman image exists "$image" || podman pull -q "$image" >/dev/null
for t in "${targets[@]}"; do
  case "$t" in
    x86_64-*) arch=amd64 ;;
    aarch64-*) arch=arm64 ;;
    *) echo "unknown target $t" >&2; exit 1 ;;
  esac
  echo "building caddy for $t"
  podman run --rm -v "$PWD/dist":/out:Z -v "$PWD/.caddy-cache":/go/pkg/mod:Z \
    -e GOOS=linux -e GOARCH="$arch" -e CGO_ENABLED=0 "$image" \
    xcaddy build --with github.com/corazawaf/coraza-caddy/v2 --output "/out/caddy-$t"
  ls -la "dist/caddy-$t"
done
