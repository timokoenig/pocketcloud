#!/bin/bash
# Push a local build to a server and let the daemon install it: scp over the VPN with a key added in the
# interface, then `pocketcloud server upgrade --from-dir`. Usage: scripts/push-dev.sh <ssh target> [caddy]
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?ssh target, e.g. admin@10.8.0.1}
arch=$(ssh "$target" uname -m)
case "$arch" in aarch64) t=aarch64-unknown-linux-musl ;; *) t=x86_64-unknown-linux-musl ;; esac
ssh "$target" "mkdir -p /tmp/pocketcloud-build"
scp "dist/pocketcloud-$t" "$target:/tmp/pocketcloud-build/pocketcloud"
[[ "${2:-}" == caddy ]] && scp "dist/caddy-$t" "$target:/tmp/pocketcloud-build/caddy"
ssh "$target" "sudo pocketcloud server upgrade --from-dir /tmp/pocketcloud-build && rm -rf /tmp/pocketcloud-build"
