#!/bin/sh
# Downloads the latest Pocketcloud release for this machine, verifies its checksum and runs setup.
#
#   curl -fsSL https://raw.githubusercontent.com/timokoenig/pocketcloud/main/scripts/install.sh | sh -s -- mycloud
#
# The binary lives in a temporary directory and is removed afterwards, like everything else setup uses.
# POCKETCLOUD_VERSION=0.1.1 pins a release instead of the latest one.
set -eu

repo=timokoenig/pocketcloud

fail() { echo "pocketcloud: $*" >&2; exit 1; }

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)                  target=aarch64-apple-darwin ;;
  Linux/x86_64)                  target=x86_64-unknown-linux-musl ;;
  Linux/aarch64 | Linux/arm64)   target=aarch64-unknown-linux-musl ;;
  *) fail "no release for $(uname -s) $(uname -m); build it from source (see README.md)" ;;
esac

command -v curl >/dev/null || fail "curl is required"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1"; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$1"; }
else fail "sha256sum or shasum is required"; fi

# Setup asks questions; when this script arrives through a pipe, they have to come from the terminal.
[ -r /dev/tty ] || fail "setup needs a terminal"

name=${1:-}
if [ -z "$name" ]; then
  printf 'Name of the installation [mycloud]: ' >/dev/tty
  read -r name </dev/tty || true
  name=${name:-mycloud}
fi

version=${POCKETCLOUD_VERSION:-}
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
    | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
  [ -n "$version" ] || fail "could not find the latest release"
fi
version=${version#v}

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT INT TERM

asset=pocketcloud-$target
url=https://github.com/$repo/releases/download/v$version/$asset
echo "Downloading pocketcloud $version ($target)"
curl -fsSL -o "$dir/$asset" "$url" || fail "download failed: $url"
curl -fsSL -o "$dir/$asset.sha256" "$url.sha256" || fail "no checksum published for $asset"

expected=$(cut -d' ' -f1 <"$dir/$asset.sha256")
actual=$(sha "$dir/$asset" | cut -d' ' -f1)
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset; not running it"
chmod +x "$dir/$asset"

"$dir/$asset" setup "$name" </dev/tty
