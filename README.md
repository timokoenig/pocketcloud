# Pocketcloud

Your own small cloud on one Hetzner server. One Rust binary: run it on your Mac to create and harden a server, then
manage compose apps from a web interface that is reachable through WireGuard only.

- **Server**: Ubuntu 24.04, key-only SSH, nftables default drop, fail2ban, auditd, AIDE, unattended security
  updates. Docker with its firewall handling turned off; Pocketcloud owns nftables. Caddy on the host as the only
  listener.
- **Network**: public DNS holds `domain`, `*.domain`, a CAA record and the delegation of `_acme-challenge` to the
  server. One wildcard certificate per domain via DNS-01, answered by the daemon's own nameserver; no DNS token
  on the server. Public routes on the public address, internal routes and the interface on the
  WireGuard address `10.8.0.1`; VPN clients resolve internal names through the server.
- **Apps**: a compose file with prebuilt images. Published ports are stripped, every app gets its own bridge
  `pc-<app>` in `172.30.<n>.0/24` with static addresses, secrets arrive as an env file and as `${NAME}` in the file.
  Deploys are health-gated; a failed deploy rolls back to the previous release.
- Public routes sit behind a web application firewall (Coraza, OWASP Core Rule Set), switchable per route.
- Built-in monitoring: journal, auditd, Falco and Docker events plus host metrics, fixed checks, alerts by mail or
  webhook, a heartbeat for a dead man's switch. Nightly restic backups to S3 with restore.
- **Interface**: Apps, Server (overview, backups, security), Alerts (alerts, host metrics, events, audit log) and Settings
  (notifications, VPN devices, ssh keys, agents, registries, account with teardown); everything after setup is managed there.
- **Agents**: the daemon is an MCP server at `https://pocketcloud.<domain>/mcp`, through the VPN only. A token from
  Settings → Agents lets Claude Code on your laptop list apps, read logs, change compose files, secrets and routes,
  and deploy, with every action in the audit log ([docs/agents.md](docs/agents.md)).
- **Recovery**: lost every device? Hetzner's rescue system and `pocketcloud recover` with the 24 words give you a
  new device and, if needed, a new password. Lost the server? Setup again with the same phrase, then restore.
  Done with it? *Tear down* under Settings → Account, proven by the phrase, removes apps, keys and optionally the
  server and DNS records.

Guides: [docs/setup.md](docs/setup.md), [docs/apps.md](docs/apps.md), [docs/agents.md](docs/agents.md),
[docs/operations.md](docs/operations.md), [docs/troubleshooting.md](docs/troubleshooting.md), [docs/security.md](docs/security.md).

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/timokoenig/pocketcloud/main/scripts/install.sh | sh -s -- mycloud
```

This downloads the latest release for your machine (macOS on Apple silicon, Linux x86_64 or arm64), checks its
checksum and runs `pocketcloud setup mycloud`. The binary is deleted afterwards. To build it yourself instead:

```sh
cargo build --release                      # the local binary (macOS)
scripts/build-linux.sh                     # the server binaries, in a podman container → dist/
target/release/pocketcloud setup mycloud --server-binary dist/pocketcloud-aarch64-unknown-linux-musl --caddy-binary dist/caddy-aarch64-unknown-linux-musl
```

Setup asks for the Hetzner token, domains, server type and the interface login, shows the recovery phrase once,
creates the server, installs everything, waits until your WireGuard tunnel works and only then closes public SSH.
The DNS zone can be at Hetzner DNS, where setup writes the records itself, or at any other provider, where setup
prints them and checks them once you have created them.
Afterwards open `https://pocketcloud.<domain>` with the tunnel active.

Without `--server-binary`, setup downloads the release matching its own version from GitHub.

## Commands

| command | where | what |
|---|---|---|
| `pocketcloud setup <name>` | your machine | create and enroll a server; re-run to continue after an interruption |
| `pocketcloud recover --root /mnt` | Hetzner rescue system | with the 24 words: a new VPN device, optionally a new password |
| `pocketcloud restic-password` | anywhere | the restic password from the 24 words, for a restore with plain restic |
| `pocketcloud server upgrade\|backup\|restore\|renew\|vpn-add\|ssh-finish\|notify-test\|passwd` | the server | what the interface does, from a shell |
| `pocketcloud server [run\|apply\|firewall\|passwd <user>]` | server | the daemon (systemd runs `server`) |

Nothing of the server stays on your computer after setup: the installer deletes its run directory. Keep the
recovery phrase.

## Development

```sh
cargo test
cargo run -- server --config dev/config.toml     # dev = true: no docker, nftables, wireguard, caddy or acme calls
```

A dev config needs `dev = true`, a `master_key_file` with 64 hex characters and a `bootstrap_user` with a hash from
`pocketcloud hash-password <pw>`. The interface then listens on `http://127.0.0.1:7788`.

## Releases

Releases are cut from GitHub Actions: run the *release* workflow and choose `patch`, `minor` or `major`. It bumps
the version in `Cargo.toml` and `Cargo.lock`, commits and tags `v<version>`, creates the release and attaches the
Linux server binaries, the Caddy builds with Coraza and the macOS binary, each with a `.sha256` file. The
version in the binary is what setup downloads by and what the Server page compares against, so never tag by hand.
