# Security model

## Perimeter

Three things are reachable from the internet: Caddy on 80/443, WireGuard on its UDP port, and ICMP. SSH is reachable
only through the tunnel; the cloud firewall additionally drops it before it reaches the host, except while setup or
rescue opens it for one address. The interface is a route on the WireGuard listener only. The name resolves publicly
through the wildcard, but the public listener has no route for it and, with `strict_sni_host`, no certificate match
either.

Public routes pass through a web application firewall before they reach the app: Coraza with the OWASP Core Rule
Set at the default paranoia level, compiled into the Caddy binary Pocketcloud installs (`scripts/build-caddy.sh`,
also a release asset). Request bodies are inspected up to 13 MB, larger ones are rejected; response bodies are
not inspected. A blocked request gets a 403 and shows up on the server page. The WAF is on for every new public
route and can be switched off per route for apps that trigger false positives. Internal routes and the interface
are not behind it.

Inside the tunnel, scope `web` devices reach `10.8.0.1:443` and DNS; `full` devices also SSH and the app networks.
Both are enforced in nftables on the server, not just in the client's allowed IPs.

## Secrets

- Master key: 256 bit, generated on your machine, shown once as a BIP39 phrase, uploaded to the server, never
  stored locally. Everything secret in the database (app secrets, registry tokens, WireGuard preshared keys) is
  sealed with XChaCha20-Poly1305 under it.
- At deploy time an app's secrets are written as an env file on tmpfs, root only, and attached to that app's
  containers only. Other apps never see them. Compose interpolation reads the same file.
- Job logs and container logs are redacted for known secret values before display.
- The interface never returns a secret value after it was saved.
- Hetzner tokens and the WireGuard hub key live in `/etc/pocketcloud/config.toml`, root only. A root compromise of
  the host exposes everything the host needs to run; encryption at rest is not a defense against that.
- The local directory `~/.config/pocketcloud/<name>/` holds the Hetzner tokens, the SSH key and the first device's
  WireGuard key in plain files with mode 0600. Protect your machine accordingly; FileVault is assumed.

## Workloads

- No published ports, no builds, no bind mounts of host paths, no privileged containers, no extra capabilities,
  no host namespaces. `no-new-privileges` on every container.
- One bridge per app; traffic between apps is dropped in the forward chain. Containers cannot reach the host's
  services except through what the app itself exposes via routes.
- Docker's iptables integration is off; the daemon is the only thing writing firewall rules.
- Images and compose files are trusted input from you. Pocketcloud does not verify signatures.

## Interface

Password login with argon2id, sessions in SQLite, cookie `HttpOnly; Secure; SameSite=Strict`, 12 hour sessions.
Cross-origin writes are refused by checking `Origin` and `Sec-Fetch-Site`. Strict CSP, no external resources, no
inline scripts. All of this sits behind the VPN; the password is the second factor.

## Host

The cloud-init and installer apply the same hardening as the k3s template: hardened sshd ciphers and limits, sysctl
hardening, fail2ban in aggressive mode, unattended security upgrades, auditd rules on identity and privileged
execution, AIDE with a nightly check, persistent journald. The daemon runs as root (it drives Docker, nftables and
WireGuard) under systemd confinement: no new privileges, protected home, kernel tunables, logs and cgroups.

## Known gaps in v1

No backups. No two-factor login beyond the VPN. No signature verification of the binary the installer uploads
(you build it, or it comes from the GitHub release you chose). Caddy runs as root to bind the WireGuard address
and read the certificate files. The daemon does not rotate the master key yet.
