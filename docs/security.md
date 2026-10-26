# Security model

## Perimeter

Four things are reachable from the internet: Caddy on 80/443, WireGuard on its UDP port, the challenge
nameserver on 53 (answers only `_acme-challenge.<domain>` and `acme-ns.<domain>`), and ICMP. The daemon
alerts on any other listening socket (Postfix, which AIDE's package brings along, is confined to loopback). SSH is reachable
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

Responses of public routes carry HSTS, `X-Content-Type-Options: nosniff`, a referrer policy and `X-Frame-Options:
SAMEORIGIN` unless switched off for the route. Clients that trip the WAF ten times in ten minutes are banned at
the firewall for an hour by fail2ban, as are ssh brute-force attempts. The public listener writes JSON access
logs to the journal (visitor addresses included; the journal keeps at most 1 GB). A CAA record limits certificate
issuance for each domain to Let's Encrypt.

Compose files are validated: no host paths, no top-level volume `driver_opts`/`external`/`name`, no
`volumes_from`, `extends`, `privileged`, capabilities, devices, host namespaces, sysctls, and `security_opt`
may only add `no-new-privileges`. Every container gets `no-new-privileges` and its own network.

Inside the tunnel, scope `web` devices reach `10.8.0.1:443` and DNS; `full` devices also SSH and the app networks.
Both are enforced in nftables on the server, not just in the client's allowed IPs.

Apps reach the internet through NAT; per app that can be cut to nothing or to a list of TCP ports. Apps never
reach each other or the host's services except through routes.

## Hetzner tokens

The server holds no Hetzner credential. Both tokens, cloud and DNS, stay on the laptop in
`~/.config/pocketcloud/<name>/`. Certificates still use the DNS-01 challenge, but the challenge name is delegated
to the server: setup writes `_acme-challenge.<domain> NS acme-ns.<domain>` and `acme-ns.<domain> A/AAAA <server>`
into the real zone once, and the daemon answers `_acme-challenge.<domain>` TXT queries itself on port 53 (rate
limited, every other name refused). A root compromise can therefore forge certificates for the domain, which it
already holds, and nothing else: MX, A and every other record of the real zone are out of reach. The A, AAAA
and CAA records are written by setup and `pocketcloud dns <name>`.

## Detection

auditd records changes to identity, sudoers, sshd, ssh keys, firewall, WireGuard, cron, systemd, Docker, Caddy
and Pocketcloud files; Falco watches syscalls for shells in containers, sensitive file reads, unexpected network
activity and privilege escalation; the daemon turns both, plus the journal and Docker events, into alerts and
mails them. See operations.md, Monitoring and alerts.

## Backups

Off unless enabled. restic encrypts everything client-side with a password derived from the master key; the
bucket operator sees only ciphertext. The master key is never part of a backup. The S3 credentials sit in the
server config (root only) and can delete snapshots; a bucket in a project of its own limits the blast radius.

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

No two-factor login beyond the VPN (failed logins are rate-limited per address and alerted). No signature verification of the binary the installer uploads
(you build it, or it comes from the GitHub release you chose). Caddy runs as root to bind the WireGuard address
and read the certificate files. The daemon does not rotate the master key yet.
