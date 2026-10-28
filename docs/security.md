# Security model

## Perimeter

Four things are reachable from the internet: Caddy on 80/443, WireGuard on its UDP port, the challenge
nameserver on 53 (answers only `_acme-challenge.<domain>` and `acme-ns.<domain>`), and ICMP. The daemon
alerts on any other listening socket (Postfix, which AIDE's package brings along, is confined to loopback). SSH is reachable
only through the tunnel; the cloud firewall additionally drops it before it reaches the host, except while setup or
rescue opens it for one address. The interface is a route on the WireGuard listener only. The name resolves publicly
through the wildcard, but the public listener has no route for it. (`strict_sni_host` is off on the public listener:
apps share the address and the wildcard certificate, HTTP/2 clients reuse one connection across them, and iOS does not
retry the 421 Caddy would answer with.)

Public routes pass through a web application firewall before they reach the app: Coraza with the OWASP Core Rule
Set at the default paranoia level, compiled into the Caddy binary Pocketcloud installs (`scripts/build-caddy.sh`,
also a release asset). Request bodies are inspected up to 13 MB, larger ones are rejected; response bodies are
not inspected. A blocked request gets a 403 and shows up under Server → Security. The WAF is on for every new public
route and can be switched off per route for apps that trigger false positives. PUT, PATCH and DELETE are allowed
next to the CRS defaults (GET, HEAD, POST, OPTIONS), which would block every REST API. Internal routes and the interface
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

The server holds no Hetzner credential, and neither does your computer after setup: the tokens are used during
the install and then forgotten. The one later exception is the teardown, where you may paste tokens into the
form so the job can delete the DNS records and the server; they live in the job's memory for its few seconds,
are redacted from its log, and die with the server. Certificates still use the DNS-01 challenge, but the challenge name is delegated
to the server: setup writes `_acme-challenge.<domain> NS acme-ns.<domain>` and `acme-ns.<domain> A/AAAA <server>`
into the real zone once, and the daemon answers `_acme-challenge.<domain>` TXT queries itself on port 53 (rate
limited, every other name refused). A root compromise can therefore forge certificates for the domain, which it
already holds, and nothing else: MX, A and every other record of the real zone are out of reach. The A, AAAA
and CAA records are written by setup.

## Teardown

The interface can tear the installation down, but only with the recovery phrase typed in: a stolen session or
password cannot destroy the server. A wrong phrase is audited and answered after a delay.

## Detection

auditd records changes to identity, sudoers, sshd, ssh keys, firewall, WireGuard, cron, systemd, Docker, Caddy
and Pocketcloud files; the daemon records failed logins and failed agent tokens; Falco watches syscalls for shells in containers, sensitive file reads, unexpected network
activity and privilege escalation; the daemon turns both, plus the journal and Docker events, into alerts and
mails them. See operations.md, Monitoring and alerts.

## Backups

Off unless enabled. restic encrypts everything client-side with a password derived from the master key; the
bucket operator sees only ciphertext. The master key is never part of a backup. The S3 credentials are stored
sealed in the database and can delete snapshots; a bucket in a project of its own limits the blast radius.

## Secrets

- Master key: 256 bit, generated on your machine, shown once as a BIP39 phrase, uploaded to the server, never
  stored locally. Everything secret in the database (app secrets, registry tokens, WireGuard preshared keys) is
  sealed with XChaCha20-Poly1305 under it.
- At deploy time an app's secrets are written as an env file on tmpfs, root only, and attached to that app's
  containers only. Other apps never see them. Compose interpolation reads the same file.
- Job logs and container logs are redacted for known secret values before display.
- The interface never returns a secret value after it was saved.
- The WireGuard hub key lives in `/etc/pocketcloud/config.toml`, root only; the master key in
  `/etc/pocketcloud/master.key`. A root compromise of the host exposes everything the host needs to run;
  encryption at rest is not a defense against that.
- After setup nothing of the server is on your computer; the roots of trust are the recovery phrase, your
  VPN devices with the interface password, and the Hetzner account login (rescue mode). Put two-factor
  authentication on the Hetzner account. A device's WireGuard config holds its private key; protect the device
  accordingly, FileVault is assumed.

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

## Agents

`/mcp` on the interface host is the machine door: the same VPN-only listener, bearer tokens instead of the
cookie. Tokens are created under Settings → Agents, shown once and stored as a SHA-256 hash; a request with a
missing or unknown token is answered 401 after a delay and recorded (`agent.auth_failed` in the audit log, an
`agent_auth_failed` event). Two scopes: `read` sees apps, logs, jobs and the server, `deploy` also changes compose
files, secrets, routes and internet access and deploys, starts and stops. No token removes an app, restores,
changes backups, upgrades or reboots, or touches VPN devices, ssh keys, registries, notifications or the account.
Agent changes pass through the same validation as the interface and are audited as `agent:<name>`. Secret values
are never returned; container and job logs are redacted as in the interface. A leaked token is worth exactly its
scope on the VPN, and nothing off it; revoke it on the same page. The endpoint answers only for the interface
host (and the listen address in dev mode); any other `Host` is refused with 403, which keeps a DNS-rebinding page in
a browser from reaching it.

## Host

The cloud-init and installer apply the same hardening as the k3s template: hardened sshd ciphers and limits, sysctl
hardening, fail2ban in aggressive mode, unattended security upgrades, auditd rules on identity and privileged
execution, AIDE with a nightly check, persistent journald. The daemon runs as root (it drives Docker, nftables and
WireGuard) under systemd confinement: no new privileges, protected home, kernel tunables, logs and cgroups.

## Known gaps in v1

No two-factor login beyond the VPN (failed logins are rate-limited per address and alerted). Release binaries are verified against the
published sha256 sums, not signatures (or you build and upload them yourself). Caddy runs as root to bind the WireGuard address
and read the certificate files. The daemon does not rotate the master key yet.
