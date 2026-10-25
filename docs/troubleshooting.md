# Troubleshooting

Start with `pocketcloud rescue <name> status`. It shows Hetzner's view of the server, whether public SSH is open in
the cloud firewall, what answers on the public and the VPN address, and the state of the services when the tunnel
works. Public SSH is closed after setup; `pocketcloud rescue <name> open-ssh` opens it for your current address.

## The tunnel connects, but the interface name does not resolve

Symptom: WireGuard shows a handshake and traffic both ways, `dig @10.8.0.1 pocketcloud.<domain>` answers
`10.8.0.1`, but the browser and `curl` time out resolving the name. Other names resolve fine.

Cause: macOS consults per-domain resolvers before anything else. A file `/etc/resolver/<domain>` (often left behind
by another project that used the same domain, for example a cluster whose internal DNS lived on a private
address) sends every query for that domain to a nameserver that no longer exists. `scutil --dns` lists it as a
resolver with `domain : <your domain>`.

```sh
ls /etc/resolver/
scutil --dns | grep -B2 -A4 '<domain>'
sudo rm /etc/resolver/<domain>
```

No restart is needed. The tunnel's DNS (`10.8.0.1`) then answers internal names and forwards the rest.

## WireGuard shows data sent but nothing received

The handshake does not complete, so the server side is not accepting the peer.

- `pocketcloud rescue <name> status`: is the server running, is `wg-quick@wg0` active?
- With public SSH open (`open-ssh`), on the server: `sudo wg show` must list your device's public key and
  `sudo journalctl -u pocketcloud -n 50`. If the log shows the daemon retrying something at startup, it never got
  as far as writing `/etc/wireguard/wg0.conf`; fix the cause (usually a config value or an API change) and
  `sudo systemctl restart pocketcloud`.
- The cloud firewall must allow the WireGuard UDP port; `status` prints the rule count, four rules without SSH.
- Your device's config must carry the server's public address as endpoint. `pocketcloud vpn <name>` prints it.

## While the tunnel is up, nothing on the Mac resolves

The tunnel's config sets `DNS = 10.8.0.1`. When the tunnel is active but the server's resolver is down (daemon not
running, or the previous problem), the Mac has no working DNS at all; even `brew` and `podman pull` fail. Deactivate
the tunnel while you fix the server, or use `pocketcloud rescue` which only needs the Hetzner API.

## Browser warns about the certificate

- Right after setup: the first certificate takes a few minutes (DNS records, nameserver propagation, Let's
  Encrypt). The server page shows the state and the last error; `sudo journalctl -u pocketcloud | grep acme` on
  the server has the details.
- Issuer contains `(STAGING)`: setup was answered with the staging environment. Change `environment = "staging"` to
  `"production"` in `/etc/pocketcloud/config.toml`, remove `/var/lib/pocketcloud/acme/account.json` and
  `/var/lib/pocketcloud/certs/<domain>/fullchain.pem`, then `sudo systemctl restart pocketcloud`.
- `acme: ... challenge record did not appear`: the DNS token has no access to the zone, or the zone is in another
  project than the one whose token was given. `dns_token` in the config must belong to the project holding the zone.

## Setup stopped half way

Run the same `pocketcloud setup <name>` again; it continues at the step that failed. Resources that exist already
(SSH key, firewall, server) are reused by name, nothing is created twice. If the installer step runs again in a
later run, setup asks for the recovery phrase: the master key only lives in memory during the run that created it.
Enter the 24 words separated by spaces; numbers and line breaks from the printed list are ignored.

## Setup fails with `decode response of POST /servers` or similar

The Hetzner API changed the shape of a response. Update Pocketcloud. The server that was being created exists and
is reused on the next run.

## The daemon runs but apps, routes or certificates are not applied

`sudo journalctl -u pocketcloud -n 100` on the server. The reconcile step writes nftables, WireGuard and the Caddy
config in that order and stops at the first error; a message naming `nft`, `wg` or `caddy rejected the config`
points at the culprit. `pocketcloud server firewall` prints the ruleset it would apply, `sudo nft -c -f
/etc/nftables.conf.new` checks it.

## Upgrade fails with `error setting permissions of './usr/bin/su': Operation not permitted`

The daemon runs in a systemd sandbox that, among other things, forbids creating setuid files. Pocketcloud
versions before 2026-10-25 ran apt inside that sandbox, so dpkg failed as soon as it touched `su` or `sudo`, and
left the package database half done. Newer versions start apt as a transient unit outside the sandbox.

1. Install the current build: `pocketcloud upgrade <name> --server-binary dist/pocketcloud-<arch>-unknown-linux-musl`.
2. Run *Server → Upgrade* again. It finishes the interrupted dpkg step first, then installs the rest.

To repair by hand instead: `pocketcloud rescue <name> ssh`, then `sudo dpkg --configure -a` and
`sudo apt-get -f install`.

## A request to an app gets a 403 it should not

The WAF blocked it. The server page lists blocked requests with client, request and transaction id; the matching
rule is in Caddy's log (`journalctl -u caddy -g <id>`). Switch the WAF off for that route on the app page if the app legitimately sends what the
rule flags (raw SQL in a form, large JSON bodies over 13 MB, unusual headers).

## The server page says the WAF is unavailable

The installed Caddy is the stock package without the Coraza module; public routes run without the WAF.
`pocketcloud upgrade <name>` installs the bundled build. For a local build: `scripts/build-caddy.sh` and
`--caddy-binary dist/caddy-<arch>-unknown-linux-musl`.

## A deploy fails or rolls back

The job page shows the compose output. Usual causes: the image cannot be pulled (add the registry under
*Registries*, check the image name), a service never becomes healthy within three minutes (the healthcheck is
wrong, or the app rejects its configuration, often a secret in the wrong format), or a route points at a service
that is not in the file. When a service is unhealthy the job log ends with the container states and their last
log lines; the same logs are on the app page per service. The containers of a failed first deploy keep running
and restarting until the next deploy or a stop.

## Locked out: no tunnel, no public SSH

```sh
pocketcloud rescue <name> open-ssh      # port 22 for your current address, in the cloud firewall
pocketcloud rescue <name> ssh
pocketcloud rescue <name> close-ssh     # afterwards
```

If the server does not react at all, `pocketcloud rescue <name> reboot` or the Hetzner console. The daemon brings
WireGuard, the firewall, Caddy and every app back on its own after a boot.
