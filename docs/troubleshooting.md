# Troubleshooting

Start with the interface if the tunnel works: the dashboard, the Alerts page with its Events and Audit tabs, and the Server page with its Backups and Security tabs say
what is going on. Without the tunnel, the Hetzner console shows whether the server runs, and its rescue system is
the way in (see "Every device is gone"). ssh works over the VPN with a key added under Settings → SSH keys.

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

- Is the server running (Hetzner console)? Over ssh, if you have a key: `sudo wg show` must list your device's public key and
  `sudo journalctl -u pocketcloud -n 50`. If the log shows the daemon retrying something at startup, it never got
  as far as writing `/etc/wireguard/wg0.conf`; fix the cause (usually a config value or an API change) and
  `sudo systemctl restart pocketcloud`.
- The cloud firewall in the Hetzner console must allow the WireGuard UDP port.
- Your device's config must carry the server's public address as endpoint.

## While the tunnel is up, nothing on the Mac resolves

The tunnel's config sets `DNS = 10.8.0.1`. When the tunnel is active but the server's resolver is down (daemon not
running, or the previous problem), the Mac has no working DNS at all; even `brew` and `podman pull` fail. Deactivate
the tunnel while you fix the server, or use the Hetzner console.

## Browser warns about the certificate

- Right after setup: the first certificate takes a few minutes (DNS records, nameserver propagation, Let's
  Encrypt). The server page shows the state and the last error; `sudo journalctl -u pocketcloud | grep acme` on
  the server has the details.
- Issuer contains `(STAGING)`: setup was answered with the staging environment. Change `environment = "staging"` to
  `"production"` in `/etc/pocketcloud/config.toml`, remove `/var/lib/pocketcloud/acme/account.json` and
  `/var/lib/pocketcloud/certs/<domain>/fullchain.pem`, then `sudo systemctl restart pocketcloud`.
- `acme: ... challenge nameserver did not answer` or the order times out: the `_acme-challenge` delegation is
  missing or port 53 is closed, see "Certificates are not renewed" below.

## Setup stopped half way

Run the same `pocketcloud setup <name>` again; it continues at the step that failed. Resources that exist already
(SSH key, firewall, server) are reused by name, nothing is created twice. If the installer step runs again in a
later run, setup asks for the recovery phrase: the master key only lives in memory during the run that created it.
Enter the 24 words separated by spaces; numbers and line breaks from the printed list are ignored.

## A job ends with `authorized_keys: Read-only file system`

The daemon's systemd sandbox made every home directory invisible, so once ssh keys are managed from the
interface, writing `authorized_keys` failed and with it every configuration pass. Units installed since
2026-10-27 keep home read-only except for writing there. Upgrade pocketcloud from the Server page; the new
unit is part of the installer that comes with the release. Keys added in the interface before that upgrade are
written as soon as the new daemon starts.

## Setup fails with `Missing privilege separation directory: /run/sshd`

The installer validates its sshd configuration with `sshd -t` before restarting ssh, and that check needs
`/run/sshd`, which Ubuntu's socket-activated ssh only has while the service holds it open; right after the
package upgrade at the start of the install it can be gone. Installers since 2026-10-27 create the directory
first. With an older binary, run the same `pocketcloud setup <name>` again: it continues at the install step
and the directory exists again by then.

## Setup fails with `unsupported location for server type`

Hetzner does not sell every server type in every location, and its price list still names types a location no
longer offers (cpx11 in fsn1, for example). Setup lists only the types a location can actually create since
2026-10-27; an older binary offered everything with a price. The chosen type is part of the saved plan, so a
plain re-run would try it again: delete `~/.cache/pocketcloud/install-<name>/` and run setup again, choosing
another type or location. Nothing needs cleaning up in Hetzner; an ssh key or firewall that exists already is
reused by name.

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

1. Install the current build: *Upgrade* on the server page.
2. Press *Install updates* on the Server page again. It finishes the interrupted dpkg step first, then installs
   the rest.

To repair by hand instead: ssh in with a key added under Settings → SSH keys, then `sudo dpkg --configure -a` and
`sudo apt-get -f install`.

## Certificates are not renewed, the log says the challenge nameserver did not answer

Let's Encrypt asks `_acme-challenge.<domain>`, which must be delegated to the server. Check from anywhere:
`dig NS _acme-challenge.<domain>` must return `acme-ns.<domain>`, `dig A acme-ns.<domain>` the server's address,
and while an order is open `dig TXT _acme-challenge.<domain>` the challenge values. If the first two are wrong,
fix the records in the Hetzner console (setup writes them; a rebuild rewrites them). Port 53 must be open on the public address (the firewall rule is
"acme challenge nameserver").

## A request to an app gets a 403 it should not

The WAF blocked it. Server → Security lists blocked requests with client, request and transaction id; the matching
rule is in Caddy's log (`journalctl -u caddy -g <id>`). Switch the WAF off for that route on the app's *Overview* tab if the app legitimately sends what the
rule flags (raw SQL in a form, large JSON bodies over 13 MB, unusual headers).

## The Security tab says the WAF is unavailable

The installed Caddy is the stock package without the Coraza module; public routes run without the WAF.
*Upgrade* on the server page installs the bundled build. For a local build: `scripts/build-caddy.sh` and the
upload field on the server page, or `scripts/push-dev.sh <target> caddy`.

## An app cannot reach the internet

Check *Internet access* on the app's *Configuration* tab. With `none` or a port list, anything else is dropped by the firewall;
mail needs 587 or 465, webhooks 443. DNS is not affected.

## A deploy fails or rolls back

The job page shows the compose output. Usual causes: the image cannot be pulled (add the registry under
*Settings → Registries*, check the image name), a service never becomes healthy within three minutes (the healthcheck is
wrong, or the app rejects its configuration, often a secret in the wrong format), or a route points at a service
that is not in the file. When a service is unhealthy the job log ends with the container states and their last
log lines; the same logs are on the app's *Overview* tab per service. The containers of a failed first deploy keep running
and restarting until the next deploy or a stop.

## ssh over the VPN says "Connection refused"

Almost always the tunnel is off on this device: without it, 10.8.0.1 is routed to your local network and
something there refuses. Check the WireGuard app first. If the tunnel is up and the interface on 443 works but
22 is refused, fail2ban banned your VPN address; lift it under Server → Security, *Banned clients*. The VPN
range is excluded from bans since 2026-10-26, and the CLI checks reachability with a real ssh login rather than
a bare TCP connect, which the aggressive sshd jail can count as a failure.

## Every device is gone: no laptop, no phone, no tunnel config

Nothing on your devices is irreplaceable; the recovery phrase is. The way back:

1. In the Hetzner console, enable the rescue system for the server and reboot into it (the console shows the
   root password or uses your console ssh key). Mount the disk: `mount /dev/sda1 /mnt`.
2. Get the binary: it is on the disk, `/mnt/usr/local/bin/pocketcloud`. Run
   `/mnt/usr/local/bin/pocketcloud recover --root /mnt`. It asks for the 24 words and refuses anything else, then
   creates a new VPN device and prints its config and a QR code, and offers to reset the interface password.
3. `umount /mnt`, disable the rescue system in the console, reboot. Once pocketcloud has started, the new device
   connects and the interface is back.

Console access alone is not enough on purpose: without the phrase, `recover` does nothing. The same phrase is
what *Tear down* on the Server page asks for, see operations.md.

## Locked out: no tunnel, no ssh

Another device of yours still has the tunnel: use it, add a replacement device under Settings → VPN devices. No device at
all: "Every device is gone" above. If the server does not react at all, reboot it in the Hetzner console; the
daemon brings apps, tunnel and firewall back on its own.
