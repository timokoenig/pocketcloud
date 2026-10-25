# Operations

## VPN

Devices are managed under *VPN*. Creating one shows the WireGuard config and a QR code exactly once; the private
key is generated on the server and not stored. Revoking a device closes its tunnel immediately. The last device
cannot be removed from the interface.

The device from setup has its config in `~/.config/pocketcloud/<name>/`; `pocketcloud vpn <name> --qr` shows it.

While the tunnel is active all DNS of the device goes through the server, which answers internal names with
`10.8.0.1` and forwards everything else to Hetzner's resolvers.

## SSH

```sh
ssh -i ~/.config/pocketcloud/<name>/id_ed25519 admin@10.8.0.1
```

with the tunnel active. `pocketcloud rescue <name> ssh` does the same and falls back to the public address when
public SSH has been opened with `open-ssh`.

## What an upgrade applies

`pocketcloud upgrade <name>` uploads the new daemon, the Caddy build and every file under `assets/`, then runs the
installer again. The installer is idempotent and owns all server configuration: host hardening (sshd, sysctl,
fail2ban, unattended-upgrades, journald), Docker's daemon.json, Caddy's unit and binary, auditd rules, the AIDE
configuration, logrotate and the systemd units. Files are replaced when they differ; sshd changes are validated
with `sshd -t` and rolled back if invalid. The daemon then migrates the database schema and regenerates nftables,
WireGuard and the Caddy configuration from its state, so nothing depends on what an earlier version wrote. Only
cloud-init (user, ssh key, bootstrap firewall) runs once, at first boot. Each installer run is noted in
`/var/log/pocketcloud/installs.log`.

## Backups

Opt-in per installation: setup asks, `pocketcloud backup <name> enable` switches it on later, `disable` off.
Without it there is no backup UI at all. Storage is Hetzner Object Storage (S3) through restic; the repository is
encrypted with a password derived from the master key, so the recovery phrase plus the bucket credentials restore
everything. Nightly at 03:30 server time; every snapshot is kept for 30 days and deleted after that, integrity check on
Sundays.

In the backup set: the pocketcloud database (consistent copy), the server config, and for every app with its
*backup* switch on: the volumes, the `files` directory, and a `pg_dumpall` or `mysqldump` of every running
postgres, mysql or mariadb service. Apps with their own backup scheme switch it off on their page. Never in the
set: the master key.

The server page shows the last run, snapshot count, size and last check, with a *Back up now* button; the
dashboard warns after a failed run or two days without success. On the server, `sudo pocketcloud server backup`
runs the same job from a shell and waits for it. Hetzner Object Storage occasionally answers a request with a
spurious "Access Denied"; restic calls are retried three times for that.

Restore by hand, from any machine with restic:

```
pocketcloud backup <name> password        # asks for the recovery phrase, prints RESTIC_* exports
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
restic snapshots
restic restore latest --target /tmp/restore --include /var/lib/docker/volumes/<volume>
```

A restored volume goes back with the app stopped: copy the `_data` directory over the volume's, start the app.
A database dump is replayed into the running database service. An automated restore (per app, and a whole
server through setup) is the next step.

Note: the server holds credentials that can delete snapshots, since it prunes them. Keep that in mind when
choosing the bucket's project.

## Updates

- Setup installs every pending package before the daemon starts and reboots once if the kernel changed.
- OS security updates install themselves daily (unattended-upgrades). Reboots never happen on their own; the
  dashboard and the server page say when one is needed and the server page has the button. Apps come back on their
  own after a reboot.
- *Server → Check* lists all pending packages, *Upgrade* installs them. The upgrade runs as a transient
  systemd unit (`pocketcloud-apt-<time>`) outside the daemon's sandbox; a failed run can be retried, it finishes the
  interrupted dpkg step first.
- Pocketcloud itself: `pocketcloud upgrade <name> --server-binary dist/pocketcloud-<arch>-unknown-linux-musl`
  uploads the binary and units and restarts the daemon. Running apps are not touched. The upgrade also installs
  the bundled Caddy build with the WAF (`--caddy-binary dist/caddy-<arch>-unknown-linux-musl` for a local build,
  `--skip-caddy` to leave Caddy alone).

## Certificates

Renewed automatically 30 days before expiry, checked every six hours. The server page shows expiry and the last
error. *Renew now* forces a new order.

## When something is wrong

- `pocketcloud rescue <name> status`: Hetzner's view of the server, the cloud firewall, what answers on the public
  and the VPN address, and the state of the services when the tunnel works.
- Interface down but SSH over VPN works: `journalctl -u pocketcloud -n 100`, `systemctl restart pocketcloud`.
- Tunnel down: `pocketcloud rescue <name> open-ssh` opens port 22 for your current address in the cloud firewall,
  SSH to the public address, fix, `close-ssh`.
- Server unresponsive: `pocketcloud rescue <name> reboot`, or the Hetzner console.
- Master key lost (fresh disk, restored image without `/etc/pocketcloud/master.key`):
  `pocketcloud rescue <name> restore-key` with the recovery phrase.

## Firewall

`pocketcloud server firewall` on the server prints the nftables ruleset the daemon applies. Inbound on the public
interface: 22 (gated by the cloud firewall), 80, 443, the WireGuard port, ICMP. Forwarding: apps to the internet,
traffic inside one app network, full-scope VPN clients to apps. Everything else is dropped. Docker's own iptables
handling is off (`/etc/docker/daemon.json`), so a container can never publish a port behind the daemon's back.

## Audit

Every action in the interface is in *Audit*. On the host, auditd records privileged commands, changes under
`/etc/pocketcloud`, `/etc/wireguard`, `/etc/docker`, `/etc/caddy`, `/etc/ssh` and the usual identity files; the
server page shows this week's summary. AIDE checks file integrity nightly at 04:30; the report is on the server page.
After an intended system change (upgrade, new packages) the next report lists those files; refresh the baseline with
`sudo aide --update -c /etc/aide/aide.conf && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db`.

## Troubleshooting

Symptoms and their causes are collected in [troubleshooting.md](troubleshooting.md).
