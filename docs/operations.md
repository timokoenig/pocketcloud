# Operations

## VPN

Devices are managed under *Settings → VPN devices*. Creating one shows the WireGuard config and a QR code exactly once; the private
key is generated on the server and not stored. Revoking a device closes its tunnel immediately. The last device
cannot be removed from the interface.

The device from setup got its config at the end of setup; further devices come from Settings → VPN devices as files or QR codes.

While the tunnel is active all DNS of the device goes through the server, which answers internal names with
`10.8.0.1` and forwards everything else to Hetzner's resolvers.

## SSH

```sh
ssh admin@10.8.0.1
```

with the tunnel active and a key you added under Settings → SSH keys. Without any key there, nobody
can log in, which is the state right after setup.

## Monitoring and alerts

Open and resolved alerts, with the host metrics of the last day, are on the *Alerts* page; what to send and
where is under *Settings → Notifications*.

The daemon watches the server itself; nothing else runs for it. Collectors: facts from the journal (ssh logins
and failures, fail2ban bans, sudo, OOM kills, kernel errors, failed units, Caddy's WAF blocks and 5xx answers),
auditd's syscall records with our keys, Falco's events, Docker events (containers dying, out of memory,
unhealthy), and a one-minute sample of cpu, memory, swap, disk, inodes, pressure and clock sync. Events are
kept 14 days, metrics 48 hours; both are on the *Alerts* page (events on its *Events* tab).

Fixed checks run every minute and open alerts with a hold time so a blip is not a page: capacity thresholds,
services and the Docker API, reboot pending, backups, certificates, failed deploys, AIDE findings, ssh brute
force, ban waves, OOM kills, kernel errors, failed units, sensitive file changes, Falco by priority, WAF spikes,
5xx bursts, containers dying, restart loops. Thresholds are editable under *Settings → Notifications*. Info-level alerts
(a newer release, a reboot happened) show but do not notify.

Notifications are configured under *Settings → Notifications* (e-mail over SMTP, a webhook, the heartbeat URL), stored
sealed with the master key. A `[notify]` section in the config file seeds them on first start, nothing more. Opened and resolved alerts are collected for a minute and sent as one message with the worst thing in
the subject. `heartbeat_url` is pinged every five minutes while the daemon runs, for a dead man's switch service
(healthchecks.io style) that tells you when the server itself is gone, the one thing it cannot report.
*Send test notification* under Settings → Notifications and `sudo pocketcloud server notify-test` prove the channels.

Live-state checks catch "up but not what the database says": every route of a running app is fetched through
Caddy once a minute and three failures in a row alert; listening sockets outside the expected set alert;
containers started outside pocketcloud alert; the configuration is re-applied every ten minutes and an error
doing so alerts. The monitoring watches itself too: a silent journal collector, auditd not enabled, an AIDE
check that failed or has not run for 36 hours, and failing deliveries all open alerts.

What gets sent: criticals always; warnings by default (*Settings → Notifications* can restrict mail to criticals); infos never,
with two exceptions you can switch: security-relevant interface actions (a new or revoked VPN device, registry
credentials, a WAF switched off, an app removed, a restore; on by default) and ssh logins (off by default).
Internet background noise (WAF blocks, bans, ssh brute force) is info and stays in the interface; fail2ban deals
with it. Point events (a login, a file change, a Falco event, a failed job) are told once and close silently;
conditions (disk, a route down) announce their end. The same alert is sent at most once an hour unless it
escalates to critical, so a flapping condition cannot flood the inbox.

Delivery is retried every minute until it works (capped at 200 changes); after three failures in a row the
heartbeat is sent as `/fail`. The heartbeat itself is withheld while the checks error, the journal collector has
seen nothing for 30 minutes, or deliveries fail, so it means "monitoring works", not just "process alive". With a
webhook configured, security events are also streamed to it once a minute as they are stored, which leaves an
off-box copy an intruder cannot clean.

AIDE findings after package updates (unattended-upgrades, *Install updates* on the Server page) refresh the baseline automatically
and only inform; findings without a package change in between stay a warning until you re-baseline. Pending
packages from third-party repositories (Docker, Caddy, Falco, Trivy) are not installed by unattended-upgrades and
open a warning until *Install updates* on the Server page.

Falco is the Falco package with the eBPF probe, writing JSON events to `/var/log/infra/falco.jsonl`; the
switch under Server → Security starts or stops its service within a minute. It costs about 150 MB.

## What an upgrade applies

*Upgrade* on the Server page downloads the release (newest, or a version you type), verifies the published
checksums, runs the installer again and restarts the daemon; `sudo pocketcloud server upgrade` does the same from
a shell, `--from-dir` with binaries you put there. The installer is idempotent and owns all server configuration: host hardening (sshd, sysctl,
fail2ban, unattended-upgrades, journald), Docker's daemon.json, Caddy's unit and binary, auditd rules, the AIDE
configuration, logrotate and the systemd units. Files are replaced when they differ; sshd changes are validated
with `sshd -t` and rolled back if invalid. The daemon then migrates the database schema and regenerates nftables,
WireGuard and the Caddy configuration from its state, so nothing depends on what an earlier version wrote. Only
cloud-init (user, ssh key, bootstrap firewall) runs once, at first boot. Each installer run is noted in
`/var/log/pocketcloud/installs.log`.

## Backups

Opt-in per installation, under Server → Backups: enter the Hetzner Object Storage endpoint, bucket and S3 keys
there; *Disable* switches them off again. Settings are stored sealed with the master key. Storage is Hetzner Object Storage (S3) through restic; the repository is
encrypted with a password derived from the master key, so the recovery phrase plus the bucket credentials restore
everything. Nightly at 03:30 server time; every snapshot is kept for 30 days and deleted after that, integrity check on
Sundays.

In the backup set: the pocketcloud database (consistent copy), the server config, and for every app with its
*backup* switch on: the volumes, the `files` directory, and a `pg_dumpall` or `mysqldump` of every running
postgres, mysql or mariadb service. Apps with their own backup scheme switch it off on their page. Never in the
set: the master key.

The Backups tab of the Server page shows the last run, snapshot count, size and last check, with a *Back up now* button; the
dashboard warns after a failed run or two days without success. On the server, `sudo pocketcloud server backup`
runs the same job from a shell and waits for it; `sudo pocketcloud server restore <app> latest` does the same
for an app's data restore, for the day the interface is down. Hetzner Object Storage occasionally answers a request with a
spurious "Access Denied"; restic calls are retried three times for that.

Restore by hand, from any machine with restic:

```
pocketcloud restic-password               # asks for the recovery phrase, prints RESTIC_PASSWORD
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
restic snapshots
restic restore latest --target /tmp/restore --include /var/lib/docker/volumes/<volume>
```

Restore in the interface:

- **One app**: *Restore from a snapshot* under *Backup* on the app's *Configuration* tab, pick a snapshot, type
  the app name. The app is
  stopped, its volumes and `files` are replaced by the snapshot's, database dumps are replayed into the database
  services (started first, alone), then everything starts. Current data is overwritten.
- **A rebuilt server**: run `pocketcloud setup <newname>` and answer *yes* to reusing the recovery phrase of the
  old installation, so the new server has the same master key. Enter the same bucket under Server → Backups, press
  *Refresh snapshots*, then *Restore apps from a
  snapshot*: every app of the snapshot that does not exist yet is imported with compose file, routes, secrets and
  settings, deployed, and its data restored. The job log tells per app what happened. Devices, users and VPN
  peers are not imported; they belong to the new server.

The snapshot list on the pages is refreshed after each backup and by the button.

Note: the server holds credentials that can delete snapshots, since it prunes them. Keep that in mind when
choosing the bucket's project.

## Teardown

*Tear down this server* at the bottom of the Server page ends an installation. It asks for the recovery phrase,
which is the proof of ownership (the master key never leaves the server, so only its owner can produce it), and
the installation name. Then, as a job you can watch until the tunnel drops: a critical notification goes out
first; every app is removed with its volumes; with a Hetzner DNS token the records setup wrote (the domain and
wildcard, `acme-ns`, the `_acme-challenge` delegation, the CAA record) are deleted, as far as they still point at
this server; with a Hetzner Cloud token the firewall and ssh key are deleted and, last of all, the server itself.
Independent of the tokens, a transient unit outside the daemon's sandbox then shreds the master key, deletes
`/etc/pocketcloud`, `/var/lib/pocketcloud`, the WireGuard and Caddy configuration, and powers the machine off.

Tokens are used once in memory and never stored; revoke them afterwards. Without them, delete the powered-off
server and the DNS records in the Hetzner console; the disk holds nothing usable. Backup snapshots stay in the
bucket, and the recovery phrase plus the bucket credentials still restore them into a new installation.

## What lives on your laptop

Nothing. Setup deletes its run directory when it completes. The CLI on your computer is only needed to set up a
server or, from Hetzner's rescue system, to recover one. Keep the recovery phrase.

## DNS

Certificates renew inside the daemon, which also runs the challenge nameserver; *Renew now* on the Server page
and `sudo pocketcloud server renew` only ask it to.

The real zone is written once, by setup. The server answers `_acme-challenge.<domain>` itself for certificate
renewals and holds no DNS token. A rebuilt server gets its records from the setup that builds it.

## Updates

- Setup installs every pending package before the daemon starts and reboots once if the kernel changed.
- OS security updates install themselves daily (unattended-upgrades). Reboots never happen on their own; the
  dashboard and the server page say when one is needed and the server page has the button. Apps come back on their
  own after a reboot.
- *Check* on the Server page lists all pending packages, *Install updates* installs them. The upgrade runs as a transient
  systemd unit (`pocketcloud-apt-<time>`) outside the daemon's sandbox; a failed run can be retried, it finishes the
  interrupted dpkg step first.
- Pocketcloud itself: *Upgrade* on the Server page, see "What an upgrade applies". Running apps are not touched.
  A development build goes in through the upload field on the same page, or `scripts/push-dev.sh`.

## Certificates

Renewed automatically 30 days before expiry, checked every six hours. The server page shows expiry and the last
error. *Renew now* forces a new order.

## When something is wrong

- Server unresponsive: reboot it in the Hetzner console. The daemon brings apps, tunnel and firewall back.
- Every device lost: Hetzner's rescue system and `pocketcloud recover`, see troubleshooting.md.
- Master key file lost or corrupt: rebuild through setup with the old phrase and restore from the backups.

## Firewall

`pocketcloud server firewall` on the server prints the nftables ruleset the daemon applies. Inbound on the public
interface: 22 (gated by the cloud firewall), 80, 443, the WireGuard port, ICMP. Forwarding: apps to the internet,
traffic inside one app network, full-scope VPN clients to apps. Everything else is dropped. Docker's own iptables
handling is off (`/etc/docker/daemon.json`), so a container can never publish a port behind the daemon's back.

## Audit

Every action in the interface is in *Alerts → Audit log*. On the host, auditd records privileged commands, changes under
`/etc/pocketcloud`, `/etc/wireguard`, `/etc/docker`, `/etc/caddy`, `/etc/ssh` and the usual identity files; the
Server → Security shows this week's summary. AIDE checks file integrity nightly at 04:30; the report is on the same tab.
After an intended system change (upgrade, new packages) the next report lists those files; refresh the baseline with
`sudo aide --update -c /etc/aide/aide.conf && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db`.

## Troubleshooting

Symptoms and their causes are collected in [troubleshooting.md](troubleshooting.md).
