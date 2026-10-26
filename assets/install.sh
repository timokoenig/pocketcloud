#!/bin/bash
# Runs as root on the server, once by setup and again on upgrades. Idempotent.
# Expects /opt/pocketcloud/stage/ with: pocketcloud (binary), config.toml, master.key, units/*.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
STAGE=/opt/pocketcloud/stage
log() { echo "install: $*"; }

log "packages"
apt-get update -qq
# first install: start from a fully updated system. Later runs (pocketcloud upgrade) leave the OS alone.
if [[ ! -x /usr/local/bin/pocketcloud ]]; then
  log "upgrading every package (a few minutes)"
  apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade >/dev/null
  apt-get -y -qq autoremove >/dev/null
fi
apt-get install -y -qq ca-certificates curl gnupg nftables fail2ban unattended-upgrades auditd aide aide-common wireguard-tools jq restic rsync debian-keyring debian-archive-keyring apt-transport-https >/dev/null

if ! command -v docker >/dev/null; then
  log "docker engine"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
fi
# pocketcloud owns the firewall; docker must not touch iptables. userland-proxy off: nothing is published anyway.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "iptables": false,
  "ip6tables": false,
  "userland-proxy": false,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "no-new-privileges": true,
  "default-address-pools": [{"base": "172.31.0.0/16", "size": 24}]
}
JSON
systemctl enable docker >/dev/null 2>&1
systemctl restart docker

if ! command -v caddy >/dev/null; then
  log "caddy"
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
fi
if ! command -v trivy >/dev/null; then
  log "trivy"
  curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg --yes
  echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
  apt-get update -qq
  apt-get install -y -qq trivy >/dev/null
fi

# Caddy with the Coraza WAF: the packaged binary stays as fallback (official custom-build procedure)
if [[ -f "$STAGE/caddy" ]]; then
  log "caddy with coraza"
  if ! dpkg-divert --list /usr/bin/caddy | grep -q caddy.default; then
    dpkg-divert --divert /usr/bin/caddy.default --rename /usr/bin/caddy
  fi
  install -m 0755 "$STAGE/caddy" /usr/bin/caddy.custom
  update-alternatives --quiet --install /usr/bin/caddy caddy /usr/bin/caddy.default 10
  update-alternatives --quiet --install /usr/bin/caddy caddy /usr/bin/caddy.custom 50
  update-alternatives --quiet --set caddy /usr/bin/caddy.custom
  /usr/bin/caddy list-modules | grep -q '^http.handlers.waf$' || { echo "caddy binary has no waf module" >&2; exit 1; }
fi
# caddy keeps the last config the daemon pushed and resumes it after a restart
mkdir -p /etc/caddy
cat > /etc/caddy/caddy.json <<'JSON'
{"admin": {"listen": "127.0.0.1:2019", "config": {"persist": true}}}
JSON
mkdir -p /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/pocketcloud.conf <<'UNIT'
[Unit]
After=wg-quick@wg0.service
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/caddy.json --resume
ExecReload=
ExecReload=/usr/bin/caddy reload --config /etc/caddy/caddy.json --force
# caddy runs as root here: it binds the WireGuard address and reads the daemon's certificate files
User=root
Group=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
UNIT

install -d -m 0700 /etc/pocketcloud /var/lib/pocketcloud /var/log/pocketcloud
# Host hardening, re-applied on every run so changes reach existing servers. Files are only replaced when they differ.
log "hardening"
put() { if ! cmp -s "$1" "$2"; then install -m "$3" "$1" "$2"; return 0; fi; return 1; }
SSH_USER="${SUDO_USER:-}"
if [[ -z "$SSH_USER" || "$SSH_USER" == root ]]; then
  SSH_USER=$(sed -n 's/^AllowUsers //p' /etc/ssh/sshd_config.d/00-hardening.conf 2>/dev/null | head -1)
fi
if [[ -n "$SSH_USER" ]]; then
  sed "s/\${SSH_USER}/$SSH_USER/" "$STAGE/hardening/sshd.conf" > "$STAGE/hardening/sshd.rendered"
else
  grep -v '^AllowUsers' "$STAGE/hardening/sshd.conf" > "$STAGE/hardening/sshd.rendered"
fi
SSHD_CONF=/etc/ssh/sshd_config.d/00-hardening.conf
if ! cmp -s "$STAGE/hardening/sshd.rendered" "$SSHD_CONF"; then
  [[ -f "$SSHD_CONF" ]] && cp -p "$SSHD_CONF" "$STAGE/hardening/sshd.previous"
  install -m 0644 "$STAGE/hardening/sshd.rendered" "$SSHD_CONF"
  if sshd -t 2>"$STAGE/hardening/sshd.err"; then
    systemctl restart ssh
  else
    cat "$STAGE/hardening/sshd.err" >&2
    if [[ -f "$STAGE/hardening/sshd.previous" ]]; then install -m 0644 "$STAGE/hardening/sshd.previous" "$SSHD_CONF"; else rm -f "$SSHD_CONF"; fi
    echo "sshd rejected the new configuration; kept the old one" >&2
    exit 1
  fi
fi
put "$STAGE/hardening/sysctl.conf" /etc/sysctl.d/90-hardening.conf 0644 && sysctl --system >/dev/null
put "$STAGE/hardening/fail2ban-waf.conf" /etc/fail2ban/filter.d/pocketcloud-waf.conf 0644 || true
put "$STAGE/hardening/fail2ban.local" /etc/fail2ban/jail.local 0644 || true
put "$STAGE/hardening/apt-unattended.conf" /etc/apt/apt.conf.d/52unattended-upgrades-local 0644 || true
install -d /etc/systemd/journald.conf.d
put "$STAGE/hardening/journald.conf" /etc/systemd/journald.conf.d/persist.conf 0644 && systemctl restart systemd-journald
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $("$STAGE/pocketcloud" --version 2>/dev/null || echo unknown)" >> /var/log/pocketcloud/installs.log 2>/dev/null || true

log "pocketcloud files"
install -m 0755 "$STAGE/pocketcloud" /usr/local/bin/pocketcloud.new
mv -f /usr/local/bin/pocketcloud.new /usr/local/bin/pocketcloud
[[ -f "$STAGE/config.toml" ]] && install -m 0600 "$STAGE/config.toml" /etc/pocketcloud/config.toml
# older configs carried the cloud token; the server only needs zone access
if grep -q '^token = ' /etc/pocketcloud/config.toml 2>/dev/null; then
  python3 - /etc/pocketcloud/config.toml <<'EOF'
import re, sys
p = sys.argv[1]; s = open(p).read()
m = re.search(r'^token = (".*")$', s, re.M); d = re.search(r'^dns_token = "(.*)"$', s, re.M)
if m:
    if d is None or d.group(1) == "":
        s = re.sub(r'^dns_token = "".*\n', '', s, flags=re.M)
        s = s.replace(m.group(0), "dns_token = " + m.group(1), 1)
    else:
        s = s.replace(m.group(0) + "\n", "", 1)
    s = re.sub(r'^(server_id|firewall_id) = .*\n', '', s, flags=re.M)
    open(p, "w").write(s)
EOF
  log "removed the cloud token from the server config"
fi
[[ -f "$STAGE/master.key" ]] && install -m 0600 "$STAGE/master.key" /etc/pocketcloud/master.key
install -m 0644 "$STAGE/units/pocketcloud.service" /etc/systemd/system/
install -m 0644 "$STAGE/units/pocketcloud-aide.service" "$STAGE/units/pocketcloud-aide.timer" /etc/systemd/system/
install -m 0640 "$STAGE/audit.rules" /etc/audit/rules.d/pocketcloud.rules
install -m 0644 "$STAGE/aide.conf" /etc/aide/aide.conf.d/99-pocketcloud
install -m 0644 "$STAGE/logrotate" /etc/logrotate.d/pocketcloud

log "audit, aide, fail2ban"
augenrules --load >/dev/null 2>&1 || true
systemctl enable --now auditd fail2ban nftables >/dev/null 2>&1 || true
systemctl restart fail2ban || true
# first aide database in the background; the daily timer checks against it
if [[ ! -f /var/lib/aide/aide.db ]] && ! systemctl is-active --quiet pocketcloud-aide-init; then
  systemd-run --quiet --unit pocketcloud-aide-init -p Nice=19 \
    bash -c 'aide --init -c /etc/aide/aide.conf >/var/log/pocketcloud/aide-init.log 2>&1; mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db' || true
fi

log "daemon"
systemctl daemon-reload
systemctl enable pocketcloud pocketcloud-aide.timer >/dev/null 2>&1
systemctl restart caddy
systemctl restart pocketcloud
systemctl start pocketcloud-aide.timer
rm -rf "$STAGE"
sleep 2
systemctl is-active --quiet pocketcloud && log "pocketcloud is running" || { journalctl -u pocketcloud -n 30 --no-pager; exit 1; }
