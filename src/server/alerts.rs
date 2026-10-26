//! Fixed checks over host samples, events and Pocketcloud's own state. Each check yields observations
//! (key, severity, summary, hold); the engine opens an alert when an observation held long enough,
//! resolves it when it is gone, and hands opened/resolved changes to the notifier in batches.
use anyhow::Result;
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use super::db;
use super::notify::{self, Change};
use super::state::Shared;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub disk_warn: f64,
    pub disk_crit: f64,
    pub inodes_warn: f64,
    pub mem_warn: f64,
    pub mem_crit: f64,
    pub cpu_warn: f64,
    pub swap_warn: f64,
    /// failed ssh logins from one address in 10 minutes
    pub ssh_failed: usize,
    /// WAF blocks from one address in 10 minutes
    pub waf_blocks: usize,
    /// 5xx answers of one host in 5 minutes
    pub http_5xx: usize,
    pub backup_stale_hours: i64,
    pub reboot_days: i64,
    pub cert_days: i64,
    /// mail every successful ssh login (one admin: every login is worth a line)
    pub notify_ssh_login: bool,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds { disk_warn: 85.0, disk_crit: 95.0, inodes_warn: 90.0, mem_warn: 10.0, mem_crit: 5.0, cpu_warn: 95.0, swap_warn: 50.0, ssh_failed: 3, waf_blocks: 50, http_5xx: 20, backup_stale_hours: 48, reboot_days: 2, cert_days: 7, notify_ssh_login: true }
    }
}

pub async fn thresholds(state: &Shared) -> Thresholds {
    db::kv_get(&state.db, "alerts.thresholds").await.ok().flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub async fn set_thresholds(state: &Shared, t: &Thresholds) -> Result<()> {
    db::kv_set(&state.db, "alerts.thresholds", &serde_json::to_string(t)?).await
}

pub struct Observation {
    pub key: String,
    pub severity: &'static str,
    pub summary: String,
    /// how long the condition must hold before the alert opens
    pub hold_s: u64,
    /// send it; info observations do not by default
    pub notify: bool,
    /// a point event (something happened), not a condition: closes silently, no "resolved" message
    pub event: bool,
}

fn obs(key: impl Into<String>, severity: &'static str, summary: impl Into<String>, hold_s: u64) -> Observation {
    Observation { key: key.into(), severity, summary: summary.into(), hold_s, notify: severity != "info", event: false }
}

fn ago(minutes: i64) -> String {
    (Utc::now() - Duration::minutes(minutes)).to_rfc3339()
}

/// Events of a kind in a window, grouped by a field of their data (or "" when the field is absent).
async fn grouped(state: &Shared, kind: &str, minutes: i64, field: &str) -> HashMap<String, (usize, String)> {
    let mut out: HashMap<String, (usize, String)> = HashMap::new();
    for e in db::events_since(&state.db, kind, &ago(minutes)).await.unwrap_or_default() {
        let v: serde_json::Value = serde_json::from_str(&e.data).unwrap_or_default();
        let g = if field.is_empty() { String::new() } else { v.get(field).and_then(|x| x.as_str()).unwrap_or("").to_string() };
        let entry = out.entry(g).or_insert((0, String::new()));
        entry.0 += 1;
        entry.1 = e.summary;
    }
    out
}

/// Event-driven observation: `count` matches within `window` minutes open it; it stays while the
/// newest match is younger than `keep` minutes (so one burst becomes one alert, not a flicker).
async fn burst(state: &Shared, open: &HashSet<String>, kind: &str, field: &str, prefix: &str, count: usize, window: i64, keep: i64, severity: &'static str, label: &str, out: &mut Vec<Observation>) {
    let recent = grouped(state, kind, window, field).await;
    let kept = grouped(state, kind, keep, field).await;
    for (g, (n, last)) in &kept {
        let key = if g.is_empty() { prefix.to_string() } else { format!("{prefix}:{g}") };
        let hot = recent.get(g).map(|(n, _)| *n >= count).unwrap_or(false);
        if hot || open.contains(&key) {
            let n_window = recent.get(g).map(|(n, _)| *n).unwrap_or(0);
            let summary = if g.is_empty() { format!("{label}: {last}") } else { format!("{label} {g}: {n_window} in {window}m, last: {last}") };
            let _ = n;
            out.push(Observation { key, severity, summary, hold_s: 0, notify: severity != "info", event: true });
        }
    }
}

pub async fn evaluate(state: &Shared, open: &HashSet<String>) -> Vec<Observation> {
    let t = thresholds(state).await;
    let host = state.host.read().await.clone();
    let s = state.sample.read().await.clone();
    let mut v: Vec<Observation> = Vec::new();

    // ---- capacity
    if s.disk_used_pct >= t.disk_crit {
        v.push(obs("disk", "critical", format!("disk / at {:.0}%", s.disk_used_pct), 300));
    } else if s.disk_used_pct >= t.disk_warn {
        v.push(obs("disk", "warning", format!("disk / at {:.0}%", s.disk_used_pct), 600));
    }
    if let Some(days) = disk_full_in_days(state).await {
        if days <= 7.0 && s.disk_used_pct < t.disk_warn {
            v.push(obs("disk-forecast", "warning", format!("disk / fills up in about {days:.0} days at the current rate"), 1800));
        }
    }
    if s.inodes_used_pct >= t.inodes_warn {
        v.push(obs("inodes", "warning", format!("inodes on / at {:.0}%", s.inodes_used_pct), 600));
    }
    if s.mem_available_pct > 0.0 && s.mem_available_pct < t.mem_crit {
        v.push(obs("memory", "critical", format!("only {:.0}% memory available, the OOM killer is next", s.mem_available_pct), 300));
    } else if s.mem_available_pct > 0.0 && s.mem_available_pct < t.mem_warn {
        v.push(obs("memory", "warning", format!("only {:.0}% memory available", s.mem_available_pct), 600));
    }
    if s.mem_full_avg10 > 5.0 {
        v.push(obs("memory-pressure", "warning", format!("memory pressure: {:.0}% of the time fully stalled", s.mem_full_avg10), 300));
    }
    if s.io_full_avg10 > 20.0 {
        v.push(obs("io-pressure", "warning", format!("io pressure: {:.0}% of the time fully stalled", s.io_full_avg10), 600));
    }
    if s.swap_used_pct > t.swap_warn {
        v.push(obs("swap", "warning", format!("swap {:.0}% in use", s.swap_used_pct), 900));
    }
    if s.cpu_busy_pct >= t.cpu_warn {
        v.push(obs("cpu", "warning", format!("cpu at {:.0}% for 15 minutes", s.cpu_busy_pct), 900));
    }
    if s.sampled && !s.clock_synced {
        v.push(obs("clock", "warning", "system clock is not synchronised", 1800));
    }

    // ---- services and the daemon's dependencies
    for (unit, active) in &host.services {
        if *active {
            continue;
        }
        let critical = matches!(unit.as_str(), "docker" | "caddy" | "nftables" | "wg-quick@wg0" | "fail2ban");
        v.push(obs(format!("service:{unit}"), if critical { "critical" } else { "warning" }, format!("{unit} is not active"), 300));
    }
    if !state.config.dev && !state.docker_ok.load(std::sync::atomic::Ordering::Relaxed) {
        v.push(obs("docker-api", "critical", "the Docker API does not answer", 120));
    }
    if host.reboot_required {
        // first seen is remembered: the file's mtime restarts with every package install
        let first = match db::kv_get(&state.db, "reboot.first_seen").await.ok().flatten().and_then(|s| db::parse_time(&s)) {
            Some(t) => t,
            None => {
                let _ = db::kv_set(&state.db, "reboot.first_seen", &db::now()).await;
                Utc::now()
            }
        };
        let days = (Utc::now() - first).num_days();
        if days >= t.reboot_days {
            v.push(obs("reboot", "warning", format!("a reboot has been pending for {days} days"), 0));
        }
    } else {
        let _ = db::kv_set(&state.db, "reboot.first_seen", "").await;
    }
    if !host.latest_version.is_empty() {
        v.push(obs("release", "info", format!("pocketcloud {} is available (running {})", host.latest_version, env!("CARGO_PKG_VERSION")), 0));
    }
    if host.uptime_hours > 0.0 && host.uptime_hours * 60.0 < 10.0 {
        // a reboot nobody ordered is a panic (kernel.panic_on_oops) or a power event; worth a mail either way
        v.push(Observation { key: "rebooted".into(), severity: "warning", summary: "the server rebooted".into(), hold_s: 0, notify: true, event: true });
    }

    // ---- live state: containers outside pocketcloud, routes that do not answer, unexpected listeners,
    //      the periodic reconcile
    if let Some(d) = &state.docker {
        let foreign = super::docker::foreign_containers(d).await;
        if !foreign.is_empty() {
            v.push(obs("foreign-containers", "warning", format!("containers running outside pocketcloud: {}", foreign.join(", ")), 120));
        }
    }
    v.extend(probe_routes(state).await);
    if !state.config.dev {
        if let Some(bad) = unexpected_listeners(state).await {
            v.push(obs("listeners", "warning", format!("unexpected listening sockets: {bad}"), 120));
        }
        if let Ok(Some(err)) = db::kv_get(&state.db, "reconcile.last_error").await {
            if !err.is_empty() {
                v.push(obs("reconcile", "warning", format!("applying the configuration fails: {err}"), 0));
            }
        }
    }
    // packages that unattended-upgrades does not cover (third-party repos) or that need a decision
    let important: Vec<&String> = host.pending_updates.iter().filter(|p| ["docker-ce", "containerd.io", "caddy", "falco", "trivy", "openssh-server", "linux-image", "restic", "wireguard"].iter().any(|k| p.starts_with(k))).collect();
    if !important.is_empty() {
        v.push(obs("packages", "warning", format!("security-relevant packages waiting for Server → Upgrade: {}", important.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), 0));
    }

    // ---- the monitoring itself
    let journal_age = chrono::Utc::now().timestamp() - state.journal_seen.load(std::sync::atomic::Ordering::Relaxed);
    if !state.config.dev && journal_age > 30 * 60 {
        v.push(obs("collector-journal", "warning", format!("no journal lines seen for {} minutes; the collector may be stuck", journal_age / 60), 0));
    }
    if !state.config.dev {
        if let Ok(out) = super::system::run("auditctl", &["-s"]).await {
            if !out.contains("enabled 2") && !out.contains("enabled 1") {
                v.push(obs("auditd", "warning", "auditd is not enabled; file changes are not recorded", 300));
            }
        }
    }

    // ---- the notifier itself
    if let Ok(Some(err)) = db::kv_get(&state.db, "notify.last_error").await {
        if !err.is_empty() {
            v.push(obs("notify", "warning", format!("notifications are failing: {err}"), 0));
        }
    }
    if !notify::settings(state).await.heartbeat_url.is_empty() && db::kv_get(&state.db, "notify.heartbeat_ok").await.ok().flatten().as_deref() == Some("0") {
        v.push(obs("heartbeat", "warning", "the heartbeat URL does not answer; the dead man's switch will fire", 600));
    }

    // ---- backups and certificates
    if super::backup::settings(state).await.is_some() {
        let b = super::backup::status(state).await;
        let enabled_since = match db::kv_get(&state.db, "backup.enabled_since").await.ok().flatten().and_then(|s| db::parse_time(&s)) {
            Some(t) => t,
            None => {
                let _ = db::kv_set(&state.db, "backup.enabled_since", &db::now()).await;
                Utc::now()
            }
        };
        if !b.last_error.is_empty() {
            v.push(obs("backup", "warning", format!("the last backup failed: {}", b.last_error), 0));
        } else if let Some(ok) = db::parse_time(&b.last_ok) {
            if Utc::now() - ok > Duration::hours(t.backup_stale_hours) {
                v.push(obs("backup", "warning", format!("no successful backup for {} hours", (Utc::now() - ok).num_hours()), 0));
            }
        } else if Utc::now() - enabled_since > Duration::hours(t.backup_stale_hours) {
            v.push(obs("backup", "warning", "backups are configured but none has ever succeeded", 0));
        }
    }
    for c in db::certificates(&state.db).await.unwrap_or_default() {
        if !c.last_error.is_empty() {
            v.push(obs(format!("certificate:{}", c.domain), "warning", format!("certificate for {}: {}", c.domain, c.last_error), 0));
        } else if let Some(days) = c.not_after.as_deref().and_then(db::parse_time).map(|t| (t - Utc::now()).num_days()) {
            if days < t.cert_days {
                v.push(obs(format!("certificate:{}", c.domain), "critical", format!("certificate for {} expires in {days} days", c.domain), 0));
            }
        }
    }

    // ---- jobs that failed (deploys are covered by the app status, backups above)
    for j in db::failed_jobs_since(&state.db, &ago(15)).await.unwrap_or_default() {
        if matches!(j.kind.as_str(), "deploy" | "apply" | "start" | "resume" | "backup") {
            continue;
        }
        v.push(Observation { key: format!("job:{}:{}", j.kind, j.id), severity: "warning", summary: format!("job #{} ({}) failed; see its log", j.id, j.kind), hold_s: 0, notify: true, event: true });
    }

    // ---- apps
    for a in db::apps(&state.db).await.unwrap_or_default() {
        match a.status.as_str() {
            "failed" => v.push(obs(format!("app:{}", a.name), "critical", format!("{}: {}", a.name, if a.status_detail.is_empty() { "deploy failed".into() } else { a.status_detail.clone() }), 0)),
            "rolled_back" => v.push(obs(format!("app:{}", a.name), "warning", format!("{}: {}", a.name, a.status_detail), 0)),
            _ => {}
        }
    }

    // ---- AIDE: findings, a failed or stale run
    let aide = super::system::aide_state();
    if aide.ran {
        match aide.exit_code {
            // aide exits with bits 1/2/4 for added/removed/changed and 14+ for errors (no database, bad config)
            Some(code) if code >= 8 => v.push(obs("aide-run", "warning", format!("the AIDE check failed with exit code {code}; see the server page"), 0)),
            _ if aide.outdated => {}
            _ => {
                if aide.added + aide.removed + aide.changed > 0 {
                    // packages installed since the baseline (unattended upgrades, Server → Upgrade) change files
                    // under /usr and /etc by design; those reports refresh the baseline and only inform
                    let packages_newer = std::fs::metadata("/var/log/apt/history.log").and_then(|a| a.modified()).ok()
                        .zip(std::fs::metadata("/var/lib/aide/aide.db").and_then(|b| b.modified()).ok())
                        .map(|(apt, db)| apt > db)
                        .unwrap_or(false);
                    if packages_newer {
                        v.push(Observation { key: "aide-packages".into(), severity: "info", summary: format!("AIDE: {} changed, {} added, {} removed files after package updates; baseline refreshed", aide.changed, aide.added, aide.removed), hold_s: 0, notify: true, event: true });
                        let _ = super::system::run("systemd-run", &["--quiet", "--unit", "pocketcloud-aide-init", "-p", "Nice=19", "bash", "-c", "aide --init -c /etc/aide/aide.conf >/var/log/pocketcloud/aide-init.log 2>&1; mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db"]).await;
                    } else {
                        v.push(obs("aide", "warning", format!("AIDE: {} changed, {} added, {} removed files since the baseline", aide.changed, aide.added, aide.removed), 0));
                    }
                }
            }
        }
        if aide.age_hours.map(|h| h > 36.0).unwrap_or(false) {
            v.push(obs("aide-stale", "warning", "the AIDE check has not run for more than 36 hours", 0));
        }
    } else if host.uptime_hours > 48.0 {
        v.push(obs("aide-stale", "warning", "AIDE has never produced a report on this server", 0));
    }

    // ---- events
    burst(state, open, "ssh_failed", "ip", "ssh-bruteforce", t.ssh_failed, 10, 30, "warning", "failed ssh logins from", &mut v).await;
    // any sshd event from outside the VPN proves port 22 is open to the internet (rescue open-ssh left open?)
    for kind in ["ssh_login", "ssh_failed"] {
        for (ip, (n, last)) in grouped(state, kind, 30, "ip").await {
            if !ip.starts_with("10.8.0.") && !ip.is_empty() {
                v.push(obs("ssh-public", "warning", format!("ssh is reachable from the internet: {n} {kind} from {ip} in 30m ({last})"), 0));
                break;
            }
        }
    }
    if t.notify_ssh_login {
        for (ip, (n, last)) in grouped(state, "ssh_login", 15, "ip").await {
            v.push(Observation { key: format!("ssh-login:{ip}"), severity: "info", summary: format!("{last} ({n} in 15m)"), hold_s: 0, notify: true, event: true });
        }
    }
    burst(state, open, "ban", "", "ban-wave", 5, 60, 60, "warning", "many bans", &mut v).await;
    burst(state, open, "login_failed", "ip", "interface-bruteforce", 5, 10, 30, "warning", "failed interface logins from", &mut v).await;
    // things done in the interface that an intruder would also do: told once, closes silently
    for e in db::events_since(&state.db, "admin_action", &ago(15)).await.unwrap_or_default() {
        v.push(Observation { key: format!("admin:{}", e.id), severity: "info", summary: e.summary, hold_s: 0, notify: true, event: true });
    }
    burst(state, open, "oom_kill", "comm", "oom", 1, 15, 15, "warning", "OOM kill of", &mut v).await;
    burst(state, open, "kernel_error", "", "kernel", 1, 15, 15, "critical", "kernel error", &mut v).await;
    burst(state, open, "unit_failed", "message", "unit-failed", 1, 15, 15, "warning", "failed unit", &mut v).await;
    // the installer (setup, upgrade) rewrites units, configs and binaries; its run is logged, and file changes
    // in the twenty minutes after it are the expected ones
    if !installer_ran_recently() {
        burst(state, open, "audit_write", "key", "audit-write", 1, 15, 15, "warning", "sensitive files changed:", &mut v).await;
    }
    burst(state, open, "audit_time", "", "audit-time", 1, 15, 15, "warning", "system time changed", &mut v).await;
    burst(state, open, "audit_denied", "key", "audit-denied", 1, 15, 15, "warning", "refused write to", &mut v).await;
    burst(state, open, "audit_setuid", "", "audit-setuid", 1, 15, 15, "warning", "setuid execution", &mut v).await;
    burst(state, open, "audit_mount", "", "audit-mount", 1, 15, 15, "info", "filesystem mounted", &mut v).await;
    burst(state, open, "audit_module", "", "audit-module", 1, 15, 15, "info", "kernel module loaded or removed", &mut v).await;
    burst(state, open, "waf_block", "ip", "waf-spike", t.waf_blocks, 10, 30, "warning", "WAF blocks from", &mut v).await;
    burst(state, open, "http_5xx", "host", "http-5xx", t.http_5xx, 5, 15, "warning", "server errors on", &mut v).await;
    burst(state, open, "container_oom", "service", "container-oom", 1, 15, 15, "warning", "container out of memory:", &mut v).await;
    burst(state, open, "container_unhealthy", "service", "container-unhealthy", 1, 15, 15, "warning", "unhealthy container:", &mut v).await;
    burst(state, open, "container_died", "service", "container-died", 1, 15, 15, "warning", "container exited:", &mut v).await;
    burst(state, open, "container_died", "service", "restart-loop", 3, 60, 60, "warning", "restart loop:", &mut v).await;
    // falco by priority
    for e in db::events_since(&state.db, "falco", &ago(15)).await.unwrap_or_default() {
        let d: serde_json::Value = serde_json::from_str(&e.data).unwrap_or_default();
        let prio = d.get("priority").and_then(|p| p.as_str()).unwrap_or("");
        let rule = d.get("rule").and_then(|p| p.as_str()).unwrap_or("").to_string();
        if matches!(prio, "Emergency" | "Alert" | "Critical" | "Error") {
            let key = format!("falco:{rule}");
            if !v.iter().any(|o| o.key == key) {
                v.push(obs(key, "critical", format!("falco: {}", e.summary), 0));
            }
        }
    }
    // Warning: one event is enough (reverse shells, memfd execs, log wipes are Warning in the default rules);
    // Notice: info at one, warning at three
    let mut by_rule: HashMap<String, (usize, usize, String)> = HashMap::new();
    for e in db::events_since(&state.db, "falco", &ago(15)).await.unwrap_or_default() {
        let d: serde_json::Value = serde_json::from_str(&e.data).unwrap_or_default();
        let prio = d.get("priority").and_then(|p| p.as_str()).unwrap_or("");
        let rule = d.get("rule").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let entry = by_rule.entry(rule).or_insert((0, 0, String::new()));
        match prio {
            "Warning" => entry.0 += 1,
            "Notice" => entry.1 += 1,
            _ => {}
        }
        entry.2 = e.summary;
    }
    for (rule, (warnings, notices, last)) in by_rule {
        if v.iter().any(|o| o.key == format!("falco:{rule}")) {
            continue;
        }
        if warnings > 0 || notices >= 3 {
            v.push(obs(format!("falco-warn:{rule}"), "warning", format!("falco: {rule} ({} events in 15m), last: {last}", warnings + notices), 0));
        } else if notices > 0 {
            v.push(obs(format!("falco-notice:{rule}"), "info", format!("falco: {last}"), 0));
        }
    }
    v
}

/// Every route of a running app is fetched once a minute through Caddy, with the route's host name and the
/// real certificate chain ignored (staging issuers). Three failures in a row open the alert.
async fn probe_routes(state: &Shared) -> Vec<Observation> {
    let mut out = Vec::new();
    if state.config.dev {
        return out;
    }
    let apps = db::apps(&state.db).await.unwrap_or_default();
    let routes = db::routes(&state.db).await.unwrap_or_default();
    let ips = state.public_ips.read().await.clone();
    let Some(v4) = ips.iter().find(|i| !i.contains(':')).cloned() else { return out };
    let mut failures = state.probe_failures.lock().await;
    for r in routes {
        if !apps.iter().any(|a| a.id == r.app_id && a.desired == "running") {
            failures.remove(&r.host);
            continue;
        }
        let target = if r.expose == "public" { v4.clone() } else { crate::wireguard::HUB_IP.to_string() };
        let Ok(addr) = format!("{target}:443").parse::<std::net::SocketAddr>() else { continue };
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(8))
            .resolve(&r.host, addr)
            .build();
        let result = match client {
            Ok(c) => c.get(format!("https://{}/", r.host)).send().await.map(|resp| resp.status().as_u16()),
            Err(_) => continue,
        };
        let problem = match result {
            Ok(code) if code >= 502 => Some(format!("answers {code}")),
            Ok(_) => None,
            Err(e) => Some(format!("does not answer ({})", if e.is_timeout() { "timeout".to_string() } else { "connection failed".to_string() })),
        };
        match problem {
            Some(p) => {
                let n = failures.entry(r.host.clone()).or_insert(0);
                *n += 1;
                if *n >= 3 {
                    out.push(obs(format!("route:{}", r.host), "warning", format!("https://{} {p} ({} checks in a row)", r.host, *n), 0));
                }
            }
            None => {
                failures.remove(&r.host);
            }
        }
    }
    out
}

/// Listening TCP and UDP sockets outside the expected set: a bind shell or a service nobody asked for.
async fn unexpected_listeners(state: &Shared) -> Option<String> {
    let out = super::system::run("ss", &["-Hltnu"]).await.ok()?;
    // 68/546: the DHCP clients of the public interface
    let allowed: Vec<u16> = vec![22, 53, 68, 80, 443, 546, 2019, 7788, state.config.vpn.port];
    let mut bad = Vec::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let Some(local) = cols.get(4) else { continue };
        let Some((addr, port)) = local.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let loopback = addr.starts_with("127.") || addr == "[::1]" || addr.starts_with("127.0.0.53") || addr.starts_with("127.0.0.54");
        if allowed.contains(&port) || loopback {
            continue;
        }
        let proto = cols.first().copied().unwrap_or("");
        bad.push(format!("{proto} {local}"));
    }
    bad.sort();
    bad.dedup();
    if bad.is_empty() {
        None
    } else {
        Some(bad.join(", "))
    }
}

/// Linear trend of disk usage over the last 24 hours: days until 100%, when it grows at all.
async fn disk_full_in_days(state: &Shared) -> Option<f64> {
    let series = db::metric_series(&state.db, "disk.used_pct", &ago(24 * 60)).await.ok()?;
    if series.len() < 30 {
        return None;
    }
    let pts: Vec<(f64, f64)> = series.iter().filter_map(|(ts, v)| db::parse_time(ts).map(|t| (t.timestamp() as f64 / 86400.0, *v))).collect();
    let n = pts.len() as f64;
    let (sx, sy) = pts.iter().fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let sxx: f64 = pts.iter().map(|(x, _)| (x - mx) * (x - mx)).sum();
    if sxx == 0.0 {
        return None;
    }
    let slope = pts.iter().map(|(x, y)| (x - mx) * (y - my)).sum::<f64>() / sxx;
    if slope <= 0.05 {
        return None;
    }
    let last = pts.last()?.1;
    Some((100.0 - last) / slope)
}

/// The installer appends a line per run to installs.log; true within twenty minutes of the last one.
fn installer_ran_recently() -> bool {
    std::fs::metadata("/var/log/pocketcloud/installs.log")
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() < 20 * 60)
        .unwrap_or(false)
}


/// One evaluation round: open, touch, resolve; queue changes for the notifier.
pub async fn tick(state: &Shared) -> Result<()> {
    let open = db::open_alerts(&state.db).await?;
    let open_keys: HashSet<String> = open.iter().map(|a| a.key.clone()).collect();
    let observed = evaluate(state, &open_keys).await;
    let mut pending = state.alert_pending.lock().await;
    let mut changes: Vec<Change> = Vec::new();
    let now = db::now();
    let seen: HashSet<String> = observed.iter().map(|o| o.key.clone()).collect();
    let mut point_events = state.point_events.lock().await;
    for o in &observed {
        if let Some(a) = open.iter().find(|a| a.key == o.key) {
            if a.severity != o.severity || a.summary != o.summary {
                db::touch_alert(&state.db, a.id, o.severity, &o.summary).await?;
                if a.severity != o.severity && o.notify {
                    changes.push(Change { event: "opened".into(), key: o.key.clone(), severity: o.severity.into(), summary: o.summary.clone(), at: now.clone() });
                }
            } else {
                db::touch_alert(&state.db, a.id, o.severity, &o.summary).await?;
            }
            continue;
        }
        let since = *pending.entry(o.key.clone()).or_insert_with(Instant::now);
        if since.elapsed().as_secs() >= o.hold_s {
            db::open_alert(&state.db, &o.key, o.severity, &o.summary).await?;
            pending.remove(&o.key);
            if o.event {
                point_events.insert(o.key.clone());
            }
            tracing::warn!("alert opened: {} {}", o.severity, o.summary);
            if o.notify {
                changes.push(Change { event: "opened".into(), key: o.key.clone(), severity: o.severity.into(), summary: o.summary.clone(), at: now.clone() });
            }
        }
    }
    pending.retain(|k, _| seen.contains(k));
    for a in &open {
        if !seen.contains(&a.key) {
            db::resolve_alert(&state.db, a.id).await?;
            tracing::info!("alert resolved: {}", a.summary);
            // conditions announce their end; point events just close
            if a.severity != "info" && !point_events.remove(&a.key) {
                changes.push(Change { event: "resolved".into(), key: a.key.clone(), severity: a.severity.clone(), summary: a.summary.clone(), at: now.clone() });
            }
        }
    }
    drop(point_events);
    drop(pending);
    if !changes.is_empty() {
        state.notify_queue.lock().await.extend(changes);
    }
    Ok(())
}

/// Send what the ticks queued, at most once a minute, so a storm is one message.
/// Send what the ticks queued, once a minute. A failed delivery keeps the batch for the next minute (capped),
/// so a transient SMTP error does not lose a critical alert.
pub async fn flush_notifications(state: &Shared) {
    let changes: Vec<Change> = std::mem::take(&mut *state.notify_queue.lock().await);
    if changes.is_empty() || !notify::settings(state).await.any() {
        return;
    }
    if notify::deliver(state, &changes).await {
        let _ = db::kv_set(&state.db, "notify.failures", "0").await;
    } else {
        let failures = db::kv_get(&state.db, "notify.failures").await.ok().flatten().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) + 1;
        let _ = db::kv_set(&state.db, "notify.failures", &failures.to_string()).await;
        let mut q = state.notify_queue.lock().await;
        let mut keep = changes;
        keep.extend(q.drain(..));
        keep.truncate(200);
        *q = keep;
        if failures >= 3 {
            notify::heartbeat_fail(state).await;
        }
    }
}

/// A hand-made notification, to prove the channels work.
pub async fn send_test(state: &Shared) -> Result<()> {
    if !notify::settings(state).await.any() {
        anyhow::bail!("no notification channel configured");
    }
    let c = Change { event: "opened".into(), key: "test".into(), severity: "info".into(), summary: "test notification from the interface".into(), at: db::now() };
    let _ = notify::deliver(state, &[c]).await;
    match db::kv_get(&state.db, "notify.last_error").await?.unwrap_or_default().as_str() {
        "" => Ok(()),
        e => anyhow::bail!("{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_merge_defaults() {
        let t: Thresholds = serde_json::from_str(r#"{"disk_warn": 70}"#).unwrap();
        assert_eq!((t.disk_warn, t.disk_crit), (70.0, 95.0));
    }
}
