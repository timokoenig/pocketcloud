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
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds { disk_warn: 85.0, disk_crit: 95.0, inodes_warn: 90.0, mem_warn: 10.0, mem_crit: 5.0, cpu_warn: 95.0, swap_warn: 50.0, ssh_failed: 10, waf_blocks: 50, http_5xx: 20, backup_stale_hours: 48, reboot_days: 2, cert_days: 7 }
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
}

fn obs(key: impl Into<String>, severity: &'static str, summary: impl Into<String>, hold_s: u64) -> Observation {
    Observation { key: key.into(), severity, summary: summary.into(), hold_s }
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
            out.push(obs(key, severity, summary, 0));
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
        if let Ok(meta) = std::fs::metadata("/var/run/reboot-required") {
            if let Ok(age) = meta.modified().and_then(|m| m.elapsed().map_err(std::io::Error::other)) {
                if age.as_secs() as i64 >= t.reboot_days * 86400 {
                    v.push(obs("reboot", "warning", format!("a reboot has been pending for {} days", age.as_secs() / 86400), 0));
                }
            }
        }
    }
    if !host.latest_version.is_empty() {
        v.push(obs("release", "info", format!("pocketcloud {} is available (running {})", host.latest_version, env!("CARGO_PKG_VERSION")), 0));
    }
    if host.uptime_hours > 0.0 && host.uptime_hours * 60.0 < 10.0 {
        v.push(obs("rebooted", "info", "the server rebooted", 0));
    }

    // ---- backups and certificates
    if state.config.backup.is_some() {
        let b = super::backup::status(state).await;
        if !b.last_error.is_empty() {
            v.push(obs("backup", "warning", format!("the last backup failed: {}", b.last_error), 0));
        } else if let Some(ok) = db::parse_time(&b.last_ok) {
            if Utc::now() - ok > Duration::hours(t.backup_stale_hours) {
                v.push(obs("backup", "warning", format!("no successful backup for {} hours", (Utc::now() - ok).num_hours()), 0));
            }
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

    // ---- apps
    for a in db::apps(&state.db).await.unwrap_or_default() {
        match a.status.as_str() {
            "failed" => v.push(obs(format!("app:{}", a.name), "critical", format!("{}: {}", a.name, if a.status_detail.is_empty() { "deploy failed".into() } else { a.status_detail.clone() }), 0)),
            "rolled_back" => v.push(obs(format!("app:{}", a.name), "warning", format!("{}: {}", a.name, a.status_detail), 0)),
            _ => {}
        }
    }

    // ---- AIDE
    if let Some((added, removed, changed)) = aide_counts(&host.aide_report) {
        if added + removed + changed > 0 {
            v.push(obs("aide", "warning", format!("AIDE: {changed} changed, {added} added, {removed} removed files since the baseline"), 0));
        }
    }

    // ---- events
    burst(state, open, "ssh_failed", "ip", "ssh-bruteforce", t.ssh_failed, 10, 30, "warning", "failed ssh logins from", &mut v).await;
    burst(state, open, "ban", "", "ban-wave", 5, 60, 60, "warning", "many bans", &mut v).await;
    burst(state, open, "oom_kill", "comm", "oom", 1, 15, 15, "warning", "OOM kill of", &mut v).await;
    burst(state, open, "kernel_error", "", "kernel", 1, 15, 15, "critical", "kernel error", &mut v).await;
    burst(state, open, "unit_failed", "message", "unit-failed", 1, 15, 15, "warning", "failed unit", &mut v).await;
    // the installer (setup, upgrade) rewrites units, configs and binaries; its run is logged, and file changes
    // in the twenty minutes after it are the expected ones
    if !installer_ran_recently() {
        burst(state, open, "audit_write", "key", "audit-write", 1, 15, 15, "warning", "sensitive files changed:", &mut v).await;
    }
    burst(state, open, "audit_time", "", "audit-time", 1, 15, 15, "warning", "system time changed", &mut v).await;
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
    let warnings = grouped(state, "falco", 10, "rule").await;
    for (rule, (n, last)) in warnings {
        let key = format!("falco-warn:{rule}");
        if (n >= 5 || open.contains(&key)) && !v.iter().any(|o| o.key == format!("falco:{rule}")) {
            v.push(obs(key, "warning", format!("falco: {n} events of {rule} in 10m, last: {last}"), 0));
        }
    }
    v
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

/// "Added entries: 3" style lines of an AIDE report.
pub fn aide_counts(report: &str) -> Option<(u64, u64, u64)> {
    let find = |label: &str| report.lines().find(|l| l.trim_start().starts_with(label)).and_then(|l| l.split(':').nth(1)).and_then(|n| n.trim().parse::<u64>().ok());
    Some((find("Added entries")?, find("Removed entries")?, find("Changed entries")?))
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
    for o in &observed {
        if let Some(a) = open.iter().find(|a| a.key == o.key) {
            if a.severity != o.severity || a.summary != o.summary {
                db::touch_alert(&state.db, a.id, o.severity, &o.summary).await?;
                if a.severity != o.severity && o.severity != "info" {
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
            tracing::warn!("alert opened: {} {}", o.severity, o.summary);
            if o.severity != "info" {
                changes.push(Change { event: "opened".into(), key: o.key.clone(), severity: o.severity.into(), summary: o.summary.clone(), at: now.clone() });
            }
        }
    }
    pending.retain(|k, _| seen.contains(k));
    for a in &open {
        if !seen.contains(&a.key) {
            db::resolve_alert(&state.db, a.id).await?;
            tracing::info!("alert resolved: {}", a.summary);
            if a.severity != "info" {
                changes.push(Change { event: "resolved".into(), key: a.key.clone(), severity: a.severity.clone(), summary: a.summary.clone(), at: now.clone() });
            }
        }
    }
    drop(pending);
    if !changes.is_empty() {
        state.notify_queue.lock().await.extend(changes);
    }
    Ok(())
}

/// Send what the ticks queued, at most once a minute, so a storm is one message.
pub async fn flush_notifications(state: &Shared) {
    let changes: Vec<Change> = std::mem::take(&mut *state.notify_queue.lock().await);
    if changes.is_empty() || !state.config.notify.any() {
        return;
    }
    notify::deliver(state, &changes).await;
}

/// A hand-made notification, to prove the channels work.
pub async fn send_test(state: &Shared) -> Result<()> {
    if !state.config.notify.any() {
        anyhow::bail!("no notification channel configured");
    }
    let c = Change { event: "opened".into(), key: "test".into(), severity: "info".into(), summary: "test notification from the interface".into(), at: db::now() };
    notify::deliver(state, &[c]).await;
    match db::kv_get(&state.db, "notify.last_error").await?.unwrap_or_default().as_str() {
        "" => Ok(()),
        e => anyhow::bail!("{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aide_report_counts() {
        let r = "AIDE found differences\n\nSummary:\n  Total number of entries:\t3\n  Added entries:\t\t1\n  Removed entries:\t\t0\n  Changed entries:\t\t2\n";
        assert_eq!(aide_counts(r), Some((1, 0, 2)));
        assert_eq!(aide_counts("no AIDE report yet"), None);
    }

    #[test]
    fn thresholds_merge_defaults() {
        let t: Thresholds = serde_json::from_str(r#"{"disk_warn": 70}"#).unwrap();
        assert_eq!((t.disk_warn, t.disk_crit), (70.0, 95.0));
    }
}
