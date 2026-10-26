//! Talking to the host: nftables, WireGuard, package state, disk, AIDE, auditd. Everything shells out.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

pub async fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}: {}{}", args.join(" "), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub async fn wan_interface() -> Result<String> {
    let out = run("ip", &["-j", "route", "show", "default"]).await?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    v.as_array()
        .and_then(|a| a.first())
        .and_then(|r| r["dev"].as_str())
        .map(|s| s.to_string())
        .context("no default route")
}

/// Global addresses of the interface with the default route, as a fallback when the API is unavailable.
pub async fn local_public_ips() -> Result<Vec<String>> {
    let wan = wan_interface().await?;
    let out = run("ip", &["-j", "addr", "show", "dev", &wan]).await?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    let mut ips = Vec::new();
    for iface in v.as_array().into_iter().flatten() {
        for a in iface["addr_info"].as_array().into_iter().flatten() {
            if a["scope"].as_str() == Some("global") {
                if let Some(ip) = a["local"].as_str() {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    if ips.is_empty() {
        bail!("no global address on {wan}");
    }
    Ok(ips)
}

pub async fn apply_nftables(ruleset: &str) -> Result<()> {
    let tmp = Path::new("/etc/nftables.conf.new");
    std::fs::write(tmp, ruleset)?;
    run("nft", &["-c", "-f", tmp.to_str().unwrap()]).await.context("nftables ruleset rejected")?;
    std::fs::rename(tmp, "/etc/nftables.conf")?;
    run("nft", &["-f", "/etc/nftables.conf"]).await?;
    Ok(())
}

pub async fn apply_wireguard(conf: &str) -> Result<()> {
    let path = Path::new("/etc/wireguard/wg0.conf");
    std::fs::create_dir_all("/etc/wireguard")?;
    let changed = std::fs::read_to_string(path).map(|c| c != conf).unwrap_or(true);
    if changed {
        crate::install::write_private(path, conf)?;
    }
    let active = Command::new("systemctl").args(["is-active", "--quiet", "wg-quick@wg0"]).status().await?.success();
    if !active {
        run("systemctl", &["enable", "--now", "wg-quick@wg0"]).await?;
    } else if changed {
        let stripped = run("wg-quick", &["strip", "wg0"]).await?;
        let tmp = "/run/pocketcloud/wg0.stripped";
        std::fs::create_dir_all("/run/pocketcloud")?;
        crate::install::write_private(Path::new(tmp), &stripped)?;
        let r = run("wg", &["syncconf", "wg0", tmp]).await;
        let _ = std::fs::remove_file(tmp);
        r?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct WgPeerStatus {
    pub public_key: String,
    pub endpoint: String,
    pub last_handshake: Option<i64>,
    pub rx: u64,
    pub tx: u64,
}

pub async fn wireguard_peers() -> Vec<WgPeerStatus> {
    let out = match run("wg", &["show", "wg0", "dump"]).await {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    out.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 8).then(|| WgPeerStatus {
                public_key: f[0].to_string(),
                endpoint: f[2].to_string(),
                last_handshake: f[4].parse::<i64>().ok().filter(|t| *t > 0),
                rx: f[5].parse().unwrap_or(0),
                tx: f[6].parse().unwrap_or(0),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HostStatus {
    pub hostname: String,
    pub uptime_hours: f64,
    pub load: String,
    pub mem_total_mb: u64,
    pub mem_available_mb: u64,
    pub disk_total_gb: f64,
    pub disk_used_gb: f64,
    pub reboot_required: bool,
    pub pending_updates: Vec<String>,
    pub pending_checked: String,
    pub aide_report: String,
    pub aide_checked: String,
    pub audit_summary: String,
    pub services: Vec<(String, bool)>,
    /// newest GitHub release when it is not the running version
    pub latest_version: String,
}

/// One-minute sample of the numbers the checks look at.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Sample {
    pub sampled: bool,
    pub cpu_busy_pct: f64,
    pub mem_available_pct: f64,
    pub swap_used_pct: f64,
    pub disk_used_pct: f64,
    pub inodes_used_pct: f64,
    pub mem_full_avg10: f64,
    pub io_full_avg10: f64,
    pub load1: f64,
    pub clock_synced: bool,
}

static LAST_CPU: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);

fn pressure(path: &str) -> f64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("full")).and_then(|l| l.split_whitespace().find_map(|p| p.strip_prefix("avg10=")).and_then(|v| v.parse().ok())))
        .unwrap_or(0.0)
}

pub async fn sample() -> Sample {
    let mut s = Sample { sampled: true, ..Default::default() };
    if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
        if let Some(l) = stat.lines().next() {
            let f: Vec<u64> = l.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
            if f.len() >= 5 {
                let idle = f[3] + f[4];
                let total: u64 = f.iter().sum();
                let mut last = LAST_CPU.lock().unwrap();
                if let Some((pt, pi)) = *last {
                    let dt = total.saturating_sub(pt);
                    if dt > 0 {
                        s.cpu_busy_pct = 100.0 * (1.0 - idle.saturating_sub(pi) as f64 / dt as f64);
                    }
                }
                *last = Some((total, idle));
            }
        }
    }
    if let Ok(m) = std::fs::read_to_string("/proc/meminfo") {
        let get = |k: &str| m.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
        let total = get("MemTotal:");
        if total > 0.0 {
            s.mem_available_pct = 100.0 * get("MemAvailable:") / total;
        }
        let swap_total = get("SwapTotal:");
        if swap_total > 0.0 {
            s.swap_used_pct = 100.0 * (swap_total - get("SwapFree:")) / swap_total;
        }
    }
    if let Ok(df) = run("df", &["--output=pcent,ipcent", "/"]).await {
        if let Some(l) = df.lines().nth(1) {
            let mut it = l.split_whitespace().map(|x| x.trim_end_matches('%').parse::<f64>().unwrap_or(0.0));
            s.disk_used_pct = it.next().unwrap_or(0.0);
            s.inodes_used_pct = it.next().unwrap_or(0.0);
        }
    }
    s.mem_full_avg10 = pressure("/proc/pressure/memory");
    s.io_full_avg10 = pressure("/proc/pressure/io");
    s.load1 = std::fs::read_to_string("/proc/loadavg").ok().and_then(|l| l.split_whitespace().next().and_then(|x| x.parse().ok())).unwrap_or(0.0);
    s.clock_synced = run("timedatectl", &["show", "-p", "NTPSynchronized", "--value"]).await.map(|o| o.trim() == "yes").unwrap_or(true);
    s
}

impl Sample {
    pub fn metrics(&self) -> Vec<(String, f64)> {
        vec![
            ("cpu.busy_pct".into(), self.cpu_busy_pct),
            ("mem.available_pct".into(), self.mem_available_pct),
            ("mem.swap_used_pct".into(), self.swap_used_pct),
            ("disk.used_pct".into(), self.disk_used_pct),
            ("disk.inodes_pct".into(), self.inodes_used_pct),
            ("pressure.mem_full_avg10".into(), self.mem_full_avg10),
            ("pressure.io_full_avg10".into(), self.io_full_avg10),
            ("load.1".into(), self.load1),
        ]
    }
}

pub async fn quick_status() -> HostStatus {
    let mut s = HostStatus::default();
    s.hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
    if let Ok(u) = std::fs::read_to_string("/proc/uptime") {
        s.uptime_hours = u.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0) / 3600.0;
    }
    if let Ok(l) = std::fs::read_to_string("/proc/loadavg") {
        s.load = l.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
    }
    if let Ok(m) = std::fs::read_to_string("/proc/meminfo") {
        for line in m.lines() {
            let kb = || line.split_whitespace().nth(1).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0) / 1024;
            if line.starts_with("MemTotal:") {
                s.mem_total_mb = kb();
            } else if line.starts_with("MemAvailable:") {
                s.mem_available_mb = kb();
            }
        }
    }
    if let Ok(df) = run("df", &["-B1", "--output=size,used", "/"]).await {
        if let Some(l) = df.lines().nth(1) {
            let mut it = l.split_whitespace();
            let gb = |x: Option<&str>| x.and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0) / 1e9;
            s.disk_total_gb = gb(it.next());
            s.disk_used_gb = gb(it.next());
        }
    }
    s.reboot_required = Path::new("/var/run/reboot-required").exists();
    let mut units = vec!["docker", "caddy", "wg-quick@wg0", "nftables", "fail2ban", "auditd", "unattended-upgrades"];
    if Path::new("/etc/systemd/system/multi-user.target.wants/falco-modern-bpf.service").exists() {
        units.push("falco-modern-bpf");
    }
    // the service list drives the service-down alert; a Falco that is switched off must not count
    for unit in units {
        let ok = Command::new("systemctl").args(["is-active", "--quiet", unit]).status().await.map(|s| s.success()).unwrap_or(false);
        s.services.push((unit.to_string(), ok));
    }
    s
}

/// Pending apt upgrades; slow (apt-get update), run from a daily job.
pub async fn pending_updates() -> Result<Vec<String>> {
    let _ = run("apt-get", &["update", "-qq"]).await;
    let out = run("apt-get", &["-s", "-o", "Debug::NoLocking=true", "upgrade"]).await?;
    Ok(out.lines().filter_map(|l| l.strip_prefix("Inst ")).map(|l| l.split_whitespace().next().unwrap_or("").to_string()).collect())
}

/// AIDE report written by the daily timer (assets/pocketcloud-aide.service).
/// The AIDE report: the summary block comes first, the per-file detail can run to hundreds of lines; the page
/// shows head and tail, the counts and exit code are parsed from the whole file.
pub fn aide_report() -> (String, String) {
    let path = Path::new("/var/log/pocketcloud/aide.log");
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| "no AIDE report yet".into());
    let checked = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let shown = if lines.len() > 80 {
        let mut v: Vec<&str> = lines[..40].to_vec();
        v.push("[...]");
        v.extend_from_slice(&lines[lines.len() - 40..]);
        v.join("\n")
    } else {
        content.clone()
    };
    (shown, checked)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AideState {
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
    pub exit_code: Option<i32>,
    pub age_hours: Option<f64>,
    pub ran: bool,
    /// the report predates the current baseline (re-initialised after an installer run); findings are moot
    pub outdated: bool,
}

/// Counts and exit code from the full report file; the unit appends "exit N at <time>" as the last line.
pub fn aide_state() -> AideState {
    let path = Path::new("/var/log/pocketcloud/aide.log");
    let Ok(content) = std::fs::read_to_string(path) else { return AideState::default() };
    let find = |label: &str| content.lines().find(|l| l.trim_start().starts_with(label) && l.contains(':')).and_then(|l| l.rsplit(':').next()).and_then(|n| n.trim().parse::<u64>().ok()).unwrap_or(0);
    let exit_code = content.lines().rev().find(|l| l.starts_with("exit ")).and_then(|l| l.split_whitespace().nth(1)).and_then(|n| n.parse().ok());
    let age_hours = std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs_f64() / 3600.0);
    let report_time = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let baseline_time = std::fs::metadata("/var/lib/aide/aide.db").and_then(|m| m.modified()).ok();
    let outdated = matches!((report_time, baseline_time), (Some(r), Some(b)) if b > r);
    AideState { added: find("Added entries"), removed: find("Removed entries"), changed: find("Changed entries"), exit_code, age_hours, ran: true, outdated }
}

/// Falco on or off, from the database; on by default.
pub async fn falco_wanted(state: &super::state::Shared) -> bool {
    super::db::kv_get(&state.db, "monitor.falco").await.ok().flatten().as_deref() != Some("0")
}

/// Make the Falco service match the setting; the package itself is always installed.
pub async fn ensure_falco(wanted: bool) {
    let unit = "falco-modern-bpf";
    let active = Command::new("systemctl").args(["is-active", "--quiet", unit]).status().await.map(|s| s.success()).unwrap_or(false);
    if wanted && !active {
        let _ = run("systemctl", &["enable", "--now", unit]).await;
    } else if !wanted && active {
        let _ = run("systemctl", &["disable", "--now", unit]).await;
    }
}

/// The installed Caddy lists `http.handlers.waf` when it was built with coraza-caddy.
pub async fn caddy_has_waf() -> bool {
    run("caddy", &["list-modules"]).await.map(|out| out.lines().any(|l| l.trim() == "http.handlers.waf")).unwrap_or(false)
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct WafEvent {
    pub at: String,
    pub client: String,
    pub host: String,
    pub uri: String,
    /// Coraza's transaction id, the same one appears in Caddy's error log
    pub id: String,
}

/// Requests Coraza blocked, from Caddy's journal (newest first).
pub async fn waf_events(limit: usize) -> Vec<WafEvent> {
    let out = run("journalctl", &["-u", "caddy", "-o", "cat", "--since", "-7d", "--no-pager", "-g", "WAF rule violation"]).await.unwrap_or_default();
    let mut events: Vec<WafEvent> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            let s = |k: &str| v.get(k).map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).unwrap_or_default();
            let at = v.get("ts").and_then(|t| t.as_f64()).and_then(|t| chrono::DateTime::from_timestamp(t as i64, 0)).map(|t| t.to_rfc3339()).unwrap_or_default();
            WafEvent { at, client: s("client_ip"), host: s("hostname"), uri: s("uri"), id: s("unique_id") }
        })
        .collect();
    events.reverse();
    events.truncate(limit);
    events
}

/// Newest release tag on GitHub, if newer than this build. Empty when unknown or current.
pub async fn newer_release() -> String {
    let client = reqwest::Client::builder().user_agent("pocketcloud").timeout(std::time::Duration::from_secs(15)).build();
    let Ok(client) = client else { return String::new() };
    let Ok(resp) = client.get("https://api.github.com/repos/timokoenig/pocketcloud/releases/latest").send().await else { return String::new() };
    let Ok(v) = resp.json::<serde_json::Value>().await else { return String::new() };
    let tag = v.get("tag_name").and_then(|t| t.as_str()).unwrap_or("").trim_start_matches('v').to_string();
    let parse = |s: &str| s.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    if !tag.is_empty() && parse(&tag) > parse(env!("CARGO_PKG_VERSION")) {
        tag
    } else {
        String::new()
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct JailStatus {
    pub jail: String,
    pub banned: Vec<String>,
    pub total: String,
}

/// Active fail2ban bans per jail.
pub async fn fail2ban_status() -> Vec<JailStatus> {
    let mut out = Vec::new();
    for jail in ["sshd", "pocketcloud-waf"] {
        let Ok(text) = run("fail2ban-client", &["status", jail]).await else { continue };
        let field = |k: &str| text.lines().find(|l| l.contains(k)).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        let banned: Vec<String> = field("Banned IP list").split_whitespace().map(str::to_string).collect();
        out.push(JailStatus { jail: jail.to_string(), banned, total: field("Total banned") });
    }
    out
}

pub async fn audit_summary() -> String {
    run("aureport", &["-k", "--summary", "-ts", "this-week", "-i"]).await.unwrap_or_else(|e| format!("aureport: {e}"))
}

pub async fn reboot() -> Result<()> {
    run("systemctl", &["reboot"]).await.map(|_| ())
}

/// apt runs as a transient unit started by PID 1, outside this daemon's sandbox: with RestrictSUIDSGID
/// alone dpkg could not install su or sudo. The unit's output comes back through the pipe.
pub async fn apt_upgrade() -> Result<String> {
    let unit = format!("pocketcloud-apt-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    let out = Command::new("systemd-run")
        .args(["--wait", "--pipe", "--collect", "--quiet", "--unit", &unit])
        .args(["--setenv=DEBIAN_FRONTEND=noninteractive", "--setenv=NEEDRESTART_SUSPEND=1"])
        .args(["/bin/sh", "-c", APT_UPGRADE])
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        bail!("apt-get full-upgrade failed:\n{text}");
    }
    Ok(text)
}

/// Finishes an interrupted dpkg run first, so a failed upgrade can simply be retried.
const APT_UPGRADE: &str = "dpkg --configure -a && apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade && apt-get -y -qq autoremove";
