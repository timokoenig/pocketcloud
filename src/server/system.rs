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
    for unit in ["docker", "caddy", "wg-quick@wg0", "nftables", "fail2ban", "auditd", "unattended-upgrades"] {
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
pub fn aide_report() -> (String, String) {
    let path = Path::new("/var/log/pocketcloud/aide.log");
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| "no AIDE report yet".into());
    let checked = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_default();
    let tail: Vec<&str> = content.lines().rev().take(60).collect();
    (tail.into_iter().rev().collect::<Vec<_>>().join("\n"), checked)
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
        let field = |k: &str| text.lines().find(|l| l.contains(k)).and_then(|l| l.split(':').nth(1)).map(|v| v.trim().to_string()).unwrap_or_default();
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
