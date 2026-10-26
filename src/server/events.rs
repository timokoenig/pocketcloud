//! Collectors: facts from the journal (ssh, fail2ban, sudo, OOM, kernel, units, Caddy), the auditd log,
//! Falco's JSON file and Docker events. Everything lands in the events table; the alert checks count it.
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::db;
use super::state::Shared;

static SSH_ACCEPTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Accepted (\w+) for (\S+) from (\S+) port (\d+)").unwrap());
static SSH_INVALID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Invalid user (\S*) from (\S+)").unwrap());
static SSH_FAILED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Failed (\w+) for (?:invalid user )?(\S+) from (\S+)").unwrap());
static SSH_CLOSED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Connection closed by (?:invalid|authenticating) user (\S+) (\S+) port").unwrap());
static F2B: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[(\S+)\] (Ban|Unban) (\S+)").unwrap());
static SUDO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(\S+) : (?:.*?; )?PWD=(\S+) ; USER=(\S+) ; (?:ENV=\S+ ; )?COMMAND=(.*)$").unwrap());
static OOM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Out of memory: Killed process (\d+) \((.+?)\)").unwrap());
static AUDIT_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(\w+)=("[^"]*"|\S+)"#).unwrap());

/// One fact: kind, one-line summary, structured data.
pub struct Fact {
    pub kind: &'static str,
    pub summary: String,
    pub data: Value,
}

/// A journal entry (`journalctl -o json`) to a fact, if it is one we care about.
pub fn journal_fact(r: &Value) -> Option<Fact> {
    let message = r.get("MESSAGE")?.as_str()?;
    let ident = r.get("SYSLOG_IDENTIFIER").and_then(Value::as_str).unwrap_or("");
    let unit = r.get("_SYSTEMD_UNIT").and_then(Value::as_str).unwrap_or("");
    let transport = r.get("_TRANSPORT").and_then(Value::as_str).unwrap_or("");
    let priority = r.get("PRIORITY").and_then(Value::as_str).and_then(|p| p.parse::<u8>().ok()).unwrap_or(6);
    if ident == "sshd" || ident == "sshd-session" || unit == "ssh.service" {
        if let Some(c) = SSH_ACCEPTED.captures(message) {
            return Some(Fact { kind: "ssh_login", summary: format!("ssh login {} from {} ({})", &c[2], &c[3], &c[1]), data: json!({"user": &c[2], "ip": &c[3], "method": &c[1]}) });
        }
        if let Some(c) = SSH_INVALID.captures(message) {
            return Some(Fact { kind: "ssh_failed", summary: format!("ssh failed: invalid user {} from {}", &c[1], &c[2]), data: json!({"user": &c[1], "ip": &c[2]}) });
        }
        if let Some(c) = SSH_FAILED.captures(message) {
            return Some(Fact { kind: "ssh_failed", summary: format!("ssh failed {} for {} from {}", &c[1], &c[2], &c[3]), data: json!({"user": &c[2], "ip": &c[3]}) });
        }
        if let Some(c) = SSH_CLOSED.captures(message) {
            return Some(Fact { kind: "ssh_failed", summary: format!("ssh closed while authenticating {} from {}", &c[1], &c[2]), data: json!({"user": &c[1], "ip": &c[2]}) });
        }
    }
    if ident.starts_with("fail2ban") || unit == "fail2ban.service" {
        if let Some(c) = F2B.captures(message) {
            let kind = if &c[2] == "Ban" { "ban" } else { "unban" };
            return Some(Fact { kind, summary: format!("{} {} ({})", &c[2].to_lowercase(), &c[3], &c[1]), data: json!({"jail": &c[1], "ip": &c[3]}) });
        }
    }
    if ident == "sudo" {
        if let Some(c) = SUDO.captures(message) {
            return Some(Fact { kind: "sudo", summary: format!("{} ran as {}: {}", &c[1], &c[3], c[4].trim()), data: json!({"user": &c[1], "target": &c[3], "command": c[4].trim()}) });
        }
    }
    if transport == "kernel" {
        if let Some(c) = OOM.captures(message) {
            return Some(Fact { kind: "oom_kill", summary: format!("{} (pid {}) killed by the OOM killer", &c[2], &c[1]), data: json!({"comm": &c[2], "pid": &c[1]}) });
        }
        if priority <= 2 {
            return Some(Fact { kind: "kernel_error", summary: format!("kernel: {}", message.chars().take(200).collect::<String>()), data: json!({}) });
        }
    }
    if ident == "systemd" && message.starts_with("Failed to start ") {
        return Some(Fact { kind: "unit_failed", summary: message.chars().take(200).collect(), data: json!({"message": message}) });
    }
    if unit == "caddy.service" && message.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(message) {
            let logger = v.get("logger").and_then(Value::as_str).unwrap_or("");
            if logger == "http.handlers.waf" && v.get("msg").and_then(Value::as_str) == Some("WAF rule violation detected") {
                let ip = v.get("client_ip").and_then(Value::as_str).unwrap_or("");
                let uri = v.get("uri").and_then(Value::as_str).unwrap_or("");
                return Some(Fact { kind: "waf_block", summary: format!("WAF blocked {} {}", ip, uri.chars().take(120).collect::<String>()), data: json!({"ip": ip, "uri": uri, "host": v.get("hostname")}) });
            }
            if logger == "http.log.access.public" {
                let status = v.get("status").and_then(Value::as_i64).unwrap_or(0);
                if status >= 500 {
                    let host = v.pointer("/request/host").and_then(Value::as_str).unwrap_or("");
                    let uri = v.pointer("/request/uri").and_then(Value::as_str).unwrap_or("");
                    return Some(Fact { kind: "http_5xx", summary: format!("{status} from {host} {}", uri.chars().take(120).collect::<String>()), data: json!({"host": host, "status": status, "uri": uri}) });
                }
            }
        }
    }
    None
}

/// An auditd SYSCALL line with one of our keys to a fact.
pub fn audit_fact(line: &str) -> Option<Fact> {
    if !line.starts_with("type=SYSCALL") {
        return None;
    }
    let mut fields = std::collections::HashMap::new();
    for c in AUDIT_FIELD.captures_iter(line) {
        fields.insert(c[1].to_string(), c[2].trim_matches('"').to_string());
    }
    let key = fields.get("key")?.clone();
    if key == "(null)" || key.is_empty() {
        return None;
    }
    let success = fields.get("success").map(|s| s == "yes").unwrap_or(false);
    if !success {
        return None;
    }
    let exe = fields.get("exe").cloned().unwrap_or_default();
    let uid = fields.get("auid").cloned().unwrap_or_default();
    // the daemon rewrites the firewall, WireGuard and Caddy files itself, unattended (no login uid)
    if exe == "/usr/local/bin/pocketcloud" && uid == "4294967295" {
        return None;
    }
    let kind = match key.as_str() {
        "modules" => "audit_module",
        "time" => "audit_time",
        "identity" | "sudoers" | "sshd" | "ssh_keys" | "firewall" | "wireguard" | "cron" | "systemd" | "pocketcloud" | "caddy" | "docker" => "audit_write",
        _ => return None,
    };
    let who = if uid == "4294967295" { "unattended".to_string() } else { format!("login uid {uid}") };
    Some(Fact { kind, summary: format!("{key} changed by {exe} ({who})"), data: json!({"key": key, "exe": exe, "auid": uid, "comm": fields.get("comm")}) })
}

/// A Falco JSON event to a fact.
pub fn falco_fact(line: &str) -> Option<Fact> {
    let v: Value = serde_json::from_str(line).ok()?;
    let rule = v.get("rule")?.as_str()?.to_string();
    let priority = v.get("priority").and_then(Value::as_str).unwrap_or("Notice").to_string();
    let output = v.get("output").and_then(Value::as_str).unwrap_or("").chars().take(300).collect::<String>();
    let container = v.pointer("/output_fields/container.name").and_then(Value::as_str).unwrap_or("").to_string();
    Some(Fact { kind: "falco", summary: format!("[{priority}] {rule}: {output}"), data: json!({"rule": rule, "priority": priority, "container": container}) })
}

async fn store(state: &Shared, source: &str, f: Fact) {
    if let Err(e) = db::add_event(&state.db, f.kind, source, &f.summary, &f.data).await {
        tracing::warn!("event not stored: {e}");
    }
}

/// `journalctl -o json --follow` from now on; restarted when it ends.
pub async fn journal_tailer(state: Shared) {
    loop {
        let child = Command::new("journalctl")
            .args(["-o", "json", "--follow", "-n", "0", "--no-pager"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        match child {
            Ok(mut child) => {
                let stdout = child.stdout.take().unwrap();
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    if let Ok(v) = serde_json::from_str::<Value>(&l) {
                        if let Some(f) = journal_fact(&v) {
                            store(&state, "journal", f).await;
                        }
                    }
                }
                let _ = child.wait().await;
                tracing::warn!("journal tailer ended, restarting");
            }
            Err(e) => tracing::warn!("journal tailer: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// Follow a text file that may be rotated or not exist yet (audit.log, falco.jsonl).
pub async fn file_tailer(state: Shared, path: &'static str, source: &'static str, parse: fn(&str) -> Option<Fact>) {
    loop {
        let child = Command::new("tail")
            .args(["-F", "-n", "0", path])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            let stdout = child.stdout.take().unwrap();
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if let Some(f) = parse(&l) {
                    store(&state, source, f).await;
                }
            }
            let _ = child.wait().await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// Docker events: containers dying, OOM kills, health changes; by compose project and service.
pub async fn docker_events(state: Shared) -> Result<()> {
    use bollard::system::EventsOptions;
    use futures_util::StreamExt;
    let docker = state.docker.clone().context("docker not available")?;
    loop {
        let mut filters = std::collections::HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        let mut stream = docker.events(Some(EventsOptions::<String> { filters, ..Default::default() }));
        while let Some(ev) = stream.next().await {
            let Ok(ev) = ev else { break };
            let action = ev.action.clone().unwrap_or_default();
            let attrs = ev.actor.as_ref().and_then(|a| a.attributes.clone()).unwrap_or_default();
            let app = attrs.get("com.docker.compose.project").cloned().unwrap_or_default();
            let service = attrs.get("com.docker.compose.service").cloned().unwrap_or_default();
            if app.is_empty() {
                continue;
            }
            let fact = match action.as_str() {
                "die" => {
                    let code = attrs.get("exitCode").cloned().unwrap_or_default();
                    if code == "0" {
                        None
                    } else {
                        Some(Fact { kind: "container_died", summary: format!("{app}/{service} exited with code {code}"), data: json!({"app": app, "service": service, "exit_code": code}) })
                    }
                }
                "oom" => Some(Fact { kind: "container_oom", summary: format!("{app}/{service} ran out of memory"), data: json!({"app": app, "service": service}) }),
                a if a.starts_with("health_status: unhealthy") => Some(Fact { kind: "container_unhealthy", summary: format!("{app}/{service} is unhealthy"), data: json!({"app": app, "service": service}) }),
                _ => None,
            };
            if let Some(f) = fact {
                store(&state, "docker", f).await;
            }
        }
        tracing::warn!("docker event stream ended, reconnecting");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(ident: &str, transport: &str, msg: &str) -> Value {
        json!({"MESSAGE": msg, "SYSLOG_IDENTIFIER": ident, "_TRANSPORT": transport, "_SYSTEMD_UNIT": format!("{ident}.service"), "PRIORITY": "6"})
    }

    #[test]
    fn journal_facts() {
        let f = journal_fact(&j("sshd", "syslog", "Accepted publickey for admin from 1.2.3.4 port 5555 ssh2: ED25519 SHA256:abc")).unwrap();
        assert_eq!((f.kind, f.data["ip"].as_str()), ("ssh_login", Some("1.2.3.4")));
        let f = journal_fact(&j("sshd", "syslog", "Invalid user bob from 9.9.9.9 port 1")).unwrap();
        assert_eq!(f.kind, "ssh_failed");
        let f = journal_fact(&j("fail2ban.server", "syslog", "2026-10-21 10:00:00,000 fail2ban.actions [123]: NOTICE [pocketcloud-waf] Ban 9.9.9.9")).unwrap();
        assert_eq!((f.kind, f.data["jail"].as_str()), ("ban", Some("pocketcloud-waf")));
        let f = journal_fact(&j("sudo", "syslog", "   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/ls -la")).unwrap();
        assert_eq!(f.data["command"], "/usr/bin/ls -la");
        let f = journal_fact(&j("kernel", "kernel", "Out of memory: Killed process 1234 (postgres) total-vm:100000kB")).unwrap();
        assert_eq!((f.kind, f.data["comm"].as_str()), ("oom_kill", Some("postgres")));
        let mut k = j("kernel", "kernel", "BUG: unable to handle page fault");
        k["PRIORITY"] = json!("2");
        assert_eq!(journal_fact(&k).unwrap().kind, "kernel_error");
        assert_eq!(journal_fact(&j("systemd", "journal", "Failed to start docker.service - Docker.")).unwrap().kind, "unit_failed");
        let mut c = j("caddy", "stdout", r#"{"level":"error","logger":"http.handlers.waf","msg":"WAF rule violation detected","hostname":"a.example.com","uri":"/?q=x","client_ip":"5.6.7.8"}"#);
        c["_SYSTEMD_UNIT"] = json!("caddy.service");
        assert_eq!(journal_fact(&c).unwrap().kind, "waf_block");
        let mut a = j("caddy", "stdout", r#"{"level":"info","logger":"http.log.access.public","msg":"handled request","request":{"host":"a.example.com","uri":"/x"},"status":502}"#);
        a["_SYSTEMD_UNIT"] = json!("caddy.service");
        assert_eq!(journal_fact(&a).unwrap().kind, "http_5xx");
        assert!(journal_fact(&j("cron", "syslog", "nothing")).is_none());
    }

    #[test]
    fn audit_and_falco() {
        let f = audit_fact(r#"type=SYSCALL msg=audit(1.0:1): arch=c00000b7 syscall=35 success=yes exit=0 auid=1000 comm="vi" exe="/usr/bin/vi" key="sshd""#).unwrap();
        assert_eq!((f.kind, f.data["key"].as_str()), ("audit_write", Some("sshd")));
        assert!(audit_fact(r#"type=SYSCALL msg=audit(1.0:1): success=no auid=1000 exe="/usr/bin/vi" key="sshd""#).is_none());
        assert_eq!(audit_fact(r#"type=SYSCALL msg=audit(1.0:1): success=yes auid=0 exe="/usr/bin/kmod" key="modules""#).unwrap().kind, "audit_module");
        assert!(audit_fact(r#"type=SYSCALL msg=audit(1.0:1): success=yes auid=4294967295 exe="/usr/local/bin/pocketcloud" key="firewall""#).is_none());
        assert!(audit_fact(r#"type=SYSCALL msg=audit(1.0:1): success=yes auid=1000 exe="/usr/local/bin/pocketcloud" key="firewall""#).is_some());
        let f = falco_fact(r#"{"priority":"Warning","rule":"Terminal shell in container","output":"A shell was spawned","output_fields":{"container.name":"site"}}"#).unwrap();
        assert_eq!((f.kind, f.data["priority"].as_str()), ("falco", Some("Warning")));
    }
}
