//! `pocketcloud backup <name> enable|disable|password`: switch backups of an installation on or off, or
//! derive the restic password from the recovery phrase for a manual restore.
use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};

use crate::cli::{BackupArgs, BackupCommand};
use crate::crypto::MasterKey;
use crate::install::{self, Installation};
use crate::remote::{self, Ssh};

pub struct BackupInput {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

pub fn ask() -> Result<BackupInput> {
    let theme = ColorfulTheme::default();
    println!("  Hetzner Object Storage: create a bucket and S3 credentials in the console first.");
    let endpoint: String = Input::with_theme(&theme).with_prompt("S3 endpoint").default("https://fsn1.your-objectstorage.com".into()).interact_text()?;
    let bucket: String = Input::with_theme(&theme).with_prompt("Bucket").interact_text()?;
    let access_key: String = Input::with_theme(&theme).with_prompt("Access key").interact_text()?;
    let secret_key: String = Password::with_theme(&theme).with_prompt("Secret key").interact()?;
    Ok(BackupInput { endpoint: endpoint.trim().to_string(), bucket: bucket.trim().to_string(), access_key: access_key.trim().to_string(), secret_key })
}

pub struct EmailInput {
    pub to: Vec<String>,
    pub from: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls: String,
    pub smtp_user: String,
    pub smtp_password: String,
}

pub fn ask_email() -> Result<EmailInput> {
    let theme = ColorfulTheme::default();
    let to: String = Input::with_theme(&theme).with_prompt("Send alerts to (comma-separated)").interact_text()?;
    let from: String = Input::with_theme(&theme).with_prompt("From address").interact_text()?;
    let smtp_host: String = Input::with_theme(&theme).with_prompt("SMTP host").interact_text()?;
    let smtp_port: u16 = Input::with_theme(&theme).with_prompt("SMTP port").default(587).interact_text()?;
    let smtp_tls: String = Input::with_theme(&theme).with_prompt("TLS (starttls, implicit, none)").default("starttls".into()).interact_text()?;
    let smtp_user: String = Input::with_theme(&theme).with_prompt("SMTP user (empty for none)").allow_empty(true).default(String::new()).interact_text()?;
    let smtp_password = if smtp_user.is_empty() { String::new() } else { Password::with_theme(&theme).with_prompt("SMTP password").interact()? };
    Ok(EmailInput {
        to: to.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        from: from.trim().to_string(),
        smtp_host: smtp_host.trim().to_string(),
        smtp_port,
        smtp_tls: smtp_tls.trim().to_string(),
        smtp_user: smtp_user.trim().to_string(),
        smtp_password,
    })
}

pub fn render_notify_section(e: Option<&EmailInput>, heartbeat_url: &str, falco: bool) -> String {
    let mut s = format!("\n[notify]\n# a dead man's switch URL (healthchecks.io style) pinged every five minutes while the daemon is healthy\nheartbeat_url = {heartbeat_url:?}\n");
    if let Some(e) = e {
        let to = e.to.iter().map(|t| format!("{t:?}")).collect::<Vec<_>>().join(", ");
        s += &format!(
            "\n[notify.email]\nto = [{to}]\nfrom = {:?}\nsmtp_host = {:?}\nsmtp_port = {}\nsmtp_tls = {:?}\nsmtp_user = {:?}\nsmtp_password = {:?}\n",
            e.from, e.smtp_host, e.smtp_port, e.smtp_tls, e.smtp_user, e.smtp_password
        );
    }
    s += "\n# [notify.webhook]\n# url = \"https://example.com/hook\"\n# token = \"\"\n";
    s += &format!("\n[monitor]\n# Falco runtime detection (eBPF); the installer adds or removes it on the next upgrade\nfalco = {falco}\n");
    s
}

pub fn render_section(b: &BackupInput) -> String {
    format!(
        "\n[backup]\n# nightly restic backup to S3-compatible storage; the repository password is derived from the master key\ns3_endpoint = {:?}\nbucket = {:?}\naccess_key = {:?}\nsecret_key = {:?}\nhour = 3\n",
        b.endpoint, b.bucket, b.access_key, b.secret_key
    )
}

/// Remove an existing `[backup]` section from a config text.
pub fn strip_section(config: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in config.lines() {
        let t = line.trim();
        if t == "[backup]" {
            skipping = true;
            continue;
        }
        if skipping && t.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.trim_end().to_string() + "\n"
}

pub async fn run(args: BackupArgs) -> Result<()> {
    let inst = Installation::load(&args.name)?;
    match args.command {
        BackupCommand::Password => {
            let phrase: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Recovery phrase (24 words)").interact_text()?;
            let key = MasterKey::from_phrase(&phrase)?;
            let local = std::fs::read_to_string(inst.dir()?.join("server-config.toml")).unwrap_or_default();
            if let Some(repo) = repo_from_config(&local) {
                println!("export RESTIC_REPOSITORY={repo}");
            }
            println!("export RESTIC_PASSWORD={}", *key.derive("restic"));
            println!("# plus AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY of the bucket; then: restic snapshots");
            Ok(())
        }
        BackupCommand::Enable => {
            let b = ask()?;
            let section = render_section(&b);
            apply(&inst, Some(&section)).await?;
            println!("backups enabled; the first one runs tonight at 03:30 server time, or now from the server page");
            Ok(())
        }
        BackupCommand::Disable => {
            if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Switch backups off? Existing snapshots stay in the bucket.").default(false).interact()? {
                return Ok(());
            }
            apply(&inst, None).await?;
            println!("backups disabled");
            Ok(())
        }
    }
}

fn repo_from_config(config: &str) -> Option<String> {
    let mut endpoint = None;
    let mut bucket = None;
    for line in config.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("s3_endpoint = ") {
            endpoint = Some(v.trim_matches('"').trim_end_matches('/').to_string());
        } else if let Some(v) = t.strip_prefix("bucket = ") {
            bucket = Some(v.trim_matches('"').to_string());
        }
    }
    Some(format!("s3:{}/{}", endpoint?, bucket?))
}

/// Rewrite the `[backup]` section locally and on the server, then restart the daemon.
async fn apply(inst: &Installation, section: Option<&str>) -> Result<()> {
    let local_path = inst.dir()?.join("server-config.toml");
    if let Ok(local) = std::fs::read_to_string(&local_path) {
        let mut text = strip_section(&local);
        if let Some(s) = section {
            text.push_str(s);
        }
        install::write_private(&local_path, &text)?;
    }
    let host = remote::pick_host(inst).await?;
    let ssh = Ssh::for_installation(inst, &host)?;
    // the edit runs in python on the server; the script travels base64-encoded so no quoting can break it
    let script = format!(
        r#"import re
p = "/etc/pocketcloud/config.toml"
s = open(p).read()
out = []
skip = False
for line in s.splitlines():
    t = line.strip()
    if t == "[backup]":
        skip = True
        continue
    if skip and t.startswith("["):
        skip = False
    if not skip:
        out.append(line)
text = "\n".join(out).rstrip() + "\n" + {section:?}
open(p, "w").write(text)
"#,
        section = section.unwrap_or("")
    );
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(script.as_bytes());
    ssh.run(&format!("echo {b64} | base64 -d | sudo python3 - && sudo systemctl restart pocketcloud")).await.context("update server config")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_and_renders() {
        let cfg = "name = \"x\"\n\n[backup]\nbucket = \"b\"\n\n[vpn]\nport = 1\n";
        assert_eq!(strip_section(cfg), "name = \"x\"\n\n[vpn]\nport = 1\n");
        let b = BackupInput { endpoint: "https://e".into(), bucket: "b".into(), access_key: "a".into(), secret_key: "s\"q".into() };
        let s = render_section(&b);
        assert!(s.contains("secret_key = \"s\\\"q\""));
        assert_eq!(repo_from_config(&s), Some("s3:https://e/b".into()));
    }
}
