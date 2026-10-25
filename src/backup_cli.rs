//! `pocketcloud backup <name> enable|disable|password`: switch backups of an installation on or off, or
//! derive the restic password from the recovery phrase for a manual restore.
use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};

use crate::cli::{BackupArgs, BackupCommand};
use crate::crypto::MasterKey;
use crate::install::{self, Installation};
use crate::remote::{self, Ssh};
use crate::wireguard::HUB_IP;

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
    let ip = inst.server.ipv4.clone().unwrap_or_default();
    let host = if remote::tcp_open(&format!("{HUB_IP}:22"), 3).await {
        HUB_IP.to_string()
    } else if remote::tcp_open(&format!("{ip}:22"), 4).await {
        ip
    } else {
        anyhow::bail!("server not reachable; activate the VPN or run: pocketcloud rescue {} open-ssh", inst.name);
    };
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
