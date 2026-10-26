//! Release assets on GitHub: where they are, how they are verified, which one fits the server.
use anyhow::{bail, Context, Result};
use std::path::Path;

pub const REPO: &str = "timokoenig/pocketcloud";

pub fn asset_url(version: &str, asset: &str) -> String {
    format!("https://github.com/{REPO}/releases/download/v{}/{asset}", version.trim_start_matches('v'))
}

/// The Rust target of a Linux machine from `uname -m`.
pub fn target_for_arch(arch: &str) -> &'static str {
    if arch.trim() == "aarch64" || arch.trim() == "arm64" {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

/// Newest release version on GitHub, without the `v`.
pub async fn latest_version() -> Result<String> {
    let client = reqwest::Client::builder().user_agent("pocketcloud").timeout(std::time::Duration::from_secs(20)).build()?;
    let v: serde_json::Value = client.get(format!("https://api.github.com/repos/{REPO}/releases/latest")).send().await?.error_for_status()?.json().await?;
    let tag = v.get("tag_name").and_then(|t| t.as_str()).context("no tag_name in the release")?;
    Ok(tag.trim_start_matches('v').to_string())
}

/// Download one asset and verify it against the `.sha256` file published next to it. Nothing runs on the server
/// that did not match the sum the release workflow wrote.
pub async fn fetch_verified(version: &str, asset: &str, dest: &Path) -> Result<()> {
    let url = asset_url(version, asset);
    let client = reqwest::Client::builder().user_agent("pocketcloud").timeout(std::time::Duration::from_secs(300)).build()?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        bail!("download of {asset} failed ({})", resp.status());
    }
    let bytes = resp.bytes().await?;
    let sums = client.get(format!("{url}.sha256")).send().await?;
    if !sums.status().is_success() {
        bail!("no checksum published for {asset}; refusing to install it unverified");
    }
    let expected = sums.text().await?.split_whitespace().next().unwrap_or("").to_lowercase();
    use sha2::Digest;
    let actual = hex::encode(sha2::Sha256::digest(&bytes));
    if expected != actual {
        bail!("checksum mismatch for {asset}: expected {expected}, got {actual}");
    }
    std::fs::write(dest, &bytes)?;
    Ok(())
}

/// Everything the installer needs besides the two binaries, from the assets compiled into this binary.
pub fn write_assets(stage: &Path) -> Result<()> {
    std::fs::create_dir_all(stage.join("units"))?;
    std::fs::write(stage.join("install.sh"), include_str!("../assets/install.sh"))?;
    std::fs::write(stage.join("units/pocketcloud.service"), include_str!("../assets/units/pocketcloud.service"))?;
    std::fs::write(stage.join("units/pocketcloud-aide.service"), include_str!("../assets/units/pocketcloud-aide.service"))?;
    std::fs::write(stage.join("units/pocketcloud-aide.timer"), include_str!("../assets/units/pocketcloud-aide.timer"))?;
    std::fs::write(stage.join("audit.rules"), include_str!("../assets/audit.rules"))?;
    std::fs::write(stage.join("aide.conf"), include_str!("../assets/aide.conf"))?;
    std::fs::write(stage.join("logrotate"), include_str!("../assets/logrotate"))?;
    std::fs::create_dir_all(stage.join("hardening"))?;
    std::fs::write(stage.join("hardening/sshd.conf"), include_str!("../assets/hardening/sshd.conf"))?;
    std::fs::write(stage.join("hardening/sysctl.conf"), include_str!("../assets/hardening/sysctl.conf"))?;
    std::fs::write(stage.join("hardening/fail2ban.local"), include_str!("../assets/hardening/fail2ban.local"))?;
    std::fs::write(stage.join("hardening/fail2ban-waf.conf"), include_str!("../assets/hardening/fail2ban-waf.conf"))?;
    std::fs::write(stage.join("hardening/fail2ban-main.local"), include_str!("../assets/hardening/fail2ban-main.local"))?;
    std::fs::write(stage.join("hardening/apt-unattended.conf"), include_str!("../assets/hardening/apt-unattended.conf"))?;
    std::fs::write(stage.join("hardening/journald.conf"), include_str!("../assets/hardening/journald.conf"))?;
    Ok(())
}
