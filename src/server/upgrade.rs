//! The daemon upgrades itself: release assets verified against their checksums into the stage directory, then
//! the installer runs as a transient unit outside the daemon's sandbox and restarts it.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use super::jobs::Log;
use super::state::Shared;
use crate::release;

pub const STAGE: &str = "/opt/pocketcloud/stage";

async fn arch_target() -> Result<&'static str> {
    let out = super::system::run("uname", &["-m"]).await?;
    Ok(release::target_for_arch(&out))
}

/// Download the release into the stage directory; `version` empty means the newest.
pub async fn stage_release(version: &str, log: &Log) -> Result<String> {
    let version = if version.is_empty() { release::latest_version().await.context("newest release")? } else { version.trim_start_matches('v').to_string() };
    let target = arch_target().await?;
    let stage = Path::new(STAGE);
    let _ = std::fs::remove_dir_all(stage);
    std::fs::create_dir_all(stage)?;
    for asset in [format!("pocketcloud-{target}"), format!("caddy-{target}")] {
        log.line(format!("downloading {asset} {version}")).await;
        let dest = stage.join(asset.split('-').next().unwrap_or("pocketcloud"));
        release::fetch_verified(&version, &asset, &dest).await?;
        log.line("  checksum verified").await;
    }
    write_assets_of_staged(stage)?;
    Ok(version)
}

/// The installer that runs is the one embedded in the staged binary, so every change a release brings to the
/// server configuration applies with that release; the running daemon only hands over.
fn write_assets_of_staged(stage: &Path) -> Result<()> {
    let bin = stage.join("pocketcloud");
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    let out = std::process::Command::new(&bin).arg("write-assets").arg(stage).output().context("run the staged binary")?;
    if out.status.success() {
        return Ok(());
    }
    // a staged binary from before this command exists: fall back to the running one's installer
    release::write_assets(stage)
}

/// Use binaries someone put into a directory (an upload from the interface, a developer's scp).
pub fn stage_from_dir(dir: &Path, log_lines: &mut Vec<String>) -> Result<()> {
    let stage = Path::new(STAGE);
    if dir != stage {
        let _ = std::fs::remove_dir_all(stage);
        std::fs::create_dir_all(stage)?;
        for name in ["pocketcloud", "caddy"] {
            let src = dir.join(name);
            if src.exists() {
                std::fs::copy(&src, stage.join(name))?;
                log_lines.push(format!("{name}: {} bytes", std::fs::metadata(&src)?.len()));
            }
        }
    }
    if !stage.join("pocketcloud").exists() {
        bail!("no pocketcloud binary in {}", dir.display());
    }
    write_assets_of_staged(stage)?;
    Ok(())
}

/// Start the installer detached; it restarts this daemon, so the job ends with "installer started".
pub async fn run_installer(log: &Log) -> Result<()> {
    let stage = PathBuf::from(STAGE);
    if !stage.join("install.sh").exists() {
        bail!("nothing staged");
    }
    super::system::run("chmod", &["0755", &stage.join("pocketcloud").display().to_string()]).await?;
    super::system::run(
        "systemd-run",
        &["--unit", "pocketcloud-upgrade", "--collect", "--quiet", "--setenv=DEBIAN_FRONTEND=noninteractive", "--setenv=NEEDRESTART_SUSPEND=1", "/bin/bash", &stage.join("install.sh").display().to_string()],
    )
    .await
    .context("start the installer")?;
    log.line("installer started as pocketcloud-upgrade; the daemon restarts in a moment, the interface comes back within a minute").await;
    log.line("its output: journalctl -u pocketcloud-upgrade").await;
    Ok(())
}

/// Upgrade to a release, as a job.
pub async fn upgrade_job(state: Shared, version: String, log: Log) -> Result<()> {
    if state.config.dev {
        bail!("no upgrades in dev mode");
    }
    let v = stage_release(&version, &log).await?;
    log.line(format!("staged release {v}")).await;
    run_installer(&log).await
}
