//! SSH to the server with the installation's key, through the system ssh binary.
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

use crate::install::Installation;

pub struct Ssh {
    pub user: String,
    pub host: String,
    pub key: String,
    pub known_hosts: String,
}

impl Ssh {
    pub fn for_installation(inst: &Installation, host: &str) -> Result<Ssh> {
        Ok(Ssh {
            user: inst.server.ssh_user.clone(),
            host: host.to_string(),
            key: inst.ssh_key_path()?.display().to_string(),
            known_hosts: inst.dir()?.join("known_hosts").display().to_string(),
        })
    }

    pub fn base_args(&self) -> Vec<String> {
        vec![
            "-i".into(),
            self.key.clone(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", self.known_hosts),
            "-o".into(),
            "LogLevel=ERROR".into(),
        ]
    }

    fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Run a command, return its stdout; stderr goes to the user.
    pub async fn run(&self, cmd: &str) -> Result<String> {
        let out = Command::new("ssh").args(self.base_args()).arg(self.target()).arg(cmd).stdin(Stdio::null()).output().await.context("ssh")?;
        if !out.status.success() {
            bail!("ssh {}: {}{}", cmd, String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Run a command with the terminal attached, so the user sees it live.
    pub async fn run_live(&self, cmd: &str) -> Result<()> {
        let status = Command::new("ssh").args(self.base_args()).arg(self.target()).arg(cmd).status().await.context("ssh")?;
        if !status.success() {
            bail!("remote command failed: {cmd}");
        }
        Ok(())
    }

    /// Interactive shell.
    pub async fn shell(&self) -> Result<()> {
        let status = Command::new("ssh").args(self.base_args()).arg("-t").arg(self.target()).status().await?;
        if !status.success() {
            bail!("ssh exited with {}", status.code().unwrap_or(-1));
        }
        Ok(())
    }

    pub async fn reachable(&self) -> bool {
        Command::new("ssh")
            .args(self.base_args())
            .arg("-o")
            .arg("ConnectTimeout=5")
            .arg(self.target())
            .arg("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Upload a local directory into a remote directory (created as root).
    pub async fn upload_dir(&self, local: &Path, remote: &str) -> Result<()> {
        let tar = std::process::Command::new("tar")
            .arg("--no-xattrs")
            .arg("-C")
            .arg(local)
            .arg("-czf")
            .arg("-")
            .arg(".")
            .env("COPYFILE_DISABLE", "1")
            .stdout(Stdio::piped())
            .spawn()
            .context("tar")?;
        let status = Command::new("ssh")
            .args(self.base_args())
            .arg(self.target())
            .arg(format!("sudo rm -rf {remote} && sudo mkdir -p {remote} && sudo tar -xzf - -C {remote}"))
            .stdin(Stdio::from(tar.stdout.unwrap()))
            .status()
            .await?;
        if !status.success() {
            bail!("upload to {remote} failed");
        }
        Ok(())
    }

    /// Pipe a string into a root-owned file.
    pub async fn write_root_file(&self, remote: &str, mode: &str, content: &str) -> Result<()> {
        let mut child = Command::new("ssh")
            .args(self.base_args())
            .arg(self.target())
            .arg(format!("sudo install -D -m {mode} /dev/stdin {remote}"))
            .stdin(Stdio::piped())
            .spawn()?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(content.as_bytes()).await?;
        }
        let status = child.wait().await?;
        if !status.success() {
            bail!("writing {remote} failed");
        }
        Ok(())
    }
}

/// The address to reach the server on: the VPN hub when the tunnel is up, else the public address when
/// rescue opened ssh. Uses real ssh logins, not bare TCP probes: an unauthenticated connect is logged by sshd
/// as a pre-auth close and counted by fail2ban's aggressive mode.
pub async fn pick_host(inst: &crate::install::Installation) -> Result<String> {
    let hub = crate::wireguard::HUB_IP.to_string();
    if Ssh::for_installation(inst, &hub)?.reachable().await {
        return Ok(hub);
    }
    if let Some(ip) = inst.server.ipv4.clone() {
        if Ssh::for_installation(inst, &ip)?.reachable().await {
            return Ok(ip);
        }
    }
    bail!("server not reachable; activate the VPN or run: pocketcloud rescue {} open-ssh", inst.name)
}

pub async fn tcp_open(addr: &str, timeout_secs: u64) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), tokio::net::TcpStream::connect(addr)).await.map(|r| r.is_ok()).unwrap_or(false)
}

pub async fn my_public_ipv4() -> Result<String> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
    for url in ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://checkip.amazonaws.com"] {
        if let Ok(r) = client.get(url).send().await {
            if let Ok(t) = r.text().await {
                let t = t.trim().to_string();
                if t.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Ok(t);
                }
            }
        }
    }
    bail!("could not determine your public IPv4 address")
}

/// Which release binary the server needs, from the Hetzner architecture name.
pub fn linux_target(architecture: &str) -> &'static str {
    if architecture == "arm" {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}


pub fn release_asset_url(asset: &str) -> String {
    format!(
        "https://github.com/timokoenig/pocketcloud/releases/download/v{}/{asset}",
        env!("CARGO_PKG_VERSION")
    )
}

/// Caddy with the Coraza WAF, same source options as the server binary.
pub async fn fetch_caddy_binary(local: Option<&Path>, target: &str, dest: &Path) -> Result<()> {
    if let Some(p) = local {
        std::fs::copy(p, dest).with_context(|| format!("copy {}", p.display()))?;
        return Ok(());
    }
    fetch_release_asset(&format!("caddy-{target}"), dest, "build caddy with scripts/build-caddy.sh and pass --caddy-binary").await
}

/// Download a release asset and verify it against the `.sha256` file published next to it. Nothing runs on
/// the server that did not match the sum the release workflow wrote.
async fn fetch_release_asset(asset: &str, dest: &Path, hint: &str) -> Result<()> {
    let url = release_asset_url(asset);
    println!("downloading {url}");
    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        bail!("download failed ({}); {hint}", resp.status());
    }
    let bytes = resp.bytes().await?;
    let sums = reqwest::get(format!("{url}.sha256")).await?;
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

pub async fn fetch_server_binary(local: Option<&Path>, target: &str, dest: &Path) -> Result<()> {
    if let Some(p) = local {
        std::fs::copy(p, dest).with_context(|| format!("copy {}", p.display()))?;
        return Ok(());
    }
    fetch_release_asset(&format!("pocketcloud-{target}"), dest, "build the linux binary with scripts/build-linux.sh and pass --server-binary").await
}
