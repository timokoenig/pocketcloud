//! Local state of an installation: ~/.config/pocketcloud/<name>/
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Installation {
    pub name: String,
    pub created: Option<DateTime<Utc>>,
    /// Setup progresses through steps; a re-run continues where it stopped.
    #[serde(default)]
    pub step: Step,
    pub hetzner: Hetzner,
    pub server: ServerInfo,
    pub vpn: Vpn,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    #[default]
    New,
    Planned,
    Created,
    Installed,
    VpnVerified,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hetzner {
    pub server_id: Option<i64>,
    pub server_name: String,
    pub firewall_id: Option<i64>,
    pub ssh_key_id: Option<i64>,
    /// Zones of the domains live in another project when set
    pub dns_separate_project: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub location: String,
    pub server_type: String,
    pub ssh_user: String,
    pub interface_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vpn {
    pub port: u16,
    pub hub_public_key: String,
    pub device_name: String,
    pub device_ip: String,
}

pub fn root_dir() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().ok_or_else(|| anyhow!("no home directory"))?;
    Ok(dirs.home_dir().join(".config").join("pocketcloud"))
}

pub fn dir(name: &str) -> Result<PathBuf> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(anyhow!("installation name must be alphanumeric with dashes"));
    }
    Ok(root_dir()?.join(name))
}

pub fn ensure_dir(name: &str) -> Result<PathBuf> {
    let d = dir(name)?;
    fs::create_dir_all(&d)?;
    set_mode(&d, 0o700)?;
    Ok(d)
}

pub fn set_mode(p: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

pub fn write_private(p: &Path, content: &str) -> Result<()> {
    fs::write(p, content).with_context(|| format!("write {}", p.display()))?;
    set_mode(p, 0o600)
}

impl Installation {
    pub fn path(name: &str) -> Result<PathBuf> {
        Ok(dir(name)?.join("install.toml"))
    }

    pub fn load(name: &str) -> Result<Installation> {
        let p = Self::path(name)?;
        let s = fs::read_to_string(&p).with_context(|| format!("no installation {name} ({})", p.display()))?;
        Ok(toml::from_str(&s)?)
    }

    pub fn load_or_new(name: &str) -> Result<Installation> {
        match Self::load(name) {
            Ok(i) => Ok(i),
            Err(_) if !Self::path(name)?.exists() => Ok(Installation { name: name.to_string(), ..Default::default() }),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self) -> Result<()> {
        ensure_dir(&self.name)?;
        write_private(&Self::path(&self.name)?, &toml::to_string_pretty(self)?)
    }

    pub fn dir(&self) -> Result<PathBuf> {
        dir(&self.name)
    }

    pub fn ssh_key_path(&self) -> Result<PathBuf> {
        Ok(self.dir()?.join("id_ed25519"))
    }

    /// The file name becomes the tunnel name when imported: pocketcloud-<installation>.
    pub fn vpn_config_path(&self) -> Result<PathBuf> {
        let new = self.dir()?.join(format!("pocketcloud-{}.conf", self.name));
        let old = self.dir()?.join(format!("vpn-{}.conf", self.vpn.device_name));
        if !new.exists() && old.exists() {
            std::fs::rename(&old, &new)?;
        }
        Ok(new)
    }

    pub fn hetzner_token_path(&self) -> Result<PathBuf> {
        Ok(self.dir()?.join("hetzner.token"))
    }

    pub fn interface_url(&self) -> String {
        format!("https://{}", self.server.interface_host)
    }
}
