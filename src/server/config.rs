//! /etc/pocketcloud/config.toml, written by setup, root only.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Name of the installation, also the hostname
    pub name: String,
    /// Domains with a wildcard certificate; the first one carries the interface
    pub domains: Vec<String>,
    /// Host name of the interface, pocketcloud.<first domain> by default
    pub interface_host: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_key_file")]
    pub master_key_file: PathBuf,
    /// Local address the daemon's HTTP listens on; Caddy proxies the interface host to it
    #[serde(default = "default_listen")]
    pub listen: String,
    pub hetzner: HetznerConfig,
    pub vpn: VpnConfig,
    pub acme: AcmeConfig,
    /// Seeded into the users table on first start, then ignored
    pub bootstrap_user: Option<BootstrapUser>,
    /// Developer mode: no nftables, wireguard, caddy, docker or acme calls, for running on a laptop
    #[serde(default)]
    pub dev: bool,
}

fn default_data_dir() -> PathBuf {
    "/var/lib/pocketcloud".into()
}
fn default_key_file() -> PathBuf {
    "/etc/pocketcloud/master.key".into()
}
fn default_listen() -> String {
    "127.0.0.1:7788".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HetznerConfig {
    /// Token of the project that holds the server
    pub token: String,
    /// Token of the project that holds the DNS zones; the server token when empty
    #[serde(default)]
    pub dns_token: String,
    pub server_id: i64,
    pub firewall_id: i64,
}

impl HetznerConfig {
    pub fn dns_token(&self) -> &str {
        if self.dns_token.is_empty() {
            &self.token
        } else {
            &self.dns_token
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub port: u16,
    pub hub_private_key: String,
    /// Upstream resolvers for the VPN DNS
    #[serde(default = "default_upstreams")]
    pub dns_upstreams: Vec<String>,
    /// The device created by setup; imported when the peers table is empty
    pub initial_peer: Option<InitialPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialPeer {
    pub name: String,
    pub public_key: String,
    pub psk: String,
    pub ip: String,
    pub scope: String,
}

fn default_upstreams() -> Vec<String> {
    vec!["185.12.64.1:53".into(), "185.12.64.2:53".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub email: String,
    /// "production" or "staging"
    #[serde(default = "default_acme_env")]
    pub environment: String,
}

fn default_acme_env() -> String {
    "production".into()
}

impl AcmeConfig {
    pub fn directory_url(&self) -> &'static str {
        if self.environment == "staging" {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapUser {
    pub username: String,
    pub password_hash: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let c: Config = toml::from_str(&s).context("parse config")?;
        Ok(c)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("pocketcloud.db")
    }
    pub fn apps_dir(&self) -> PathBuf {
        self.data_dir.join("apps")
    }
    pub fn certs_dir(&self) -> PathBuf {
        self.data_dir.join("certs")
    }
    pub fn acme_dir(&self) -> PathBuf {
        self.data_dir.join("acme")
    }
    /// tmpfs, env files and docker credentials live here only while needed
    pub fn run_dir(&self) -> PathBuf {
        if self.dev {
            self.data_dir.join("run")
        } else {
            "/run/pocketcloud".into()
        }
    }
}
