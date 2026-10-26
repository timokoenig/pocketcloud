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
    /// Seeds for the database on first start only; afterwards the interface owns backups and notifications
    #[serde(default)]
    pub backup: Option<BackupConfig>,
    #[serde(default)]
    pub notify: NotifyConfig,
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
    /// Token of the project that holds the DNS zones. The only Hetzner credential the server holds: it needs it
    /// for the certificate challenge and the public records, nothing else. The cloud token stays on the laptop.
    #[serde(default)]
    pub dns_token: String,
    /// Older configs: the cloud token; only used when `dns_token` is empty. The installer removes it.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub server_id: i64,
    #[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotifyConfig {
    #[serde(default)]
    pub email: Option<EmailConfig>,
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
    /// GET every five minutes while the daemon is healthy; a dead man's switch service mails you when it stops
    #[serde(default)]
    pub heartbeat_url: String,
}

impl NotifyConfig {
    pub fn any(&self) -> bool {
        self.email.is_some() || self.webhook.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub to: Vec<String>,
    pub from: String,
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// starttls | implicit | none
    #[serde(default = "default_smtp_tls")]
    pub smtp_tls: String,
    #[serde(default)]
    pub smtp_user: String,
    #[serde(default)]
    pub smtp_password: String,
}

fn default_smtp_port() -> u16 {
    587
}
fn default_smtp_tls() -> String {
    "starttls".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub token: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub s3_endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    /// local hour of the nightly run (minute 30)
    #[serde(default = "default_backup_hour")]
    pub hour: u8,
}

fn default_backup_hour() -> u8 {
    3
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
