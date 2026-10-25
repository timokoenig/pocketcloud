use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::config::Config;
use super::db::Db;
use super::dns::InternalNames;
use super::system::HostStatus;
use crate::crypto::MasterKey;
use crate::hetzner::Hetzner;

pub struct State {
    pub config: Config,
    pub db: Db,
    pub key: MasterKey,
    pub docker: Option<bollard::Docker>,
    /// DNS zone access (certificate challenge, public records); the server has no cloud token
    pub dns_api: Hetzner,
    pub internal_names: InternalNames,
    /// Public addresses of the server, read from its own interface
    pub public_ips: RwLock<Vec<String>>,
    pub reconcile_lock: Mutex<()>,
    pub host: RwLock<HostStatus>,
    pub started: chrono::DateTime<chrono::Utc>,
    /// Freshly created VPN configs, downloadable once within a few minutes: token -> (file name, config, created)
    pub pending_configs: Mutex<HashMap<String, (String, String, std::time::Instant)>>,
    /// Caddy was built with the Coraza module (checked once at start)
    pub waf_available: bool,
}

pub type Shared = Arc<State>;
