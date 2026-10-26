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
    /// latest one-minute sample of host numbers
    pub sample: RwLock<super::system::Sample>,
    /// Docker API answered the last ping
    pub docker_ok: std::sync::atomic::AtomicBool,
    /// alert keys whose condition is true but has not held long enough yet
    pub alert_pending: Mutex<HashMap<String, std::time::Instant>>,
    /// opened and resolved alerts waiting for the next notification batch
    pub notify_queue: Mutex<Vec<super::notify::Change>>,
    /// open alerts that are point events (close silently)
    pub point_events: Mutex<std::collections::HashSet<String>>,
    /// the last alert evaluation succeeded (gates the heartbeat)
    pub tick_ok: std::sync::atomic::AtomicBool,
    /// unix time of the last journal line the collector saw
    pub journal_seen: std::sync::atomic::AtomicI64,
    /// consecutive failed route probes per host
    pub probe_failures: Mutex<HashMap<String, u32>>,
    /// alert keys notified in the last hour (no repeats while flapping)
    pub notified: Mutex<HashMap<String, std::time::Instant>>,
}

pub type Shared = Arc<State>;
