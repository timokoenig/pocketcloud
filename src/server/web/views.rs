//! Template structs. Values are preformatted here so the templates stay plain.
use askama::Template;

use crate::server::db;
use crate::server::docker::ContainerInfo;
use crate::server::system::HostStatus;

pub struct Base {
    pub title: String,
    pub user: String,
    pub msg: Option<String>,
    pub error: Option<String>,
    pub version: &'static str,
    pub name: String,
}

impl Base {
    pub fn new(title: &str, user: &str, name: &str, flash: &super::auth::Flash) -> Base {
        Base {
            title: title.to_string(),
            user: user.to_string(),
            msg: flash.msg.clone(),
            error: flash.error.clone(),
            version: env!("CARGO_PKG_VERSION"),
            name: name.to_string(),
        }
    }
}

pub fn short_time(rfc3339: &str) -> String {
    match db::parse_time(rfc3339) {
        Some(t) => t.format("%Y-%m-%d %H:%M").to_string(),
        None => rfc3339.to_string(),
    }
}

pub fn ago(rfc3339: &str) -> String {
    let Some(t) = db::parse_time(rfc3339) else { return rfc3339.to_string() };
    let d = chrono::Utc::now() - t;
    if d.num_seconds() < 60 {
        "just now".into()
    } else if d.num_minutes() < 60 {
        format!("{} min ago", d.num_minutes())
    } else if d.num_hours() < 48 {
        format!("{} h ago", d.num_hours())
    } else {
        format!("{} days ago", d.num_days())
    }
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub message: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub error: Option<String>,
    pub name: String,
}

pub struct AppRow {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub status_detail: String,
    pub hosts: String,
    pub updated: String,
}

pub struct JobRow {
    pub id: i64,
    pub kind: String,
    pub app_name: String,
    pub status: String,
    pub created: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct Dashboard {
    pub base: Base,
    pub apps: Vec<AppRow>,
    pub jobs: Vec<JobRow>,
    pub host: HostStatus,
    pub docker_ok: bool,
    pub cert_problem: Option<String>,
}

#[derive(Template)]
#[template(path = "app_new.html")]
pub struct AppNew {
    pub base: Base,
    pub name: String,
    pub compose: String,
}

pub struct AppView {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub status_detail: String,
    pub desired: String,
    pub subnet: String,
    pub created: String,
    pub updated: String,
}

impl AppView {
    pub fn from(a: &db::App) -> AppView {
        AppView {
            id: a.id,
            name: a.name.clone(),
            status: a.status.clone(),
            status_detail: a.status_detail.clone(),
            desired: a.desired.clone(),
            subnet: crate::firewall::app_subnet(a.net_index as u32),
            created: short_time(&a.created),
            updated: ago(&a.updated),
        }
    }
}

pub struct RouteView {
    pub id: i64,
    pub host: String,
    pub service: String,
    pub port: i64,
    pub expose: String,
    pub waf: bool,
}

pub struct SecretView {
    pub key: String,
    pub updated: String,
}

pub struct ReleaseView {
    pub id: i64,
    pub outcome: String,
    pub created: String,
    pub images: Vec<String>,
}

#[derive(Template)]
#[template(path = "app.html")]
pub struct AppShow {
    pub base: Base,
    pub app: AppView,
    pub containers: Vec<ContainerInfo>,
    pub routes: Vec<RouteView>,
    pub secrets: Vec<SecretView>,
    pub releases: Vec<ReleaseView>,
    pub jobs: Vec<JobRow>,
    pub services: Vec<String>,
    pub active_job: Option<i64>,
    pub domains: Vec<String>,
    pub waf_available: bool,
    /// per service: container port from the compose file, for the route form
    pub hints: Vec<ServiceHint>,
    pub suggest: Option<ServiceHint>,
    /// `environment` entries of all services
    pub env: Vec<EnvView>,
    /// `${NAME}` placeholders in the compose file without a secret
    pub missing: Vec<String>,
}

pub struct ServiceHint {
    pub name: String,
    pub host: String,
    pub port: u16,
}

pub struct EnvView {
    pub service: String,
    pub key: String,
    pub value: String,
    /// value is `${NAME}`: name and whether a secret for it exists
    pub placeholder: Option<(String, bool)>,
}

#[derive(Template)]
#[template(path = "app_edit.html")]
pub struct AppEdit {
    pub base: Base,
    pub app: AppView,
    pub compose: String,
}

#[derive(Template)]
#[template(path = "job.html")]
pub struct JobPage {
    pub base: Base,
    pub id: i64,
    pub kind: String,
    pub status: String,
    pub app_id: Option<i64>,
    pub app_name: String,
    pub created: String,
    pub finished: String,
    pub log: String,
    pub running: bool,
}

#[derive(Template)]
#[template(path = "logs.html")]
pub struct LogsPage {
    pub base: Base,
    pub app: AppView,
    pub service: String,
    pub log: String,
    pub tail: usize,
}

pub struct PeerView {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub scope: String,
    pub created: String,
    pub last_handshake: String,
    pub endpoint: String,
}

pub struct NewPeer {
    pub name: String,
    pub config: String,
    pub qr_svg: String,
    pub file_name: String,
    pub download_token: String,
}

#[derive(Template)]
#[template(path = "vpn.html")]
pub struct VpnPage {
    pub base: Base,
    pub peers: Vec<PeerView>,
    pub new_peer: Option<NewPeer>,
    pub apps_cidr: String,
}

pub struct RegistryView {
    pub id: i64,
    pub host: String,
    pub username: String,
    pub updated: String,
}

#[derive(Template)]
#[template(path = "registries.html")]
pub struct RegistriesPage {
    pub base: Base,
    pub registries: Vec<RegistryView>,
}

pub struct CertView {
    pub domain: String,
    pub not_after: String,
    pub days_left: i64,
    pub last_error: String,
}

#[derive(Template)]
#[template(path = "server.html")]
pub struct ServerPage {
    pub base: Base,
    pub host: HostStatus,
    pub certs: Vec<CertView>,
    pub public_ips: Vec<String>,
    pub domains: Vec<String>,
    pub interface_host: String,
    pub vpn_port: u16,
    pub daemon_started: String,
    pub uptime: String,
    pub mem_used_pct: u64,
    pub disk_used_pct: u64,
    pub pending_checked: String,
    pub aide_checked: String,
    pub waf_available: bool,
    pub waf_events: Vec<crate::server::system::WafEvent>,
}

pub struct AuditView {
    pub at: String,
    pub username: String,
    pub action: String,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditPage {
    pub base: Base,
    pub entries: Vec<AuditView>,
}
