//! Validated operations on apps, shared by the interface (forms) and the MCP endpoint (tools): one place
//! decides what a valid route host or secret name is, audits as the actor that asked, and starts jobs.
use std::fmt;

use super::state::Shared;
use super::{compose, db, deploy, docker, jobs, reconcile};

/// `Invalid` is the caller's mistake, said in a sentence the user can act on; `Other` is ours.
#[derive(Debug)]
pub enum ActionError {
    Invalid(String),
    Other(anyhow::Error),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionError::Invalid(m) => f.write_str(m),
            ActionError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl<E: Into<anyhow::Error>> From<E> for ActionError {
    fn from(e: E) -> Self {
        ActionError::Other(e.into())
    }
}

pub type AResult<T> = Result<T, ActionError>;

fn invalid<T>(msg: impl Into<String>) -> AResult<T> {
    Err(ActionError::Invalid(msg.into()))
}

pub async fn app_by_name(state: &Shared, name: &str) -> AResult<db::App> {
    match db::app_by_name(&state.db, name.trim()).await? {
        Some(a) => Ok(a),
        None => invalid(format!("no app named `{}`", name.trim())),
    }
}

// ---- apps ----

pub async fn create_app(state: &Shared, actor: &str, name: &str, compose_text: &str) -> AResult<db::App> {
    let name = name.trim().to_lowercase();
    if let Err(e) = compose::validate_app_name(&name) {
        return invalid(e.to_string());
    }
    if db::app_by_name(&state.db, &name).await?.is_some() {
        return invalid("an app with this name exists");
    }
    if let Err(e) = compose::check(compose_text) {
        return invalid(format!("compose file: {e:#}"));
    }
    let app = db::create_app(&state.db, &name, compose_text).await?;
    db::audit(&state.db, actor, "app.create", &name).await?;
    Ok(app)
}

pub async fn update_compose(state: &Shared, actor: &str, app: &db::App, compose_text: &str) -> AResult<()> {
    if let Err(e) = compose::check(compose_text) {
        return invalid(format!("compose file: {e:#}"));
    }
    db::update_compose(&state.db, app.id, compose_text).await?;
    db::audit(&state.db, actor, "app.compose", &app.name).await?;
    Ok(())
}

// ---- routes ----

/// The certificate covers each configured domain and one label below it, and the interface host is taken.
pub fn route_host_ok(domains: &[String], interface_host: &str, host: &str) -> Result<(), &'static str> {
    let Some(domain) = domains.iter().find(|d| host == d.as_str() || host.ends_with(&format!(".{d}"))) else {
        return Err("the host must be one of the configured domains or one label below it");
    };
    let depth = host.split('.').count() - domain.split('.').count();
    if host.starts_with("*.") || depth > 1 || host.contains("..") {
        return Err("use the domain itself or exactly one label below it, the wildcard certificate covers only those");
    }
    if host == interface_host {
        return Err("that host is the interface");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn add_route(state: &Shared, actor: &str, app: &db::App, host: &str, service: &str, port: i64, expose: &str, waf: bool, headers: bool) -> AResult<()> {
    let host = host.trim().to_lowercase();
    if let Err(e) = route_host_ok(&state.config.domains, &state.config.interface_host, &host) {
        return invalid(e);
    }
    if !(1..=65535).contains(&port) {
        return invalid("port out of range");
    }
    if !matches!(expose, "public" | "internal") {
        return invalid("expose must be public or internal");
    }
    let services = compose::check(&app.compose).unwrap_or_default();
    if !services.iter().any(|s| s == service) {
        return invalid("unknown service");
    }
    if let Err(e) = db::add_route(&state.db, app.id, &host, service, port, expose, waf, headers).await {
        return invalid(format!("route not added: {e}"));
    }
    db::audit(&state.db, actor, "route.add", &format!("{} {host} -> {service}:{port} {expose} waf={waf} headers={headers}", app.name)).await?;
    if app.desired == "running" {
        reconcile::apply(state).await?;
    }
    Ok(())
}

pub async fn delete_route(state: &Shared, actor: &str, app: &db::App, route_id: i64) -> AResult<()> {
    db::delete_route(&state.db, app.id, route_id).await?;
    db::audit(&state.db, actor, "route.delete", &format!("{} route {route_id}", app.name)).await?;
    reconcile::apply(state).await?;
    Ok(())
}

// ---- secrets ----

/// Secret names are environment variable names.
pub fn secret_key_ok(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !key.starts_with(|c: char| c.is_ascii_digit())
}

/// The services a secret reaches, as stored: sorted, comma-separated, and empty for "every service"
/// (nothing asked for, every service asked for, or only unknown names).
pub fn secret_scope(services: &[String], requested: Option<&[String]>) -> String {
    let mut scope: Vec<&str> = requested.unwrap_or_default().iter().map(|s| s.trim()).filter(|s| services.iter().any(|x| x == s)).collect();
    scope.sort_unstable();
    scope.dedup();
    if scope.is_empty() || scope.len() == services.len() {
        String::new()
    } else {
        scope.join(",")
    }
}

/// Save a secret; an empty value only changes the services an existing secret reaches. Returns the message for the user.
pub async fn put_secret(state: &Shared, actor: &str, app: &db::App, key: &str, value: &str, services: Option<&[String]>) -> AResult<String> {
    let key = key.trim();
    if !secret_key_ok(key) {
        return invalid("secret names are environment variable names: letters, digits, underscores");
    }
    let known = compose::check(&app.compose).unwrap_or_default();
    let scope = secret_scope(&known, services);
    let scope_text = if scope.is_empty() { "all".to_string() } else { scope.clone() };
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        if !db::set_secret_services(&state.db, app.id, key, &scope).await? {
            return invalid("a new secret needs a value");
        }
        db::audit(&state.db, actor, "secret.scope", &format!("{} {key} {scope_text}", app.name)).await?;
        return Ok(format!("secret {key} now reaches {}, deploy to apply", if scope.is_empty() { "every service".to_string() } else { scope.replace(',', ", ") }));
    }
    db::put_secret(&state.db, app.id, key, &state.key.seal(value.as_bytes()), &scope).await?;
    db::audit(&state.db, actor, "secret.put", &format!("{} {key} -> {scope_text}", app.name)).await?;
    Ok(format!("secret {key} saved, deploy to apply"))
}

pub async fn delete_secret(state: &Shared, actor: &str, app: &db::App, key: &str) -> AResult<()> {
    db::delete_secret(&state.db, app.id, key).await?;
    db::audit(&state.db, actor, "secret.delete", &format!("{} {key}", app.name)).await?;
    Ok(())
}

// ---- egress ----

/// `all`, `none`, or `ports` with a list like `587, 443` → the stored form (`all` | `none` | `587,443`).
pub fn parse_egress(mode: &str, ports: &str) -> Result<String, String> {
    match mode {
        "all" => Ok("all".into()),
        "none" => Ok("none".into()),
        "ports" => {
            let mut out = Vec::new();
            for p in ports.split([',', ' ', ';']).filter(|p| !p.is_empty()) {
                match p.parse::<u16>() {
                    Ok(n) if n > 0 => out.push(n.to_string()),
                    _ => return Err(format!("`{p}` is not a port")),
                }
            }
            if out.is_empty() {
                return Err("list at least one TCP port, or choose none".into());
            }
            Ok(out.join(","))
        }
        _ => Err("mode must be all, none or ports".into()),
    }
}

pub async fn set_egress(state: &Shared, actor: &str, app: &db::App, egress: &str) -> AResult<()> {
    db::set_app_egress(&state.db, app.id, egress).await?;
    db::audit(&state.db, actor, "app.egress", &format!("{} {egress}", app.name)).await?;
    if app.desired == "running" {
        reconcile::apply(state).await?;
    }
    Ok(())
}

// ---- jobs ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    /// pull the images and bring the app up, health-gated, rolled back on failure
    Deploy,
    /// recreate the containers with the images pinned to the last deployment
    Apply,
    /// bring the app up again without pulling
    Start,
    /// remove the containers and the network, keep the volumes
    Stop,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Deploy => "deploy",
            JobKind::Apply => "apply",
            JobKind::Start => "start",
            JobKind::Stop => "stop",
        }
    }
}

/// Start a deploy, apply, start or stop job for the app; one job per app at a time. Returns the job id.
pub async fn start_job(state: &Shared, actor: &str, app: &db::App, kind: JobKind) -> AResult<i64> {
    if kind == JobKind::Deploy && state.docker.is_none() {
        return invalid("docker is not available");
    }
    db::audit(&state.db, actor, &format!("app.{}", kind.as_str()), &app.name).await?;
    let redact = deploy::secret_values(state, app.id).await?;
    let app_id = app.id;
    let spawned = match kind {
        JobKind::Stop => jobs::spawn(state, "stop", Some(app_id), redact, move |s, log| deploy::stop(s, app_id, log)).await,
        _ => {
            let pull = kind == JobKind::Deploy;
            jobs::spawn(state, kind.as_str(), Some(app_id), redact, move |s, log| deploy::deploy(s, app_id, log, pull)).await
        }
    };
    match spawned {
        Ok(id) => Ok(id),
        Err(e) => invalid(e.to_string()),
    }
}

// ---- logs ----

/// The last `tail` lines of one service's container, secret values redacted.
pub async fn service_logs(state: &Shared, app: &db::App, containers: &[docker::ContainerInfo], service: &str, tail: usize) -> anyhow::Result<String> {
    let Some(d) = &state.docker else { return Ok("docker is not available".into()) };
    let Some(c) = containers.iter().find(|c| c.service == service) else {
        return Ok("no container for this service; deploy the app to start it".into());
    };
    let raw = docker::logs(d, &c.id, tail).await?;
    Ok(jobs::Log::new(state.db.clone(), 0, deploy::secret_values(state, app.id).await?).redact(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> Vec<String> {
        vec!["example.com".into(), "other.org".into()]
    }

    #[test]
    fn route_hosts() {
        let d = domains();
        assert!(route_host_ok(&d, "pocketcloud.example.com", "example.com").is_ok());
        assert!(route_host_ok(&d, "pocketcloud.example.com", "shop.example.com").is_ok());
        assert!(route_host_ok(&d, "pocketcloud.example.com", "other.org").is_ok());
        assert!(route_host_ok(&d, "pocketcloud.example.com", "a.b.example.com").is_err(), "two labels");
        assert!(route_host_ok(&d, "pocketcloud.example.com", "*.example.com").is_err(), "wildcard");
        assert!(route_host_ok(&d, "pocketcloud.example.com", "evil.com").is_err(), "foreign domain");
        assert!(route_host_ok(&d, "pocketcloud.example.com", "notexample.com").is_err(), "suffix without dot");
        assert!(route_host_ok(&d, "pocketcloud.example.com", "pocketcloud.example.com").is_err(), "the interface");
    }

    #[test]
    fn secret_keys_and_scope() {
        assert!(secret_key_ok("POSTGRES_PASSWORD"));
        assert!(!secret_key_ok("1ABC"));
        assert!(!secret_key_ok("A-B"));
        assert!(!secret_key_ok(""));
        let services = vec!["db".to_string(), "web".to_string()];
        assert_eq!(secret_scope(&services, None), "");
        assert_eq!(secret_scope(&services, Some(&["web".into(), "db".into()])), "", "every service is all");
        assert_eq!(secret_scope(&services, Some(&["web".into()])), "web");
        assert_eq!(secret_scope(&services, Some(&["web".into(), "mailer".into()])), "web", "unknown names are dropped");
        assert_eq!(secret_scope(&services, Some(&["mailer".into()])), "", "only unknown names means all");
    }

    #[test]
    fn egress_modes() {
        assert_eq!(parse_egress("all", "").unwrap(), "all");
        assert_eq!(parse_egress("none", "ignored").unwrap(), "none");
        assert_eq!(parse_egress("ports", "587, 443").unwrap(), "587,443");
        assert!(parse_egress("ports", "").is_err());
        assert!(parse_egress("ports", "x").is_err());
        assert!(parse_egress("open", "").is_err());
    }
}
