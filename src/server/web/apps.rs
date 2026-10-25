use axum::extract::{Path, Query, State};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use super::auth::{Flash, User};
use super::{back, html, views, R};
use crate::server::state::Shared;
use crate::server::{compose, db, deploy, docker, jobs};

const EXAMPLE: &str = r#"services:
  web:
    image: ghcr.io/you/your-app:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:3000/health"]
      interval: 10s
      timeout: 3s
      retries: 5
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - db:/var/lib/postgresql/data
volumes:
  db: {}
"#;

async fn load_app(state: &Shared, id: i64) -> anyhow::Result<db::App> {
    db::app(&state.db, id).await?.ok_or_else(|| anyhow::anyhow!("app {id} not found"))
}

fn job_rows(jobs: &[db::Job], app_name: &str) -> Vec<views::JobRow> {
    jobs.iter()
        .map(|j| views::JobRow {
            id: j.id,
            kind: j.kind.clone(),
            app_name: app_name.to_string(),
            status: j.status.clone(),
            created: views::ago(&j.created),
        })
        .collect()
}

pub async fn new_page(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    html(views::AppNew {
        base: views::Base::new("New app", &user.username, &state.config.name, &f),
        name: String::new(),
        compose: EXAMPLE.to_string(),
    })
}

#[derive(Deserialize)]
pub struct NewAppForm {
    name: String,
    compose: String,
}

pub async fn create(State(state): State<Shared>, user: User, Form(f): Form<NewAppForm>) -> R {
    let name = f.name.trim().to_lowercase();
    if let Err(e) = compose::validate_app_name(&name) {
        return Ok(back("/apps/new", None, Some(&e.to_string())));
    }
    if db::app_by_name(&state.db, &name).await?.is_some() {
        return Ok(back("/apps/new", None, Some("an app with this name exists")));
    }
    if let Err(e) = compose::check(&f.compose) {
        return Ok(back("/apps/new", None, Some(&format!("compose file: {e:#}"))));
    }
    let app = db::create_app(&state.db, &name, &f.compose).await?;
    db::audit(&state.db, &user.username, "app.create", &name).await?;
    Ok(back(&format!("/apps/{}", app.id), Some("app created, add routes and secrets, then deploy"), None))
}

pub async fn show(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    let app = load_app(&state, id).await?;
    let containers = match &state.docker {
        Some(d) => docker::containers_of(d, &app.name).await.unwrap_or_default(),
        None => vec![],
    };
    let routes: Vec<views::RouteView> = db::routes_of(&state.db, id)
        .await?
        .into_iter()
        .map(|r| views::RouteView { id: r.id, host: r.host, service: r.service, port: r.port, expose: r.expose, waf: r.waf != 0, headers: r.headers != 0 })
        .collect();
    let secrets: Vec<views::SecretView> = db::secrets_of(&state.db, id)
        .await?
        .into_iter()
        .map(|s| views::SecretView { key: s.key, updated: views::ago(&s.updated) })
        .collect();
    let releases = db::releases_of(&state.db, id, 10)
        .await?
        .into_iter()
        .map(|r| views::ReleaseView {
            id: r.id,
            outcome: r.outcome,
            created: views::short_time(&r.created),
            images: serde_json::from_str(&r.images).unwrap_or_default(),
            scan: views::scan_summary(&r.scan).0,
            scan_bad: views::scan_summary(&r.scan).1,
            findings: views::scan_summary(&r.scan).2,
        })
        .collect();
    let jobs = db::jobs_of(&state.db, id, 10).await?;
    let services = compose::check(&app.compose).unwrap_or_default();
    let active_job = db::active_job_of(&state.db, id).await?.map(|j| j.id);
    let (hints, suggest, env, missing) = compose_views(&state, &app, &routes, &secrets);
    let hardening: Vec<(String, String)> = compose::inspect(&app.compose)
        .map(|i| i.services.into_iter().flat_map(|s| s.hints.into_iter().map(move |h| (s.name.clone(), h))).collect())
        .unwrap_or_default();
    html(views::AppShow {
        base: views::Base::new(&app.name, &user.username, &state.config.name, &f),
        app: views::AppView::from(&app),
        containers,
        routes,
        secrets,
        releases,
        jobs: job_rows(&jobs, &app.name),
        services,
        active_job,
        domains: state.config.domains.clone(),
        waf_available: state.waf_available,
        hints,
        suggest,
        env,
        missing,
        hardening,
        backup_enabled: state.config.backup.is_some(),
    })
}

#[derive(Deserialize)]
pub struct OnOffForm {
    value: String,
}

/// Include the app's volumes, files and database dumps in the nightly backup, or not.
pub async fn set_backup(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<OnOffForm>) -> R {
    let app = load_app(&state, id).await?;
    let on = f.value == "on";
    db::set_app_backup(&state.db, id, on).await?;
    db::audit(&state.db, &user.username, "app.backup", &format!("{} {on}", app.name)).await?;
    Ok(back(&format!("/apps/{id}"), Some(if on { "app included in the nightly backup" } else { "app excluded from backups" }), None))
}

/// Route hints, a suggested first route, the environment table and the unset placeholders, all from the compose file.
fn compose_views(
    state: &Shared,
    app: &db::App,
    routes: &[views::RouteView],
    secrets: &[views::SecretView],
) -> (Vec<views::ServiceHint>, Option<views::ServiceHint>, Vec<views::EnvView>, Vec<String>) {
    let Ok(info) = compose::inspect(&app.compose) else { return (vec![], None, vec![], vec![]) };
    let domain = state.config.domains.first().cloned().unwrap_or_default();
    let hints: Vec<views::ServiceHint> = info
        .services
        .iter()
        .map(|s| views::ServiceHint { name: s.name.clone(), host: format!("{}.{domain}", s.name), port: s.port.unwrap_or(80) })
        .collect();
    // first service that has a port in the file and no route yet; a lone service may well be the site itself
    let suggest = hints
        .iter()
        .find(|h| info.services.iter().any(|s| s.name == h.name && s.port.is_some()) && !routes.iter().any(|r| r.service == h.name))
        .map(|h| views::ServiceHint { name: h.name.clone(), host: if hints.len() == 1 { domain.clone() } else { h.host.clone() }, port: h.port });
    let has_secret = |n: &str| secrets.iter().any(|s| s.key == n);
    let env = info
        .services
        .iter()
        .flat_map(|s| {
            s.env.iter().map(move |(k, v)| {
                let placeholder = placeholder_name(v).map(|n| (n.to_string(), has_secret(n)));
                views::EnvView { service: s.name.clone(), key: k.clone(), value: v.clone(), placeholder }
            })
        })
        .collect();
    let missing = info.placeholders.into_iter().filter(|n| !has_secret(n)).collect();
    (hints, suggest, env, missing)
}

/// `${NAME}` exactly, nothing else in the value.
fn placeholder_name(v: &str) -> Option<&str> {
    let inner = v.strip_prefix("${")?.strip_suffix('}')?;
    let name = inner.split([':', '-', '?']).next()?;
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(name)
}

#[derive(Deserialize)]
pub struct EgressForm {
    mode: String,
    #[serde(default)]
    ports: String,
}

/// Internet access of the app's containers; applied to the firewall at once.
pub async fn set_egress(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<EgressForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}");
    let egress = match f.mode.as_str() {
        "all" => "all".to_string(),
        "none" => "none".to_string(),
        "ports" => {
            let mut ports = Vec::new();
            for p in f.ports.split([',', ' ', ';']).filter(|p| !p.is_empty()) {
                match p.parse::<u16>() {
                    Ok(n) if n > 0 => ports.push(n.to_string()),
                    _ => return Ok(back(&page, None, Some(&format!("`{p}` is not a port")))),
                }
            }
            if ports.is_empty() {
                return Ok(back(&page, None, Some("list at least one TCP port, or choose none")));
            }
            ports.join(",")
        }
        _ => return Ok(back(&page, None, Some("mode must be all, none or ports"))),
    };
    db::set_app_egress(&state.db, id, &egress).await?;
    db::audit(&state.db, &user.username, "app.egress", &format!("{} {egress}", app.name)).await?;
    if app.desired == "running" {
        crate::server::reconcile::apply(&state).await?;
    }
    Ok(back(&page, Some("internet access updated"), None))
}

#[derive(Deserialize)]
pub struct EnvForm {
    service: String,
    key: String,
    #[serde(default)]
    value: String,
}

/// Set one `environment` entry in the compose file.
pub async fn put_env(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<EnvForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}");
    let key = f.key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.starts_with(|c: char| c.is_ascii_digit()) {
        return Ok(back(&page, None, Some("variable names are letters, digits and underscores")));
    }
    let value = f.value.trim_end_matches(['\r', '\n']);
    let updated = match compose::set_environment(&app.compose, f.service.trim(), key, Some(value)) {
        Ok(c) => c,
        Err(e) => return Ok(back(&page, None, Some(&format!("{e:#}")))),
    };
    if let Err(e) = compose::check(&updated) {
        return Ok(back(&page, None, Some(&format!("compose file: {e:#}"))));
    }
    db::update_compose(&state.db, id, &updated).await?;
    db::audit(&state.db, &user.username, "app.env", &format!("{} {} {key}", app.name, f.service)).await?;
    Ok(back(&page, Some("variable saved in the compose file, deploy to apply"), None))
}

pub async fn delete_env(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<EnvForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}");
    let updated = match compose::set_environment(&app.compose, f.service.trim(), f.key.trim(), None) {
        Ok(c) => c,
        Err(e) => return Ok(back(&page, None, Some(&format!("{e:#}")))),
    };
    db::update_compose(&state.db, id, &updated).await?;
    db::audit(&state.db, &user.username, "app.env.delete", &format!("{} {} {}", app.name, f.service, f.key)).await?;
    Ok(back(&page, Some("variable removed from the compose file, deploy to apply"), None))
}

pub async fn edit_page(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    let app = load_app(&state, id).await?;
    html(views::AppEdit {
        base: views::Base::new(&format!("{} · compose", app.name), &user.username, &state.config.name, &f),
        compose: app.compose.clone(),
        app: views::AppView::from(&app),
    })
}

#[derive(Deserialize)]
pub struct ComposeForm {
    compose: String,
}

pub async fn update_compose(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<ComposeForm>) -> R {
    let app = load_app(&state, id).await?;
    if let Err(e) = compose::check(&f.compose) {
        return Ok(back(&format!("/apps/{id}/edit"), None, Some(&format!("compose file: {e:#}"))));
    }
    db::update_compose(&state.db, id, &f.compose).await?;
    db::audit(&state.db, &user.username, "app.compose", &app.name).await?;
    Ok(back(&format!("/apps/{id}"), Some("compose file saved, deploy to apply"), None))
}

async fn run_job(state: &Shared, app: &db::App, kind: &str, pull: bool) -> anyhow::Result<i64> {
    let redact = deploy::secret_values(state, app.id).await?;
    let app_id = app.id;
    jobs::spawn(state, kind, Some(app.id), redact, move |s, log| deploy::deploy(s, app_id, log, pull)).await
}

pub async fn deploy(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let app = load_app(&state, id).await?;
    if state.docker.is_none() {
        return Ok(back(&format!("/apps/{id}"), None, Some("docker is not available")));
    }
    db::audit(&state.db, &user.username, "app.deploy", &app.name).await?;
    match run_job(&state, &app, "deploy", true).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

/// Recreate the containers with the current compose file and secrets, images pinned to the last deployment.
pub async fn apply(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let app = load_app(&state, id).await?;
    db::audit(&state.db, &user.username, "app.apply", &app.name).await?;
    match run_job(&state, &app, "apply", false).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

pub async fn scan(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let app = load_app(&state, id).await?;
    db::audit(&state.db, &user.username, "app.scan", &app.name).await?;
    let redact = deploy::secret_values(&state, app.id).await?;
    let app_id = app.id;
    match jobs::spawn(&state, "scan", Some(app.id), redact, move |s, log| deploy::scan(s, app_id, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

pub async fn start(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let app = load_app(&state, id).await?;
    db::audit(&state.db, &user.username, "app.start", &app.name).await?;
    match run_job(&state, &app, "start", false).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

pub async fn stop(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let app = load_app(&state, id).await?;
    db::audit(&state.db, &user.username, "app.stop", &app.name).await?;
    let redact = deploy::secret_values(&state, app.id).await?;
    match jobs::spawn(&state, "stop", Some(id), redact, move |s, log| deploy::stop(s, id, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

#[derive(Deserialize)]
pub struct RemoveForm {
    confirm: String,
    #[serde(default)]
    volumes: Option<String>,
}

pub async fn remove(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<RemoveForm>) -> R {
    let app = load_app(&state, id).await?;
    if f.confirm.trim() != app.name {
        return Ok(back(&format!("/apps/{id}"), None, Some("type the app name to confirm removal")));
    }
    let volumes = f.volumes.is_some();
    db::audit(&state.db, &user.username, "app.remove", &format!("{} volumes={volumes}", app.name)).await?;
    let redact = deploy::secret_values(&state, app.id).await?;
    match jobs::spawn(&state, "remove", Some(id), redact, move |s, log| deploy::remove(s, id, volumes, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string()))),
    }
}

#[derive(Deserialize)]
pub struct RouteForm {
    host: String,
    service: String,
    port: i64,
    expose: String,
    /// checkboxes; absent when unchecked
    waf: Option<String>,
    headers: Option<String>,
}

pub async fn add_route(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<RouteForm>) -> R {
    let app = load_app(&state, id).await?;
    let host = f.host.trim().to_lowercase();
    let page = format!("/apps/{id}");
    // the certificate covers the domain itself and one label below it; both point at the server
    let Some(domain) = state.config.domains.iter().find(|d| &host == *d || host.ends_with(&format!(".{d}"))) else {
        return Ok(back(&page, None, Some("the host must be one of the configured domains or one label below it")));
    };
    let depth = host.split('.').count() - domain.split('.').count();
    if host.starts_with("*.") || depth > 1 || host.contains("..") {
        return Ok(back(&page, None, Some("use the domain itself or exactly one label below it, the wildcard certificate covers only those")));
    }
    if host == state.config.interface_host {
        return Ok(back(&page, None, Some("that host is the interface")));
    }
    if !(1..=65535).contains(&f.port) {
        return Ok(back(&page, None, Some("port out of range")));
    }
    if !matches!(f.expose.as_str(), "public" | "internal") {
        return Ok(back(&page, None, Some("expose must be public or internal")));
    }
    let services = compose::check(&app.compose).unwrap_or_default();
    if !services.contains(&f.service) {
        return Ok(back(&page, None, Some("unknown service")));
    }
    let (waf, headers) = (f.waf.is_some(), f.headers.is_some());
    if let Err(e) = db::add_route(&state.db, id, &host, &f.service, f.port, &f.expose, waf, headers).await {
        return Ok(back(&page, None, Some(&format!("route not added: {e}"))));
    }
    db::audit(&state.db, &user.username, "route.add", &format!("{} {} -> {}:{} {} waf={waf} headers={headers}", app.name, host, f.service, f.port, f.expose)).await?;
    if app.desired == "running" {
        crate::server::reconcile::apply(&state).await?;
    }
    Ok(back(&page, Some("route added"), None))
}

#[derive(Deserialize)]
pub struct FlagForm {
    /// `waf` or `headers`
    what: String,
    value: String,
}

/// Switch the WAF or the default security headers of one route.
pub async fn set_route_flag(State(state): State<Shared>, user: User, Path((id, rid)): Path<(i64, i64)>, Form(f): Form<FlagForm>) -> R {
    let app = load_app(&state, id).await?;
    let on = f.value == "on";
    if let Err(e) = db::set_route_flag(&state.db, id, rid, &f.what, on).await {
        return Ok(back(&format!("/apps/{id}"), None, Some(&e.to_string())));
    }
    db::audit(&state.db, &user.username, "route.flag", &format!("{} route {rid} {}={on}", app.name, f.what)).await?;
    crate::server::reconcile::apply(&state).await?;
    Ok(back(&format!("/apps/{id}"), Some(&format!("{} {} for the route", f.what, if on { "enabled" } else { "disabled" })), None))
}

pub async fn delete_route(State(state): State<Shared>, user: User, Path((id, rid)): Path<(i64, i64)>) -> R {
    let app = load_app(&state, id).await?;
    db::delete_route(&state.db, id, rid).await?;
    db::audit(&state.db, &user.username, "route.delete", &format!("{} route {rid}", app.name)).await?;
    crate::server::reconcile::apply(&state).await?;
    Ok(back(&format!("/apps/{id}"), Some("route removed"), None))
}

#[derive(Deserialize)]
pub struct SecretForm {
    key: String,
    value: String,
}

pub async fn put_secret(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<SecretForm>) -> R {
    let app = load_app(&state, id).await?;
    let key = f.key.trim().to_string();
    let page = format!("/apps/{id}");
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.starts_with(|c: char| c.is_ascii_digit()) {
        return Ok(back(&page, None, Some("secret names are environment variable names: letters, digits, underscores")));
    }
    let value = f.value.trim_end_matches(['\r', '\n']);
    db::put_secret(&state.db, id, &key, &state.key.seal(value.as_bytes())).await?;
    db::audit(&state.db, &user.username, "secret.put", &format!("{} {key}", app.name)).await?;
    Ok(back(&page, Some(&format!("secret {key} saved, deploy to apply")), None))
}

#[derive(Deserialize)]
pub struct SecretDeleteForm {
    key: String,
}

pub async fn delete_secret(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<SecretDeleteForm>) -> R {
    let app = load_app(&state, id).await?;
    db::delete_secret(&state.db, id, &f.key).await?;
    db::audit(&state.db, &user.username, "secret.delete", &format!("{} {}", app.name, f.key)).await?;
    Ok(back(&format!("/apps/{id}"), Some("secret removed, deploy to apply"), None))
}

#[derive(Deserialize)]
pub struct LogsQuery {
    tail: Option<usize>,
}

pub async fn logs(State(state): State<Shared>, user: User, Path((id, service)): Path<(i64, String)>, Query(q): Query<LogsQuery>) -> R<Response> {
    let app = load_app(&state, id).await?;
    let tail = q.tail.unwrap_or(200).min(5000);
    let mut log = String::from("docker is not available");
    if let Some(d) = &state.docker {
        let containers = docker::containers_of(d, &app.name).await?;
        log = match containers.iter().find(|c| c.service == service) {
            Some(c) => docker::logs(d, &c.id, tail).await?,
            None => "no container for this service".into(),
        };
        // never show secret values
        let redact = jobs::Log::new(state.db.clone(), 0, deploy::secret_values(&state, id).await?);
        log = redact.redact(&log);
    }
    html(views::LogsPage {
        base: views::Base::new(&format!("{} · {service} logs", app.name), &user.username, &state.config.name, &Flash { msg: None, error: None }),
        app: views::AppView::from(&app),
        service,
        log,
        tail,
    })
}
