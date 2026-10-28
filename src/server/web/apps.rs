use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
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
    show_tab(state, user, id, f, "overview", None, 0).await
}

pub async fn show_services(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "services", None, 0).await
}

pub async fn show_service(State(state): State<Shared>, user: User, Path((id, service)): Path<(i64, String)>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "services", Some(service), 0).await
}

pub async fn show_secrets(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "secrets", None, 0).await
}

pub async fn show_network(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "network", None, 0).await
}

pub async fn show_history(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "deployments", None, 0).await
}

pub async fn show_settings(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    show_tab(state, user, id, f, "settings", None, 0).await
}

/// The old Configuration tab: secrets now have their own tab.
pub async fn config_redirect(Path(id): Path<i64>) -> Response {
    back(&format!("/apps/{id}/secrets"), None, None)
}

#[derive(Deserialize)]
pub struct LogsQuery {
    service: Option<String>,
    tail: Option<usize>,
}

pub async fn show_logs(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(q): Query<LogsQuery>) -> R {
    let tail = q.tail.unwrap_or(200).clamp(10, 5000);
    show_tab(state, user, id, Flash { msg: None, error: None }, "logs", q.service, tail).await
}

/// The last `tail` lines of one service's container, secret values redacted.
async fn service_log(state: &Shared, app_id: i64, containers: &[docker::ContainerInfo], service: &str, tail: usize) -> anyhow::Result<String> {
    let Some(d) = &state.docker else { return Ok("docker is not available".into()) };
    let Some(c) = containers.iter().find(|c| c.service == service) else {
        return Ok("no container for this service; deploy the app to start it".into());
    };
    let raw = docker::logs(d, &c.id, tail).await?;
    // never show secret values
    Ok(jobs::Log::new(state.db.clone(), 0, deploy::secret_values(state, app_id).await?).redact(&raw))
}

/// The log of one service as plain text, for the live view of the Logs tab.
pub async fn logs_text(State(state): State<Shared>, _user: User, Path(id): Path<i64>, Query(q): Query<LogsQuery>) -> R {
    let app = load_app(&state, id).await?;
    let tail = q.tail.unwrap_or(200).clamp(10, 5000);
    let containers = match &state.docker {
        Some(d) => docker::containers_of(d, &app.name).await.unwrap_or_default(),
        None => vec![],
    };
    let text = service_log(&state, id, &containers, q.service.as_deref().unwrap_or_default(), tail).await?;
    Ok(([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

/// Old link to one service's logs.
pub async fn logs_redirect(Path((id, service)): Path<(i64, String)>) -> Response {
    back(&format!("/apps/{id}/logs?service={}", super::urlenc(&service)), None, None)
}

/// `FOO_BAR` and `FOO_BAZ` share the group FOO; names without a partner go to General.
fn group_secrets(secrets: &[views::SecretView]) -> Vec<views::SecretGroup> {
    let prefix = |k: &str| k.split_once('_').map(|(p, _)| p.to_string()).filter(|p| !p.is_empty());
    let mut groups: Vec<views::SecretGroup> = Vec::new();
    let mut general = Vec::new();
    for s in secrets {
        let shared = prefix(&s.key).filter(|p| secrets.iter().filter(|o| prefix(&o.key).as_deref() == Some(p.as_str())).count() > 1);
        match shared {
            Some(p) => match groups.iter_mut().find(|g| g.name == p) {
                Some(g) => g.secrets.push(s.clone()),
                None => groups.push(views::SecretGroup { name: p, secrets: vec![s.clone()] }),
            },
            None => general.push(s.clone()),
        }
    }
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    if !general.is_empty() {
        groups.insert(0, views::SecretGroup { name: "General".into(), secrets: general });
    }
    groups
}

async fn show_tab(state: Shared, user: User, id: i64, f: Flash, tab: &'static str, service: Option<String>, tail: usize) -> R {
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
    let release_rows = db::releases_of(&state.db, id, 10).await?;
    let last_deploy = release_rows.first().map(|r| r.created.clone()).unwrap_or_default();
    let inspection = compose::inspect(&app.compose).ok();
    let mut secrets: Vec<views::SecretView> = db::secrets_of(&state.db, id)
        .await?
        .into_iter()
        .map(|s| views::SecretView {
            services: if s.services.is_empty() { vec![] } else { s.services.split(',').map(str::to_string).collect() },
            changed: !last_deploy.is_empty() && s.updated > last_deploy,
            key: s.key,
            updated: views::ago(&s.updated),
        })
        .collect();
    secrets.sort_by(|a, b| a.key.cmp(&b.key));
    let changed_secrets = secrets.iter().filter(|s| s.changed).count();
    let releases = release_rows
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
    let hardening: Vec<(String, String)> = inspection
        .as_ref()
        .map(|i| i.services.iter().flat_map(|s| s.hints.iter().map(move |h| (s.name.clone(), h.clone()))).collect())
        .unwrap_or_default();
    let service_views: Vec<views::ServiceView> = inspection
        .as_ref()
        .map(|i| i.services.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let c = containers.iter().find(|c| c.service == s.name);
            let (plain, from_secrets): (Vec<views::EnvView>, Vec<views::EnvView>) = env.iter().filter(|e| e.service == s.name).cloned().partition(|e| e.placeholder.is_none());
            views::ServiceView {
                name: s.name.clone(),
                image: c.map(|c| c.image.clone()).unwrap_or_else(|| s.image.clone()),
                state: c.map(|c| c.state.clone()).unwrap_or_else(|| "not created".into()),
                state_class: c.map(|c| c.state.clone()).unwrap_or_else(|| "not-created".into()),
                health: c.map(|c| c.health.clone()).unwrap_or_default(),
                status: c.map(|c| c.status.clone()).unwrap_or_default(),
                port: s.port.map(|p| p.to_string()).unwrap_or_default(),
                env_text: plain.iter().map(|e| format!("{}={}", e.key, e.value)).collect::<Vec<_>>().join("\n"),
                env: plain,
                env_secrets: from_secrets,
                secrets: secrets.iter().filter(|x| x.services.is_empty() || x.services.contains(&s.name)).map(|x| x.key.clone()).collect(),
                routes: routes.iter().filter(|r| r.service == s.name).cloned().collect(),
                hints: s.hints.clone(),
            }
        })
        .collect();
    let running = service_views.iter().filter(|s| s.state == "running").count();
    let service = match service {
        Some(s) if services.contains(&s) => s,
        _ => services.first().cloned().unwrap_or_default(),
    };
    let log = if tab == "logs" && !service.is_empty() { service_log(&state, id, &containers, &service, tail).await? } else { String::new() };
    let backup_enabled = crate::server::backup::settings(&state).await.is_some();
    html(views::AppShow {
        base: views::Base::new(&app.name, &user.username, &state.config.name, &f),
        tab,
        app: views::AppView::from(&app),
        secret_groups: group_secrets(&secrets),
        routes,
        secrets,
        releases,
        jobs: job_rows(&jobs, &app.name),
        services,
        service_views,
        service,
        active_job,
        domains: state.config.domains.clone(),
        waf_available: state.waf_available,
        hints,
        suggest,
        missing,
        hardening,
        backup_enabled,
        snapshots: if backup_enabled { crate::server::backup::cached_snapshots(&state).await } else { vec![] },
        changed_secrets,
        compose: app.compose.clone(),
        log,
        tail,
        running,
    })
}

#[derive(Deserialize)]
pub struct AppRestoreForm {
    snapshot: String,
    confirm: String,
}

/// Put volumes, files and database dumps of this app back from a snapshot.
pub async fn restore(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<AppRestoreForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}/settings");
    let backup_cfg = crate::server::backup::settings(&state).await;
    if backup_cfg.is_none() {
        return Ok(back(&page, None, Some("backups are not configured")));
    }
    if f.confirm.trim() != app.name {
        return Ok(back(&page, None, Some("type the app name to confirm")));
    }
    db::audit(&state.db, &user.username, "app.restore", &format!("{} {}", app.name, f.snapshot)).await?;
    let mut redact = deploy::secret_values(&state, app.id).await?;
    redact.extend(backup_cfg.map(|b| b.secret_key));
    let snap = f.snapshot.trim().to_string();
    let app_id = app.id;
    match jobs::spawn(&state, "restore", Some(app.id), redact, move |s, log| crate::server::backup::restore_app(s, app_id, snap, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&page, None, Some(&e.to_string()))),
    }
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
    Ok(back(&format!("/apps/{id}/settings"), Some(if on { "app included in the nightly backup" } else { "app excluded from backups" }), None))
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
    let page = format!("/apps/{id}/network");
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
    let page = format!("/apps/{id}/services/{}", super::urlenc(f.service.trim()));
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
    let page = format!("/apps/{id}/services/{}", super::urlenc(f.service.trim()));
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
        return Ok(back(&format!("/apps/{id}/settings"), None, Some("type the app name to confirm removal")));
    }
    let volumes = f.volumes.is_some();
    db::audit(&state.db, &user.username, "app.remove", &format!("{} volumes={volumes}", app.name)).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} removed app {} (volumes deleted: {volumes})", user.username, app.name), &serde_json::json!({"user": user.username, "action": "app.remove"})).await;
    let redact = deploy::secret_values(&state, app.id).await?;
    match jobs::spawn(&state, "remove", Some(id), redact, move |s, log| deploy::remove(s, id, volumes, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back(&format!("/apps/{id}/settings"), None, Some(&e.to_string()))),
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
    let page = format!("/apps/{id}/network");
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
        return Ok(back(&format!("/apps/{id}/network"), None, Some(&e.to_string())));
    }
    db::audit(&state.db, &user.username, "route.flag", &format!("{} route {rid} {}={on}", app.name, f.what)).await?;
    if !on {
        let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} switched {} off for a route of {}", user.username, f.what, app.name), &serde_json::json!({"user": user.username, "action": "route.flag"})).await;
    }
    crate::server::reconcile::apply(&state).await?;
    Ok(back(&format!("/apps/{id}/network"), Some(&format!("{} {} for the route", f.what, if on { "enabled" } else { "disabled" })), None))
}

pub async fn delete_route(State(state): State<Shared>, user: User, Path((id, rid)): Path<(i64, i64)>) -> R {
    let app = load_app(&state, id).await?;
    db::delete_route(&state.db, id, rid).await?;
    db::audit(&state.db, &user.username, "route.delete", &format!("{} route {rid}", app.name)).await?;
    crate::server::reconcile::apply(&state).await?;
    Ok(back(&format!("/apps/{id}/network"), Some("route removed"), None))
}

#[derive(Deserialize)]
pub struct SecretForm {
    key: String,
    #[serde(default)]
    value: String,
    /// `svc_<name>=on` for each service the secret should reach; none checked means every service
    #[serde(flatten)]
    rest: std::collections::HashMap<String, String>,
}

pub async fn put_secret(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<SecretForm>) -> R {
    let app = load_app(&state, id).await?;
    let key = f.key.trim().to_string();
    let page = format!("/apps/{id}/secrets");
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.starts_with(|c: char| c.is_ascii_digit()) {
        return Ok(back(&page, None, Some("secret names are environment variable names: letters, digits, underscores")));
    }
    let services = compose::check(&app.compose).unwrap_or_default();
    let mut scope: Vec<String> = f.rest.keys().filter_map(|k| k.strip_prefix("svc_")).filter(|s| services.iter().any(|x| x == s)).map(str::to_string).collect();
    scope.sort();
    let scope = if scope.len() == services.len() { String::new() } else { scope.join(",") };
    let value = f.value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        if !db::set_secret_services(&state.db, id, &key, &scope).await? {
            return Ok(back(&page, None, Some("a new secret needs a value")));
        }
        db::audit(&state.db, &user.username, "secret.scope", &format!("{} {key} {}", app.name, if scope.is_empty() { "all" } else { &scope })).await?;
        return Ok(back(&page, Some(&format!("secret {key} now reaches {}, deploy to apply", if scope.is_empty() { "every service".to_string() } else { scope.replace(',', ", ") })), None));
    }
    db::put_secret(&state.db, id, &key, &state.key.seal(value.as_bytes()), &scope).await?;
    db::audit(&state.db, &user.username, "secret.put", &format!("{} {key} -> {}", app.name, if scope.is_empty() { "all" } else { &scope })).await?;
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
    Ok(back(&format!("/apps/{id}/secrets"), Some("secret removed, deploy to apply"), None))
}

#[derive(Deserialize)]
pub struct EnvBulkForm {
    service: String,
    #[serde(default)]
    env: String,
}

/// Replace the plain `environment` entries of one service with `KEY=value` lines; `${NAME}` entries stay.
pub async fn put_env_bulk(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<EnvBulkForm>) -> R {
    let app = load_app(&state, id).await?;
    let service = f.service.trim();
    let page = format!("/apps/{id}/services/{}", super::urlenc(service));
    let mut wanted: Vec<(String, String)> = Vec::new();
    for line in f.env.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || k.starts_with(|c: char| c.is_ascii_digit()) {
            return Ok(back(&page, None, Some(&format!("`{k}` is not a variable name: letters, digits and underscores"))));
        }
        wanted.retain(|(o, _)| o != k);
        wanted.push((k.to_string(), v.to_string()));
    }
    let current = compose::inspect(&app.compose).ok().and_then(|i| i.services.into_iter().find(|s| s.name == service)).map(|s| s.env).unwrap_or_default();
    let mut updated = app.compose.clone();
    let (mut set, mut removed) = (0, 0);
    for (k, v) in &current {
        if placeholder_name(v).is_none() && !wanted.iter().any(|(w, _)| w == k) {
            updated = match compose::set_environment(&updated, service, k, None) {
                Ok(c) => c,
                Err(e) => return Ok(back(&page, None, Some(&format!("{e:#}")))),
            };
            removed += 1;
        }
    }
    for (k, v) in &wanted {
        if current.iter().any(|(ck, cv)| ck == k && cv == v) {
            continue;
        }
        updated = match compose::set_environment(&updated, service, k, Some(v)) {
            Ok(c) => c,
            Err(e) => return Ok(back(&page, None, Some(&format!("{e:#}")))),
        };
        set += 1;
    }
    if set + removed == 0 {
        return Ok(back(&page, Some("nothing changed"), None));
    }
    if let Err(e) = compose::check(&updated) {
        return Ok(back(&page, None, Some(&format!("compose file: {e:#}"))));
    }
    db::update_compose(&state.db, id, &updated).await?;
    db::audit(&state.db, &user.username, "app.env", &format!("{} {service} {set} set, {removed} removed", app.name)).await?;
    Ok(back(&page, Some("environment saved in the compose file, deploy to apply"), None))
}

#[derive(Deserialize)]
pub struct SecretImportForm {
    #[serde(default)]
    env: String,
    #[serde(flatten)]
    rest: std::collections::HashMap<String, String>,
}

/// Several secrets at once from `.env` lines; existing ones get the new value.
pub async fn import_secrets(State(state): State<Shared>, user: User, Path(id): Path<i64>, Form(f): Form<SecretImportForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}/secrets");
    let services = compose::check(&app.compose).unwrap_or_default();
    let mut scope: Vec<String> = f.rest.keys().filter_map(|k| k.strip_prefix("svc_")).filter(|s| services.iter().any(|x| x == s)).map(str::to_string).collect();
    scope.sort();
    let scope = if scope.is_empty() || scope.len() == services.len() { String::new() } else { scope.join(",") };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in f.env.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            return Ok(back(&page, None, Some(&format!("`{line}` is not KEY=value"))));
        };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || k.starts_with(|c: char| c.is_ascii_digit()) {
            return Ok(back(&page, None, Some(&format!("`{k}` is not a secret name: letters, digits and underscores"))));
        }
        let v = v.trim();
        let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\''))).unwrap_or(v);
        if v.is_empty() {
            return Ok(back(&page, None, Some(&format!("{k} has no value"))));
        }
        pairs.push((k.to_string(), v.to_string()));
    }
    if pairs.is_empty() {
        return Ok(back(&page, None, Some("paste at least one KEY=value line")));
    }
    for (k, v) in &pairs {
        db::put_secret(&state.db, id, k, &state.key.seal(v.as_bytes()), &scope).await?;
    }
    let names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    db::audit(&state.db, &user.username, "secret.import", &format!("{} {} -> {}", app.name, names.join(","), if scope.is_empty() { "all" } else { &scope })).await?;
    Ok(back(&page, Some(&format!("{} secret{} saved, deploy to apply", pairs.len(), if pairs.len() == 1 { "" } else { "s" })), None))
}

#[derive(Deserialize)]
pub struct RouteUpdateForm {
    waf: Option<String>,
    headers: Option<String>,
}

/// WAF and security headers of one public route, from its settings dialog.
pub async fn update_route(State(state): State<Shared>, user: User, Path((id, rid)): Path<(i64, i64)>, Form(f): Form<RouteUpdateForm>) -> R {
    let app = load_app(&state, id).await?;
    let page = format!("/apps/{id}/network");
    let (waf, headers) = (f.waf.is_some(), f.headers.is_some());
    for (what, on) in [("waf", waf), ("headers", headers)] {
        if let Err(e) = db::set_route_flag(&state.db, id, rid, what, on).await {
            return Ok(back(&page, None, Some(&e.to_string())));
        }
    }
    db::audit(&state.db, &user.username, "route.flag", &format!("{} route {rid} waf={waf} headers={headers}", app.name)).await?;
    if !waf || !headers {
        let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} saved a route of {} with waf={waf} headers={headers}", user.username, app.name), &serde_json::json!({"user": user.username, "action": "route.flag"})).await;
    }
    crate::server::reconcile::apply(&state).await?;
    Ok(back(&page, Some("route saved"), None))
}
