//! Deploy, start, stop, remove and roll back apps.
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;

use super::jobs::Log;
use super::state::{Shared, State};
use super::{compose, db, docker, reconcile};

pub struct Prepared {
    pub app_dir: PathBuf,
    pub env_file: PathBuf,
    pub rendered: compose::Rendered,
}

/// Secret values of an app, for log redaction.
pub async fn secret_values(state: &State, app_id: i64) -> Result<Vec<String>> {
    let mut v = Vec::new();
    for s in db::secrets_of(&state.db, app_id).await? {
        v.push(state.key.open_string(&s.sealed)?.to_string());
    }
    for r in db::registries(&state.db).await? {
        v.push(state.key.open_string(&r.sealed_password)?.to_string());
    }
    Ok(v)
}

fn env_line(key: &str, value: &str) -> String {
    // single-quoted for compose's env_file and --env-file parsers; a literal ' is closed, escaped, reopened
    format!("{key}='{}'\n", value.replace('\'', "'\\''"))
}

/// Render the compose file and write it with the env file. `compose_text` defaults to the app's current file.
pub async fn prepare(state: &State, app: &db::App, compose_text: Option<&str>) -> Result<Prepared> {
    let app_dir = state.config.apps_dir().join(&app.name);
    std::fs::create_dir_all(app_dir.join("files"))?;
    let env_dir = state.config.run_dir().join("env");
    std::fs::create_dir_all(&env_dir)?;
    crate::install::set_mode(&env_dir, 0o700)?;
    let env_file = env_dir.join(format!("{}.env", app.name));
    let mut env = String::new();
    for s in db::secrets_of(&state.db, app.id).await? {
        let v = state.key.open_string(&s.sealed)?;
        env += &env_line(&s.key, &v);
    }
    crate::install::write_private(&env_file, &env)?;
    let text = compose_text.unwrap_or(&app.compose);
    let rendered = compose::render(text, &app.name, app.net_index as u32, &env_file.display().to_string())?;
    let routes = db::routes_of(&state.db, app.id).await?;
    for r in &routes {
        if !rendered.services.iter().any(|(s, _)| s == &r.service) {
            bail!("route {} points at service `{}` which is not in the compose file", r.host, r.service);
        }
    }
    std::fs::write(app_dir.join("compose.yaml"), &rendered.yaml)?;
    Ok(Prepared { app_dir, env_file, rendered })
}

pub async fn deploy(state: Shared, app_id: i64, log: Log, pull: bool) -> Result<()> {
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    db::set_app_status(&state.db, app.id, "deploying", "").await?;
    let result = deploy_inner(&state, &app, &log, pull).await;
    match result {
        Ok(()) => {
            db::set_app_desired(&state.db, app.id, "running").await?;
            db::set_app_status(&state.db, app.id, "running", "").await?;
            reconcile::apply(&state).await?;
            log.line("deployed").await;
            Ok(())
        }
        Err(e) => {
            log.line(format!("deploy failed: {e:#}")).await;
            rollback(&state, &app, &log, &e.to_string()).await
        }
    }
}

async fn deploy_inner(state: &Shared, app: &db::App, log: &Log, pull: bool) -> Result<()> {
    let p = prepare(state, app, None).await?;
    log.line(format!("services: {}", p.rendered.services.iter().map(|(n, ip)| format!("{n} ({ip})")).collect::<Vec<_>>().join(", "))).await;
    if pull {
        docker::compose(state, &app.name, &p.app_dir, &p.env_file, &["pull", "--quiet"], log).await.context("pull")?;
    }
    // the network must exist before the firewall can name its bridge; up creates it
    let up = docker::compose(
        state,
        &app.name,
        &p.app_dir,
        &p.env_file,
        &["up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "180"],
        log,
    )
    .await;
    if up.is_err() {
        // the reason is almost always in the containers' own output; show it before giving up
        log.line("--- container state and last log lines").await;
        let _ = docker::compose(state, &app.name, &p.app_dir, &p.env_file, &["ps", "--all", "--format", "table {{.Service}}\t{{.Status}}"], log).await;
        let _ = docker::compose(state, &app.name, &p.app_dir, &p.env_file, &["logs", "--no-color", "--tail", "40"], log).await;
    }
    up.context("up")?;
    let images = match &state.docker {
        Some(d) => docker::image_digests(d, &app.name).await,
        None => vec![],
    };
    db::add_release(&state.db, app.id, &p.rendered.yaml, &images, "deployed").await?;
    Ok(())
}

async fn rollback(state: &Shared, app: &db::App, log: &Log, reason: &str) -> Result<()> {
    let p = prepare(state, app, None).await.ok();
    if let Some(p) = &p {
        db::add_release(&state.db, app.id, &p.rendered.yaml, &[], "failed").await?;
    }
    let Some(last) = db::last_good_release(&state.db, app.id).await? else {
        db::set_app_status(&state.db, app.id, "failed", reason).await?;
        bail!("no previous release to roll back to");
    };
    log.line(format!("rolling back to release {} from {}", last.id, last.created)).await;
    let app_dir = state.config.apps_dir().join(&app.name);
    std::fs::write(app_dir.join("compose.yaml"), &last.compose_rendered)?;
    let env_file = state.config.run_dir().join("env").join(format!("{}.env", app.name));
    let r = docker::compose(state, &app.name, &app_dir, &env_file, &["up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "180"], log).await;
    match r {
        Ok(()) => {
            db::set_app_status(&state.db, app.id, "rolled_back", &format!("deploy failed, previous release {} is running: {reason}", last.id)).await?;
            reconcile::apply(state).await?;
            bail!("deploy failed, rolled back to release {}", last.id)
        }
        Err(e) => {
            db::set_app_status(&state.db, app.id, "failed", &format!("deploy failed and rollback failed: {e}")).await?;
            bail!("deploy failed ({reason}) and rollback failed ({e})")
        }
    }
}

pub async fn stop(state: Shared, app_id: i64, log: Log) -> Result<()> {
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    let app_dir = state.config.apps_dir().join(&app.name);
    db::set_app_desired(&state.db, app.id, "stopped").await?;
    if app_dir.join("compose.yaml").exists() {
        let env_file = state.config.run_dir().join("env").join(format!("{}.env", app.name));
        if !env_file.exists() {
            crate::install::write_private(&env_file, "")?;
        }
        docker::compose(&state, &app.name, &app_dir, &env_file, &["down", "--remove-orphans"], &log).await?;
    }
    db::set_app_status(&state.db, app.id, "stopped", "").await?;
    reconcile::apply(&state).await?;
    Ok(())
}

pub async fn remove(state: Shared, app_id: i64, delete_volumes: bool, log: Log) -> Result<()> {
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    let app_dir = state.config.apps_dir().join(&app.name);
    if app_dir.join("compose.yaml").exists() {
        let env_file = state.config.run_dir().join("env").join(format!("{}.env", app.name));
        if !env_file.exists() {
            crate::install::write_private(&env_file, "")?;
        }
        let mut args = vec!["down", "--remove-orphans"];
        if delete_volumes {
            args.push("--volumes");
        }
        docker::compose(&state, &app.name, &app_dir, &env_file, &args, &log).await?;
    }
    let _ = std::fs::remove_dir_all(&app_dir);
    let _ = std::fs::remove_file(state.config.run_dir().join("env").join(format!("{}.env", app.name)));
    db::delete_app(&state.db, app.id).await?;
    reconcile::apply(&state).await?;
    log.line(format!("app {} removed{}", app.name, if delete_volumes { " with its volumes" } else { ", volumes kept" })).await;
    Ok(())
}

/// After a daemon start: bring every app that should run back up without pulling.
pub async fn resume_all(state: Shared) -> Result<()> {
    for app in db::apps(&state.db).await? {
        if app.desired != "running" {
            continue;
        }
        let st = state.clone();
        let redact = secret_values(&state, app.id).await.unwrap_or_default();
        let _ = super::jobs::spawn(&state, "resume", Some(app.id), redact, move |s, log| async move {
            let _ = &st;
            deploy(s, app.id, log, false).await
        })
        .await;
    }
    Ok(())
}
