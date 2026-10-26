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
    // <app>.env holds every secret and only serves `${VAR}` interpolation of the compose file;
    // each container gets <app>.<service>.env with the secrets scoped to it
    let env_file = env_dir.join(format!("{}.env", app.name));
    let secrets = db::secrets_of(&state.db, app.id).await?;
    let mut all = String::new();
    let mut opened: Vec<(String, String, &db::Secret)> = Vec::new();
    for s in &secrets {
        let v = state.key.open_string(&s.sealed)?;
        all += &env_line(&s.key, &v);
        opened.push((s.key.clone(), v.to_string(), s));
    }
    crate::install::write_private(&env_file, &all)?;
    let text = compose_text.unwrap_or(&app.compose);
    let rendered = compose::render(text, &app.name, app.net_index as u32, &env_dir.display().to_string())?;
    for (service, _) in &rendered.services {
        let mut env = String::new();
        for (k, v, s) in &opened {
            if s.reaches(service) {
                env += &env_line(k, v);
            }
        }
        crate::install::write_private(&env_dir.join(format!("{}.{service}.env", app.name)), &env)?;
    }
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
    deploy_with(state, app_id, log, pull, true).await
}

/// `announce`: record a "deployed" event; the resume after a restart does not.
pub async fn deploy_with(state: Shared, app_id: i64, log: Log, pull: bool, announce: bool) -> Result<()> {
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    db::set_app_status(&state.db, app.id, "deploying", "").await?;
    let result = deploy_inner(&state, &app, &log, pull).await;
    match result {
        Ok(()) => {
            db::set_app_desired(&state.db, app.id, "running").await?;
            db::set_app_status(&state.db, app.id, "running", "").await?;
            reconcile::apply(&state).await?;
            if announce {
                let _ = db::add_event(&state.db, "deployed", "pocketcloud", &format!("{} deployed", app.name), &serde_json::json!({"app": app.name})).await;
            }
            log.line("deployed").await;
            Ok(())
        }
        Err(e) => {
            log.line(format!("deploy failed: {e:#}")).await;
            let _ = db::add_event(&state.db, "deploy_failed", "pocketcloud", &format!("deploy of {} failed: {e:#}", app.name), &serde_json::json!({"app": app.name})).await;
            rollback(&state, &app, &log, &e.to_string()).await
        }
    }
}

async fn deploy_inner(state: &Shared, app: &db::App, log: &Log, pull: bool) -> Result<()> {
    let p = prepare(state, app, None).await?;
    log.line(format!("services: {}", p.rendered.services.iter().map(|(n, ip)| format!("{n} ({ip})")).collect::<Vec<_>>().join(", "))).await;
    if pull {
        docker::compose(state, &app.name, &p.app_dir, &p.env_file, &["pull", "--quiet"], log).await.context("pull")?;
    } else if let Some(last) = db::last_good_release(&state.db, app.id).await? {
        // without a pull the images stay exactly what the last deployment ran, by digest
        let digests: Vec<String> = serde_json::from_str(&last.images).unwrap_or_default();
        match pin_images(&p.rendered.yaml, &digests) {
            Ok((yaml, n)) if n > 0 => {
                std::fs::write(p.app_dir.join("compose.yaml"), &yaml)?;
                log.line(format!("{n} image(s) pinned to the digests of deployment #{}", last.id)).await;
            }
            Ok(_) => {}
            Err(e) => log.line(format!("could not pin images: {e:#}")).await,
        }
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
    let scan = if pull { scan_images(state, &p.rendered.images, log).await } else { String::new() };
    db::add_release(&state.db, app.id, &p.rendered.yaml, &images, "deployed", &scan).await?;
    Ok(())
}

/// Rewrite `image:` of every service to the digest the last deployment recorded ("service: repo@sha256:..").
fn pin_images(yaml: &str, digests: &[String]) -> Result<(String, usize)> {
    let mut doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml)?;
    let mut n = 0;
    if let Some(services) = doc.get_mut("services").and_then(|s| s.as_mapping_mut()) {
        for entry in digests {
            let Some((service, digest)) = entry.split_once(": ") else { continue };
            if !digest.contains("@sha256:") {
                continue;
            }
            if let Some(svc) = services.get_mut(serde_yaml_ng::Value::String(service.to_string())).and_then(|s| s.as_mapping_mut()) {
                svc.insert(serde_yaml_ng::Value::String("image".into()), serde_yaml_ng::Value::String(digest.to_string()));
                n += 1;
            }
        }
    }
    Ok((serde_yaml_ng::to_string(&doc)?, n))
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct ImageScan {
    pub image: String,
    pub critical: usize,
    pub high: usize,
    /// up to ten critical findings: "CVE pkg installed -> fixed"
    pub findings: Vec<String>,
    pub error: String,
}

/// Trivy on each image, local daemon only. Never blocks a deploy; the result goes to the log and the release.
pub async fn scan_images(state: &State, images: &[String], log: &Log) -> String {
    if state.config.dev {
        return String::new();
    }
    let cache = state.config.data_dir.join("trivy");
    let mut out = Vec::new();
    for image in images {
        log.line(format!("$ trivy image {image}")).await;
        let res = tokio::process::Command::new("trivy")
            .args(["image", "--quiet", "--format", "json", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--image-src", "docker", "--timeout", "10m"])
            .arg("--cache-dir")
            .arg(&cache)
            .arg(image)
            .env("TRIVY_CACHE_DIR", &cache)
            .env("HOME", &state.config.data_dir)
            .stdin(std::process::Stdio::null())
            .output()
            .await;
        let mut scan = ImageScan { image: image.clone(), ..Default::default() };
        match res {
            Err(e) => scan.error = format!("trivy not available: {e}"),
            Ok(o) if !o.status.success() => scan.error = String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("trivy failed").to_string(),
            Ok(o) => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                    for r in v.get("Results").and_then(|r| r.as_array()).into_iter().flatten() {
                        for vuln in r.get("Vulnerabilities").and_then(|x| x.as_array()).into_iter().flatten() {
                            let sev = vuln.get("Severity").and_then(|s| s.as_str()).unwrap_or("");
                            let s = |k: &str| vuln.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                            if sev == "CRITICAL" {
                                scan.critical += 1;
                                if scan.findings.len() < 10 {
                                    let fixed = s("FixedVersion");
                                    scan.findings.push(format!("{} {} {}{}", s("VulnerabilityID"), s("PkgName"), s("InstalledVersion"), if fixed.is_empty() { String::new() } else { format!(" -> {fixed}") }));
                                }
                            } else if sev == "HIGH" {
                                scan.high += 1;
                            }
                        }
                    }
                } else {
                    scan.error = "unreadable trivy output".into();
                }
            }
        }
        if scan.error.is_empty() {
            log.line(format!("  {} critical, {} high", scan.critical, scan.high)).await;
            for f in &scan.findings {
                log.line(format!("  {f}")).await;
            }
        } else {
            log.line(format!("  scan failed: {}", scan.error)).await;
        }
        out.push(scan);
    }
    serde_json::to_string(&out).unwrap_or_default()
}

/// Scan the images of the current compose file and attach the result to the latest deployment.
pub async fn scan(state: Shared, app_id: i64, log: Log) -> Result<()> {
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    let env_dir = state.config.run_dir().join("env");
    let rendered = compose::render(&app.compose, &app.name, app.net_index as u32, &env_dir.display().to_string())?;
    let scan = scan_images(&state, &rendered.images, &log).await;
    if let Some(last) = db::last_good_release(&state.db, app.id).await? {
        db::set_release_scan(&state.db, last.id, &scan).await?;
    }
    Ok(())
}

async fn rollback(state: &Shared, app: &db::App, log: &Log, reason: &str) -> Result<()> {
    let p = prepare(state, app, None).await.ok();
    if let Some(p) = &p {
        db::add_release(&state.db, app.id, &p.rendered.yaml, &[], "failed", "").await?;
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
            deploy_with(s, app.id, log, false, false).await
        })
        .await;
    }
    Ok(())
}
