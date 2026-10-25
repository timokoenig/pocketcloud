//! Docker: the compose CLI for lifecycle, the engine API for status and logs.
use anyhow::{bail, Context, Result};
use bollard::container::{ListContainersOptions, LogsOptions};
use bollard::Docker;
use futures_util::StreamExt;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::jobs::Log;
use super::state::Shared;
use super::{db, state::State};

pub fn connect() -> Result<Docker> {
    Ok(Docker::connect_with_local_defaults()?)
}

/// Registry credentials for the compose subprocess, in a root-only directory on tmpfs.
pub async fn write_docker_config(state: &State) -> Result<std::path::PathBuf> {
    let dir = state.config.run_dir().join("docker");
    std::fs::create_dir_all(&dir)?;
    crate::install::set_mode(&dir, 0o700)?;
    let mut auths = serde_json::Map::new();
    for r in db::registries(&state.db).await? {
        let pw = state.key.open_string(&r.sealed_password)?;
        let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", r.username, *pw));
        auths.insert(r.host.clone(), serde_json::json!({"auth": token}));
    }
    let cfg = serde_json::json!({"auths": auths});
    crate::install::write_private(&dir.join("config.json"), &serde_json::to_string(&cfg)?)?;
    Ok(dir)
}

/// Run `docker compose` for an app and stream its output into the job log.
pub async fn compose(state: &State, app: &str, app_dir: &Path, env_file: &Path, args: &[&str], log: &Log) -> Result<()> {
    let docker_config = write_docker_config(state).await?;
    let compose_file = app_dir.join("compose.yaml");
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-p")
        .arg(app)
        .arg("--project-directory")
        .arg(app_dir)
        .arg("-f")
        .arg(&compose_file)
        .arg("--env-file")
        .arg(env_file)
        .args(args)
        .env("DOCKER_CONFIG", &docker_config)
        .env("COMPOSE_ANSI", "never")
        .env("COMPOSE_PROGRESS", "plain")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    log.line(format!("$ docker compose -p {app} {}", args.join(" "))).await;
    let mut child = cmd.spawn().context("start docker compose")?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let l1 = log.clone();
    let l2 = log.clone();
    let t1 = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            l1.line(l).await;
        }
    });
    let t2 = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            l2.line(l).await;
        }
    });
    let status = child.wait().await?;
    let _ = tokio::join!(t1, t2);
    if !status.success() {
        bail!("docker compose {} exited with {}", args.first().unwrap_or(&""), status.code().unwrap_or(-1));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    pub id: String,
    pub service: String,
    pub state: String,
    pub status: String,
    pub image: String,
    pub health: String,
}

pub async fn containers_of(docker: &Docker, project: &str) -> Result<Vec<ContainerInfo>> {
    let mut filters = HashMap::new();
    filters.insert("label".to_string(), vec![format!("com.docker.compose.project={project}")]);
    let list = docker.list_containers(Some(ListContainersOptions { all: true, filters, ..Default::default() })).await?;
    let mut out: Vec<ContainerInfo> = list
        .into_iter()
        .map(|c| {
            let labels = c.labels.unwrap_or_default();
            let status = c.status.clone().unwrap_or_default();
            let health = if status.contains("(healthy)") {
                "healthy"
            } else if status.contains("(unhealthy)") {
                "unhealthy"
            } else if status.contains("(health: starting)") {
                "starting"
            } else {
                ""
            };
            ContainerInfo {
                id: c.id.unwrap_or_default(),
                service: labels.get("com.docker.compose.service").cloned().unwrap_or_default(),
                state: c.state.unwrap_or_default(),
                status,
                image: c.image.unwrap_or_default(),
                health: health.into(),
            }
        })
        .collect();
    out.sort_by(|a, b| a.service.cmp(&b.service));
    Ok(out)
}

pub async fn image_digests(docker: &Docker, project: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(cs) = containers_of(docker, project).await {
        for c in cs {
            if let Ok(info) = docker.inspect_container(&c.id, None).await {
                let image_id = info.image.unwrap_or_default();
                if let Ok(img) = docker.inspect_image(&image_id).await {
                    let digest = img.repo_digests.and_then(|d| d.first().cloned()).unwrap_or(image_id);
                    out.push(format!("{}: {digest}", c.service));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub async fn logs(docker: &Docker, container_id: &str, tail: usize) -> Result<String> {
    let opts = LogsOptions::<String> { stdout: true, stderr: true, tail: tail.to_string(), timestamps: true, ..Default::default() };
    let mut stream = docker.logs(container_id, Some(opts));
    let mut out = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(l) => out.push_str(&l.to_string()),
            Err(e) => {
                out.push_str(&format!("\n[log error: {e}]\n"));
                break;
            }
        }
    }
    Ok(out)
}

pub async fn ping(state: &Shared) -> bool {
    match &state.docker {
        Some(d) => d.ping().await.is_ok(),
        None => false,
    }
}
