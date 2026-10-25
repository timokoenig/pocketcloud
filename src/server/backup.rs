//! Nightly backups with restic to S3-compatible storage (Hetzner Object Storage). Opt-in per installation,
//! opt-out per app. The repository password is derived from the master key, so the recovery phrase plus the
//! bucket credentials restore everything. Never backed up: the master key itself.
use anyhow::{anyhow, bail, Context, Result};
use chrono::{Datelike, Timelike};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::jobs::{self, Log};
use super::state::{Shared, State};
use super::{db, docker};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct BackupStatus {
    pub enabled: bool,
    pub repo: String,
    pub hour: u8,
    pub last_ok: String,
    pub last_error: String,
    pub last_snapshot: String,
    pub snapshots: String,
    pub bytes: String,
    pub last_check: String,
}

pub fn repo(state: &State) -> Option<String> {
    state.config.backup.as_ref().map(|b| format!("s3:{}/{}", b.s3_endpoint.trim_end_matches('/'), b.bucket))
}

fn env(state: &State) -> Result<Vec<(String, String)>> {
    let b = state.config.backup.as_ref().ok_or_else(|| anyhow!("backups are not configured"))?;
    let cache = state.config.data_dir.join("restic-cache");
    std::fs::create_dir_all(&cache)?;
    Ok(vec![
        ("RESTIC_REPOSITORY".into(), repo(state).unwrap_or_default()),
        ("RESTIC_PASSWORD".into(), state.key.derive("restic").to_string()),
        ("RESTIC_CACHE_DIR".into(), cache.display().to_string()),
        ("AWS_ACCESS_KEY_ID".into(), b.access_key.clone()),
        ("AWS_SECRET_ACCESS_KEY".into(), b.secret_key.clone()),
        ("HOME".into(), state.config.data_dir.display().to_string()),
    ])
}

/// Run restic with retries: Hetzner Object Storage answers a small share of requests with a spurious
/// "Access Denied", which restic treats as permanent. Three attempts a few seconds apart cover it.
async fn restic(state: &State, args: &[&str], log: Option<&Log>) -> Result<String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match restic_once(state, args, log).await {
            Ok(out) => return Ok(out),
            Err(e) if attempt < 3 && is_transient(&e.to_string()) => {
                if let Some(l) = log {
                    l.line(format!("transient storage error, retrying ({e})")).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5 * attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_transient(msg: &str) -> bool {
    ["Access Denied", "connection reset", "timeout", "Timeout", "EOF", "503", "500", "SlowDown"].iter().any(|s| msg.contains(s))
}

/// One restic run; stdout is returned, stderr goes to the log. Non-zero exit is an error with restic's own message.
async fn restic_once(state: &State, args: &[&str], log: Option<&Log>) -> Result<String> {
    let mut cmd = Command::new("restic");
    cmd.args(args).envs(env(state)?).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    if let Some(l) = log {
        l.line(format!("$ restic {}", args.join(" "))).await;
    }
    let mut child = cmd.spawn().context("start restic")?;
    let stderr = child.stderr.take().unwrap();
    let log2 = log.cloned();
    let err_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut tail: Vec<String> = Vec::new();
        while let Ok(Some(l)) = lines.next_line().await {
            if let Some(log) = &log2 {
                log.line(&l).await;
            }
            if !l.trim().is_empty() {
                tail.push(l);
                if tail.len() > 4 {
                    tail.remove(0);
                }
            }
        }
        // restic puts the reason on a "Fatal:" line, followed by hints; prefer the reason
        tail.iter().find(|l| l.starts_with("Fatal:")).cloned().unwrap_or_else(|| tail.last().cloned().unwrap_or_default())
    });
    let mut out = String::new();
    {
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            out.push_str(&l);
            out.push('\n');
        }
    }
    let status = child.wait().await?;
    let last_err = err_task.await.unwrap_or_default();
    if !status.success() {
        bail!("restic {} failed: {}", args.first().unwrap_or(&""), if last_err.is_empty() { "see the job log".to_string() } else { last_err });
    }
    Ok(out)
}

pub async fn status(state: &State) -> BackupStatus {
    let get = |k: &str| {
        let k = k.to_string();
        async move { db::kv_get(&state.db, &k).await.ok().flatten().unwrap_or_default() }
    };
    BackupStatus {
        enabled: state.config.backup.is_some(),
        repo: repo(state).unwrap_or_default(),
        hour: state.config.backup.as_ref().map(|b| b.hour).unwrap_or(3),
        last_ok: get("backup.last_ok").await,
        last_error: get("backup.last_error").await,
        last_snapshot: get("backup.last_snapshot").await,
        snapshots: get("backup.snapshots").await,
        bytes: get("backup.bytes").await,
        last_check: get("backup.last_check").await,
    }
}

pub async fn spawn_job(state: &Shared) -> Result<i64> {
    let redact = state.config.backup.as_ref().map(|b| vec![b.secret_key.clone()]).unwrap_or_default();
    jobs::spawn(state, "backup", None, redact, |s, log| run(s, log)).await
}

/// Called once a minute from the host loop: starts the nightly job in its window, once per day.
pub async fn tick(state: &Shared) {
    let Some(b) = &state.config.backup else { return };
    let now = chrono::Local::now();
    if now.hour() != b.hour as u32 || !(30..35).contains(&now.minute()) {
        return;
    }
    let today = now.format("%Y-%m-%d").to_string();
    if db::kv_get(&state.db, "backup.last_date").await.ok().flatten().as_deref() == Some(today.as_str()) {
        return;
    }
    let _ = db::kv_set(&state.db, "backup.last_date", &today).await;
    if let Err(e) = spawn_job(state).await {
        tracing::warn!("nightly backup not started: {e:#}");
    }
}

pub async fn run(state: Shared, log: Log) -> Result<()> {
    let res = run_inner(&state, &log).await;
    match &res {
        Ok(()) => {
            db::kv_set(&state.db, "backup.last_ok", &db::now()).await?;
            db::kv_set(&state.db, "backup.last_error", "").await?;
            log.line("backup complete").await;
        }
        Err(e) => {
            db::kv_set(&state.db, "backup.last_error", &format!("{} · {e:#}", db::now())).await?;
        }
    }
    res
}

async fn run_inner(state: &State, log: &Log) -> Result<()> {
    if state.config.dev {
        bail!("no backups in dev mode");
    }
    let name = &state.config.name;
    if restic(state, &["cat", "config"], None).await.is_err() {
        log.line("repository not initialised yet").await;
        restic(state, &["init"], Some(log)).await?;
    }

    // staging: database copy, server config, database dumps
    let stage: PathBuf = state.config.data_dir.join("backup-stage");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    crate::install::set_mode(&stage, 0o700)?;
    let db_copy = stage.join("pocketcloud.db");
    sqlx::query(&format!("VACUUM INTO '{}'", db_copy.display())).execute(&state.db).await.context("copy database")?;
    if let Err(e) = std::fs::copy("/etc/pocketcloud/config.toml", stage.join("config.toml")) {
        log.line(format!("config.toml not copied: {e}")).await;
    }

    let mut paths: Vec<String> = vec![stage.display().to_string()];
    let mut problems: Vec<String> = Vec::new();
    let mut included = Vec::new();
    let mut skipped = Vec::new();
    for app in db::apps(&state.db).await? {
        if app.backup == 0 {
            skipped.push(app.name.clone());
            continue;
        }
        included.push(app.name.clone());
        let files = state.config.apps_dir().join(&app.name).join("files");
        if files.is_dir() {
            paths.push(files.display().to_string());
        }
        for v in volumes_of(&app.name).await {
            let p = format!("/var/lib/docker/volumes/{v}/_data");
            if std::path::Path::new(&p).is_dir() {
                paths.push(p);
            }
        }
        if let Some(d) = &state.docker {
            for c in docker::containers_of(d, &app.name).await.unwrap_or_default() {
                if c.state != "running" {
                    continue;
                }
                if let Some(cmd) = dump_command(&c.image) {
                    let dir = stage.join("apps").join(&app.name);
                    std::fs::create_dir_all(&dir)?;
                    let file = dir.join(format!("{}.sql", c.service));
                    log.line(format!("dumping database of {}/{}", app.name, c.service)).await;
                    match dump(&c.id, cmd, &file).await {
                        Ok(bytes) => log.line(format!("  {} bytes", bytes)).await,
                        Err(e) => problems.push(format!("dump of {}/{} failed: {e:#}", app.name, c.service)),
                    }
                }
            }
        }
    }
    log.line(format!("apps included: {}", if included.is_empty() { "none".into() } else { included.join(", ") })).await;
    if !skipped.is_empty() {
        log.line(format!("apps excluded by their setting: {}", skipped.join(", "))).await;
    }

    let host = format!("pocketcloud-{name}");
    let mut args: Vec<&str> = vec!["backup", "--json", "--host", &host, "--tag", "pocketcloud", "--exclude-caches"];
    args.extend(paths.iter().map(|s| s.as_str()));
    let out = restic(state, &args, Some(log)).await?;
    for line in out.lines().rev() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v.get("message_type").and_then(|m| m.as_str()) == Some("summary") {
            let snap = v.get("snapshot_id").and_then(|s| s.as_str()).unwrap_or("").chars().take(8).collect::<String>();
            let bytes = v.get("total_bytes_processed").and_then(|b| b.as_u64()).unwrap_or(0);
            let added = v.get("data_added").and_then(|b| b.as_u64()).unwrap_or(0);
            log.line(format!("snapshot {snap}: {} MB in the backup set, {} MB new", bytes / 1_000_000, added / 1_000_000)).await;
            db::kv_set(&state.db, "backup.last_snapshot", &snap).await?;
            db::kv_set(&state.db, "backup.bytes", &bytes.to_string()).await?;
            break;
        }
    }

    // every nightly snapshot is kept for 30 days, nothing older survives
    restic(state, &["forget", "--keep-within", "30d", "--prune", "--quiet"], Some(log)).await?;
    if let Ok(list) = restic(state, &["snapshots", "--json"], None).await {
        let n = serde_json::from_str::<serde_json::Value>(&list).ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
        db::kv_set(&state.db, "backup.snapshots", &n.to_string()).await?;
    }

    // weekly integrity check
    let now = chrono::Local::now();
    let week = format!("{}-{}", now.iso_week().year(), now.iso_week().week());
    if now.weekday() == chrono::Weekday::Sun && db::kv_get(&state.db, "backup.check_week").await?.as_deref() != Some(week.as_str()) {
        restic(state, &["check", "--read-data-subset=5%"], Some(log)).await?;
        db::kv_set(&state.db, "backup.check_week", &week).await?;
        db::kv_set(&state.db, "backup.last_check", &db::now()).await?;
    }
    let _ = std::fs::remove_dir_all(&stage);

    if !problems.is_empty() {
        bail!("snapshot stored, but: {}", problems.join("; "));
    }
    Ok(())
}

async fn volumes_of(app: &str) -> Vec<String> {
    let out = Command::new("docker")
        .args(["volume", "ls", "-q", "--filter", &format!("label=com.docker.compose.project={app}")])
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).filter(|l| !l.is_empty()).collect(),
        _ => vec![],
    }
}

/// Dump command for the databases we recognise by image name; the dump runs inside the container.
fn dump_command(image: &str) -> Option<&'static str> {
    let img = image.rsplit('/').next().unwrap_or(image).to_ascii_lowercase();
    if img.starts_with("postgres") || img.starts_with("timescale") || img.starts_with("pgvector") {
        Some(r#"pg_dumpall --clean --if-exists -U "${POSTGRES_USER:-postgres}""#)
    } else if img.starts_with("mysql") || img.starts_with("mariadb") {
        Some(r#"if command -v mariadb-dump >/dev/null; then d=mariadb-dump; else d=mysqldump; fi; $d --all-databases --single-transaction -uroot -p"${MYSQL_ROOT_PASSWORD:-$MARIADB_ROOT_PASSWORD}""#)
    } else {
        None
    }
}

async fn dump(container: &str, cmd: &str, file: &std::path::Path) -> Result<u64> {
    let out = Command::new("docker").args(["exec", container, "sh", "-c", cmd]).stdin(std::process::Stdio::null()).output().await?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("dump failed"));
    }
    std::fs::write(file, &out.stdout)?;
    crate::install::set_mode(file, 0o600)?;
    Ok(out.stdout.len() as u64)
}
