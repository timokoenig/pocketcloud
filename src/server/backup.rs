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

/// The backup settings: from the database (sealed with the master key, edited on the server page), seeded
/// from the config file on first start. None means backups are off and there is no backup UI.
pub async fn settings(state: &State) -> Option<super::config::BackupConfig> {
    let b64 = db::kv_get(&state.db, "backup.settings").await.ok().flatten()?;
    if b64.is_empty() {
        return None;
    }
    use base64::Engine;
    let sealed = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let json = state.key.open_string(&sealed).ok()?;
    serde_json::from_str(&json).ok()
}

pub async fn save_settings(state: &State, cfg: Option<&super::config::BackupConfig>) -> Result<()> {
    use base64::Engine;
    let value = match cfg {
        Some(c) => base64::engine::general_purpose::STANDARD.encode(state.key.seal(serde_json::to_string(c)?.as_bytes())),
        None => String::new(),
    };
    db::kv_set(&state.db, "backup.settings", &value).await
}

pub fn repo_of(b: &super::config::BackupConfig) -> String {
    format!("s3:{}/{}", b.s3_endpoint.trim_end_matches('/'), b.bucket)
}

async fn env(state: &State) -> Result<Vec<(String, String)>> {
    let b = settings(state).await.ok_or_else(|| anyhow!("backups are not configured"))?;
    let cache = state.config.data_dir.join("restic-cache");
    std::fs::create_dir_all(&cache)?;
    Ok(vec![
        ("RESTIC_REPOSITORY".into(), repo_of(&b)),
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
    cmd.args(args).envs(env(state).await?).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
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
    let cfg = settings(state).await;
    BackupStatus {
        enabled: cfg.is_some(),
        repo: cfg.as_ref().map(repo_of).unwrap_or_default(),
        hour: cfg.as_ref().map(|b| b.hour).unwrap_or(3),
        last_ok: get("backup.last_ok").await,
        last_error: get("backup.last_error").await,
        last_snapshot: get("backup.last_snapshot").await,
        snapshots: get("backup.snapshots").await,
        bytes: get("backup.bytes").await,
        last_check: get("backup.last_check").await,
    }
}

pub async fn spawn_job(state: &Shared) -> Result<i64> {
    let redact = settings(state).await.map(|b| vec![b.secret_key]).unwrap_or_default();
    jobs::spawn(state, "backup", None, redact, |s, log| run(s, log)).await
}

/// Called once a minute from the host loop: starts the nightly job in its window, once per day.
pub async fn tick(state: &Shared) {
    let Some(b) = settings(state).await else { return };
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
    if let Err(e) = refresh_snapshots(state).await {
        log.line(format!("snapshot list not refreshed: {e:#}")).await;
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

// ---------------------------------------------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub time: String,
}

/// Snapshots in the repository, newest first; also cached for the pages.
pub async fn refresh_snapshots(state: &State) -> Result<Vec<Snapshot>> {
    let out = restic(state, &["snapshots", "--json", "--tag", "pocketcloud"], None).await?;
    let v: serde_json::Value = serde_json::from_str(&out).context("snapshot list")?;
    let mut list: Vec<Snapshot> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| Snapshot {
            id: s.get("short_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            time: s.get("time").and_then(|x| x.as_str()).unwrap_or("").chars().take(16).collect::<String>().replace('T', " "),
        })
        .collect();
    list.reverse();
    db::kv_set(&state.db, "backup.snapshot_list", &serde_json::to_string(&list)?).await?;
    db::kv_set(&state.db, "backup.snapshots", &list.len().to_string()).await?;
    Ok(list)
}

pub async fn cached_snapshots(state: &State) -> Vec<Snapshot> {
    db::kv_get(&state.db, "backup.snapshot_list").await.ok().flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn valid_snapshot(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit()) || id == "latest"
}

async fn rsync(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    let out = Command::new("rsync")
        .arg("-a")
        .arg("--delete")
        .arg(format!("{}/", from.display()))
        .arg(format!("{}/", to.display()))
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("rsync")?;
    if !out.status.success() {
        bail!("rsync: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or(""));
    }
    Ok(())
}

/// Replay command for a dump, inside the database container, reading the dump from stdin.
fn replay_command(image: &str) -> Option<&'static str> {
    let img = image.rsplit('/').next().unwrap_or(image).to_ascii_lowercase();
    if img.starts_with("postgres") || img.starts_with("timescale") || img.starts_with("pgvector") {
        Some(r#"psql -q -U "${POSTGRES_USER:-postgres}" -d postgres -f -"#)
    } else if img.starts_with("mysql") || img.starts_with("mariadb") {
        Some(r#"if command -v mariadb >/dev/null; then c=mariadb; else c=mysql; fi; $c -uroot -p"${MYSQL_ROOT_PASSWORD:-$MARIADB_ROOT_PASSWORD}""#)
    } else {
        None
    }
}

/// Put an app's volumes, files and database dumps back from a snapshot. The app is stopped meanwhile.
pub async fn restore_app(state: Shared, app_id: i64, snapshot: String, log: Log) -> Result<()> {
    if !valid_snapshot(&snapshot) {
        bail!("not a snapshot id");
    }
    let app = db::app(&state.db, app_id).await?.ok_or_else(|| anyhow!("app not found"))?;
    let p = super::deploy::prepare(&state, &app, None).await?;
    let tmp = state.config.data_dir.join("restore").join(&app.name);
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    crate::install::set_mode(&tmp, 0o700)?;

    let vol_glob = format!("/var/lib/docker/volumes/{}_*", app.name);
    let files_path = format!("/var/lib/pocketcloud/apps/{}/files", app.name);
    let dumps_path = format!("/var/lib/pocketcloud/backup-stage/apps/{}", app.name);
    log.line(format!("restoring {} from snapshot {snapshot}", app.name)).await;
    let target = tmp.display().to_string();
    restic(&state, &["restore", &snapshot, "--target", &target, "--include", &vol_glob, "--include", &files_path, "--include", &dumps_path], Some(&log)).await?;

    db::set_app_status(&state.db, app.id, "deploying", "restoring from backup").await?;
    docker::compose(&state, &app.name, &p.app_dir, &p.env_file, &["down", "--remove-orphans"], &log).await.context("stop")?;
    // containers and volumes exist afterwards, nothing runs yet
    docker::compose(&state, &app.name, &p.app_dir, &p.env_file, &["create"], &log).await.context("create")?;

    let mut restored = 0;
    let vols = tmp.join("var/lib/docker/volumes");
    if let Ok(entries) = std::fs::read_dir(&vols) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let dest = std::path::Path::new("/var/lib/docker/volumes").join(&name).join("_data");
            if !dest.is_dir() {
                log.line(format!("volume {name} is not part of the app any more, skipped")).await;
                continue;
            }
            log.line(format!("volume {name}")).await;
            rsync(&e.path().join("_data"), &dest).await?;
            restored += 1;
        }
    }
    let files_src = tmp.join(files_path.trim_start_matches('/'));
    if files_src.is_dir() {
        log.line("files directory").await;
        rsync(&files_src, &state.config.apps_dir().join(&app.name).join("files")).await?;
        restored += 1;
    }

    // database dumps: start only the database services, replay, then everything
    let dumps_dir = tmp.join(dumps_path.trim_start_matches('/'));
    let mut dumps: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dumps_dir) {
        for e in entries.flatten() {
            if let Some(service) = e.file_name().to_string_lossy().strip_suffix(".sql") {
                dumps.push((service.to_string(), e.path()));
            }
        }
    }
    if !dumps.is_empty() {
        let services: Vec<&str> = dumps.iter().map(|(s, _)| s.as_str()).collect();
        let mut args = vec!["up", "-d", "--wait", "--wait-timeout", "180"];
        args.extend(services.iter().copied());
        docker::compose(&state, &app.name, &p.app_dir, &p.env_file, &args, &log).await.context("start database services")?;
        let docker_api = state.docker.as_ref().ok_or_else(|| anyhow!("docker not available"))?;
        let containers = docker::containers_of(docker_api, &app.name).await?;
        for (service, file) in &dumps {
            let Some(c) = containers.iter().find(|c| &c.service == service) else {
                log.line(format!("no container for {service}, dump not replayed")).await;
                continue;
            };
            let Some(cmd) = replay_command(&c.image) else {
                log.line(format!("{service}: unknown database image, dump not replayed")).await;
                continue;
            };
            log.line(format!("replaying dump into {service}")).await;
            let input = std::fs::File::open(file)?;
            let out = Command::new("docker").args(["exec", "-i", &c.id, "sh", "-c", cmd]).stdin(input).output().await?;
            if !out.status.success() {
                bail!("replay into {service} failed: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or(""));
            }
            let errs = String::from_utf8_lossy(&out.stderr).lines().filter(|l| l.contains("ERROR")).count();
            log.line(format!("  done{}", if errs > 0 { format!(" ({errs} statements reported errors, usually roles or databases that already exist)") } else { String::new() })).await;
            restored += 1;
        }
    }

    docker::compose(&state, &app.name, &p.app_dir, &p.env_file, &["up", "-d", "--wait", "--wait-timeout", "180"], &log).await.context("start")?;
    db::set_app_desired(&state.db, app.id, "running").await?;
    db::set_app_status(&state.db, app.id, "running", "").await?;
    super::reconcile::apply(&state).await?;
    let _ = std::fs::remove_dir_all(&tmp);
    log.line(format!("restore complete: {restored} item(s) restored")).await;
    Ok(())
}

/// Bring apps of an earlier installation back from a snapshot: definitions (compose, routes, secrets, settings)
/// from the backed-up database, then deploy and data restore per app. Apps that exist here already are skipped.
pub async fn restore_import(state: Shared, snapshot: String, log: Log) -> Result<()> {
    if !valid_snapshot(&snapshot) {
        bail!("not a snapshot id");
    }
    let tmp = state.config.data_dir.join("restore").join("db");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    crate::install::set_mode(&tmp, 0o700)?;
    let target = tmp.display().to_string();
    restic(&state, &["restore", &snapshot, "--target", &target, "--include", "/var/lib/pocketcloud/backup-stage/pocketcloud.db"], Some(&log)).await?;
    let db_path = tmp.join("var/lib/pocketcloud/backup-stage/pocketcloud.db");
    if !db_path.exists() {
        bail!("the snapshot has no pocketcloud database");
    }
    let old = db::open_read_only(&db_path).await?;

    #[derive(sqlx::FromRow)]
    struct OldApp {
        id: i64,
        name: String,
        compose: String,
        egress: String,
        backup: i64,
    }
    let apps: Vec<OldApp> = sqlx::query_as("SELECT id, name, compose, COALESCE(egress, 'all') AS egress, COALESCE(backup, 1) AS backup FROM apps").fetch_all(&old).await?;
    let mut imported: Vec<i64> = Vec::new();
    for a in &apps {
        if db::app_by_name(&state.db, &a.name).await?.is_some() {
            log.line(format!("{}: exists here already, not imported (restore its data from the app page)", a.name)).await;
            continue;
        }
        let app = db::create_app(&state.db, &a.name, &a.compose).await?;
        db::set_app_egress(&state.db, app.id, &a.egress).await?;
        db::set_app_backup(&state.db, app.id, a.backup != 0).await?;
        let secrets: Vec<(String, Vec<u8>, String)> = match sqlx::query_as("SELECT key, sealed, services FROM secrets WHERE app_id = ?").bind(a.id).fetch_all(&old).await {
            Ok(v) => v,
            Err(_) => sqlx::query_as::<_, (String, Vec<u8>)>("SELECT key, sealed FROM secrets WHERE app_id = ?").bind(a.id).fetch_all(&old).await?.into_iter().map(|(k, s)| (k, s, String::new())).collect(),
        };
        for (key, sealed, services) in &secrets {
            if state.key.open(sealed).is_err() {
                bail!("secret {key} of {} cannot be opened: this server has a different master key than the backup", a.name);
            }
            db::put_secret(&state.db, app.id, key, sealed, services).await?;
        }
        let routes: Vec<(String, String, i64, String, i64, i64)> =
            sqlx::query_as("SELECT host, service, port, expose, COALESCE(waf, 1), COALESCE(headers, 1) FROM routes WHERE app_id = ?").bind(a.id).fetch_all(&old).await?;
        for (host, service, port, expose, waf, headers) in &routes {
            if let Err(e) = db::add_route(&state.db, app.id, host, service, *port, expose, *waf != 0, *headers != 0).await {
                log.line(format!("route {host} not added: {e}")).await;
            }
        }
        log.line(format!("{}: imported with {} secret(s) and {} route(s)", a.name, secrets.len(), routes.len())).await;
        imported.push(app.id);
    }
    old.close().await;
    let _ = std::fs::remove_dir_all(&tmp);

    for id in imported {
        let name = db::app(&state.db, id).await?.map(|a| a.name).unwrap_or_default();
        log.line(format!("--- deploying {name}")).await;
        if let Err(e) = super::deploy::deploy(state.clone(), id, log.clone(), true).await {
            log.line(format!("{name}: deploy failed ({e:#}); data not restored, fix the app and restore from its page")).await;
            continue;
        }
        log.line(format!("--- restoring data of {name}")).await;
        if let Err(e) = Box::pin(restore_app(state.clone(), id, snapshot.clone(), log.clone())).await {
            log.line(format!("{name}: data restore failed: {e:#}")).await;
        }
    }
    log.line("import complete").await;
    Ok(())
}
