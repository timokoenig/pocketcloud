//! SQLite schema and queries. Desired state lives here; the reconciler makes the system match it.
#![allow(dead_code)] // row structs mirror the tables
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};
use std::path::Path;
use std::str::FromStr;

pub type Db = SqlitePool;

pub async fn open(path: &Path) -> Result<Db> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(10))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await.context("open database")?;
    migrate(&pool).await?;
    Ok(pool)
}

const SCHEMA: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf TEXT NOT NULL,
        created TEXT NOT NULL,
        expires TEXT NOT NULL,
        remote TEXT NOT NULL DEFAULT ''
    )"#,
    r#"CREATE TABLE IF NOT EXISTS apps (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        net_index INTEGER NOT NULL UNIQUE,
        compose TEXT NOT NULL DEFAULT '',
        desired TEXT NOT NULL DEFAULT 'stopped',
        status TEXT NOT NULL DEFAULT 'new',
        status_detail TEXT NOT NULL DEFAULT '',
        created TEXT NOT NULL,
        updated TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS routes (
        id INTEGER PRIMARY KEY,
        app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        host TEXT NOT NULL UNIQUE,
        service TEXT NOT NULL,
        port INTEGER NOT NULL,
        expose TEXT NOT NULL CHECK (expose IN ('public','internal'))
    )"#,
    r#"CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY,
        app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        key TEXT NOT NULL,
        sealed BLOB NOT NULL,
        updated TEXT NOT NULL,
        UNIQUE (app_id, key)
    )"#,
    r#"CREATE TABLE IF NOT EXISTS releases (
        id INTEGER PRIMARY KEY,
        app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        compose_rendered TEXT NOT NULL,
        images TEXT NOT NULL DEFAULT '[]',
        outcome TEXT NOT NULL,
        created TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS registries (
        id INTEGER PRIMARY KEY,
        host TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        sealed_password BLOB NOT NULL,
        updated TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS vpn_peers (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL UNIQUE,
        sealed_psk BLOB NOT NULL,
        ip TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL CHECK (scope IN ('full','web')),
        created TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        app_id INTEGER REFERENCES apps(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        log TEXT NOT NULL DEFAULT '',
        created TEXT NOT NULL,
        finished TEXT
    )"#,
    r#"CREATE TABLE IF NOT EXISTS certificates (
        domain TEXT PRIMARY KEY,
        not_after TEXT,
        last_error TEXT NOT NULL DEFAULT '',
        updated TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT ''
    )"#,
    r#"CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )"#,
];

async fn migrate(db: &Db) -> Result<()> {
    for stmt in SCHEMA {
        sqlx::query(stmt).execute(db).await.with_context(|| format!("schema: {stmt}"))?;
    }
    // columns added after the first release
    let cols: Vec<(i64, String)> = sqlx::query_as("SELECT cid, name FROM pragma_table_info('routes')").fetch_all(db).await?;
    if !cols.iter().any(|(_, n)| n == "waf") {
        sqlx::query("ALTER TABLE routes ADD COLUMN waf INTEGER NOT NULL DEFAULT 1").execute(db).await?;
    }
    if !cols.iter().any(|(_, n)| n == "headers") {
        sqlx::query("ALTER TABLE routes ADD COLUMN headers INTEGER NOT NULL DEFAULT 1").execute(db).await?;
    }
    let cols: Vec<(i64, String)> = sqlx::query_as("SELECT cid, name FROM pragma_table_info('apps')").fetch_all(db).await?;
    if !cols.iter().any(|(_, n)| n == "egress") {
        sqlx::query("ALTER TABLE apps ADD COLUMN egress TEXT NOT NULL DEFAULT 'all'").execute(db).await?;
    }
    if !cols.iter().any(|(_, n)| n == "backup") {
        sqlx::query("ALTER TABLE apps ADD COLUMN backup INTEGER NOT NULL DEFAULT 1").execute(db).await?;
    }
    let cols: Vec<(i64, String)> = sqlx::query_as("SELECT cid, name FROM pragma_table_info('releases')").fetch_all(db).await?;
    if !cols.iter().any(|(_, n)| n == "scan") {
        sqlx::query("ALTER TABLE releases ADD COLUMN scan TEXT NOT NULL DEFAULT ''").execute(db).await?;
    }
    Ok(())
}

pub fn now() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

// ---- users & sessions ----

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

pub async fn user_by_name(db: &Db, username: &str) -> Result<Option<User>> {
    Ok(sqlx::query_as("SELECT id, username, password_hash FROM users WHERE username = ?").bind(username).fetch_optional(db).await?)
}

pub async fn user_count(db: &Db) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(db).await?)
}

pub async fn create_user(db: &Db, username: &str, password_hash: &str) -> Result<()> {
    sqlx::query("INSERT INTO users (username, password_hash, created) VALUES (?, ?, ?)")
        .bind(username)
        .bind(password_hash)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_password(db: &Db, username: &str, password_hash: &str) -> Result<bool> {
    let r = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?").bind(password_hash).bind(username).execute(db).await?;
    Ok(r.rows_affected() == 1)
}

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub csrf: String,
    pub expires: String,
    pub username: String,
}

pub async fn create_session(db: &Db, user_id: i64, remote: &str, ttl_hours: i64) -> Result<Session> {
    let id = crate::crypto::random_token(32);
    let csrf = crate::crypto::random_token(16);
    let expires = (Utc::now() + chrono::Duration::hours(ttl_hours)).to_rfc3339();
    sqlx::query("INSERT INTO sessions (id, user_id, csrf, created, expires, remote) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(user_id)
        .bind(&csrf)
        .bind(now())
        .bind(&expires)
        .bind(remote)
        .execute(db)
        .await?;
    session(db, &id).await?.context("session just created")
}

pub async fn session(db: &Db, id: &str) -> Result<Option<Session>> {
    let s: Option<Session> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.csrf, s.expires, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    if let Some(s) = &s {
        if parse_time(&s.expires).map(|e| e < Utc::now()).unwrap_or(true) {
            delete_session(db, id).await?;
            return Ok(None);
        }
    }
    Ok(s)
}

pub async fn delete_session(db: &Db, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn purge_sessions(db: &Db) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires < ?").bind(now()).execute(db).await?;
    Ok(())
}

// ---- apps ----

#[derive(Debug, Clone, FromRow)]
pub struct App {
    pub id: i64,
    pub name: String,
    pub net_index: i64,
    pub compose: String,
    /// running | stopped
    pub desired: String,
    /// new | deploying | running | failed | stopped | rolled_back
    pub status: String,
    pub status_detail: String,
    pub created: String,
    pub updated: String,
    /// internet access of the containers: `all`, `none`, or allowed TCP ports like `587,443`
    pub egress: String,
    /// volumes, files and database dumps of this app go into the nightly backup
    pub backup: i64,
}

pub async fn set_app_backup(db: &Db, id: i64, on: bool) -> Result<()> {
    sqlx::query("UPDATE apps SET backup = ?, updated = ? WHERE id = ?").bind(on as i64).bind(now()).bind(id).execute(db).await?;
    Ok(())
}

pub async fn kv_get(db: &Db, key: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT value FROM kv WHERE key = ?").bind(key).fetch_optional(db).await?)
}

pub async fn kv_set(db: &Db, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_app_egress(db: &Db, id: i64, egress: &str) -> Result<()> {
    sqlx::query("UPDATE apps SET egress = ?, updated = ? WHERE id = ?").bind(egress).bind(now()).bind(id).execute(db).await?;
    Ok(())
}

pub async fn apps(db: &Db) -> Result<Vec<App>> {
    Ok(sqlx::query_as("SELECT * FROM apps ORDER BY name").fetch_all(db).await?)
}

pub async fn app(db: &Db, id: i64) -> Result<Option<App>> {
    Ok(sqlx::query_as("SELECT * FROM apps WHERE id = ?").bind(id).fetch_optional(db).await?)
}

pub async fn app_by_name(db: &Db, name: &str) -> Result<Option<App>> {
    Ok(sqlx::query_as("SELECT * FROM apps WHERE name = ?").bind(name).fetch_optional(db).await?)
}

pub async fn create_app(db: &Db, name: &str, compose: &str) -> Result<App> {
    let max: Option<i64> = sqlx::query_scalar("SELECT max(net_index) FROM apps").fetch_one(db).await?;
    let idx = max.unwrap_or(0) + 1;
    if idx > 250 {
        anyhow::bail!("too many apps for the 172.30.0.0/16 range");
    }
    let n = now();
    sqlx::query("INSERT INTO apps (name, net_index, compose, desired, status, created, updated) VALUES (?, ?, ?, 'stopped', 'new', ?, ?)")
        .bind(name)
        .bind(idx)
        .bind(compose)
        .bind(&n)
        .bind(&n)
        .execute(db)
        .await?;
    app_by_name(db, name).await?.context("app just created")
}

pub async fn update_compose(db: &Db, id: i64, compose: &str) -> Result<()> {
    sqlx::query("UPDATE apps SET compose = ?, updated = ? WHERE id = ?").bind(compose).bind(now()).bind(id).execute(db).await?;
    Ok(())
}

pub async fn set_app_status(db: &Db, id: i64, status: &str, detail: &str) -> Result<()> {
    sqlx::query("UPDATE apps SET status = ?, status_detail = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(detail)
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_app_desired(db: &Db, id: i64, desired: &str) -> Result<()> {
    sqlx::query("UPDATE apps SET desired = ?, updated = ? WHERE id = ?").bind(desired).bind(now()).bind(id).execute(db).await?;
    Ok(())
}

pub async fn delete_app(db: &Db, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM apps WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

// ---- routes ----

#[derive(Debug, Clone, FromRow)]
pub struct Route {
    pub id: i64,
    pub app_id: i64,
    pub host: String,
    pub service: String,
    pub port: i64,
    pub expose: String,
    /// web application firewall in front of this route (public routes only)
    pub waf: i64,
    /// default security headers on responses (public routes only)
    pub headers: i64,
}

pub async fn routes(db: &Db) -> Result<Vec<Route>> {
    Ok(sqlx::query_as("SELECT * FROM routes ORDER BY host").fetch_all(db).await?)
}

pub async fn routes_of(db: &Db, app_id: i64) -> Result<Vec<Route>> {
    Ok(sqlx::query_as("SELECT * FROM routes WHERE app_id = ? ORDER BY host").bind(app_id).fetch_all(db).await?)
}

pub async fn add_route(db: &Db, app_id: i64, host: &str, service: &str, port: i64, expose: &str, waf: bool, headers: bool) -> Result<()> {
    sqlx::query("INSERT INTO routes (app_id, host, service, port, expose, waf, headers) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(app_id)
        .bind(host)
        .bind(service)
        .bind(port)
        .bind(expose)
        .bind(waf as i64)
        .bind(headers as i64)
        .execute(db)
        .await?;
    Ok(())
}

/// `what` is `waf` or `headers`.
pub async fn set_route_flag(db: &Db, app_id: i64, id: i64, what: &str, on: bool) -> Result<()> {
    let sql = match what {
        "waf" => "UPDATE routes SET waf = ? WHERE id = ? AND app_id = ?",
        "headers" => "UPDATE routes SET headers = ? WHERE id = ? AND app_id = ?",
        _ => anyhow::bail!("unknown route flag"),
    };
    sqlx::query(sql).bind(on as i64).bind(id).bind(app_id).execute(db).await?;
    Ok(())
}

pub async fn delete_route(db: &Db, app_id: i64, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM routes WHERE id = ? AND app_id = ?").bind(id).bind(app_id).execute(db).await?;
    Ok(())
}

// ---- secrets ----

#[derive(Debug, Clone, FromRow)]
pub struct Secret {
    pub id: i64,
    pub app_id: i64,
    pub key: String,
    pub sealed: Vec<u8>,
    pub updated: String,
}

pub async fn secrets_of(db: &Db, app_id: i64) -> Result<Vec<Secret>> {
    Ok(sqlx::query_as("SELECT * FROM secrets WHERE app_id = ? ORDER BY key").bind(app_id).fetch_all(db).await?)
}

pub async fn put_secret(db: &Db, app_id: i64, key: &str, sealed: &[u8]) -> Result<()> {
    sqlx::query(
        "INSERT INTO secrets (app_id, key, sealed, updated) VALUES (?, ?, ?, ?)
         ON CONFLICT (app_id, key) DO UPDATE SET sealed = excluded.sealed, updated = excluded.updated",
    )
    .bind(app_id)
    .bind(key)
    .bind(sealed)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_secret(db: &Db, app_id: i64, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM secrets WHERE app_id = ? AND key = ?").bind(app_id).bind(key).execute(db).await?;
    Ok(())
}

// ---- releases ----

#[derive(Debug, Clone, FromRow)]
pub struct Release {
    pub id: i64,
    pub app_id: i64,
    pub compose_rendered: String,
    /// JSON list of "image@sha256:..." strings
    pub images: String,
    /// deployed | failed | rolled_back
    pub outcome: String,
    pub created: String,
    /// JSON from the vulnerability scan, empty when not scanned
    pub scan: String,
}

pub async fn releases_of(db: &Db, app_id: i64, limit: i64) -> Result<Vec<Release>> {
    Ok(sqlx::query_as("SELECT * FROM releases WHERE app_id = ? ORDER BY id DESC LIMIT ?").bind(app_id).bind(limit).fetch_all(db).await?)
}

pub async fn set_release_scan(db: &Db, id: i64, scan: &str) -> Result<()> {
    sqlx::query("UPDATE releases SET scan = ? WHERE id = ?").bind(scan).bind(id).execute(db).await?;
    Ok(())
}

pub async fn last_good_release(db: &Db, app_id: i64) -> Result<Option<Release>> {
    Ok(sqlx::query_as("SELECT * FROM releases WHERE app_id = ? AND outcome = 'deployed' ORDER BY id DESC LIMIT 1")
        .bind(app_id)
        .fetch_optional(db)
        .await?)
}

pub async fn add_release(db: &Db, app_id: i64, compose_rendered: &str, images: &[String], outcome: &str, scan: &str) -> Result<i64> {
    let r = sqlx::query("INSERT INTO releases (app_id, compose_rendered, images, outcome, created, scan) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(app_id)
        .bind(compose_rendered)
        .bind(serde_json::to_string(images)?)
        .bind(outcome)
        .bind(now())
        .bind(scan)
        .execute(db)
        .await?;
    Ok(r.last_insert_rowid())
}

// ---- registries ----

#[derive(Debug, Clone, FromRow)]
pub struct Registry {
    pub id: i64,
    pub host: String,
    pub username: String,
    pub sealed_password: Vec<u8>,
    pub updated: String,
}

pub async fn registries(db: &Db) -> Result<Vec<Registry>> {
    Ok(sqlx::query_as("SELECT * FROM registries ORDER BY host").fetch_all(db).await?)
}

pub async fn put_registry(db: &Db, host: &str, username: &str, sealed_password: &[u8]) -> Result<()> {
    sqlx::query(
        "INSERT INTO registries (host, username, sealed_password, updated) VALUES (?, ?, ?, ?)
         ON CONFLICT (host) DO UPDATE SET username = excluded.username, sealed_password = excluded.sealed_password, updated = excluded.updated",
    )
    .bind(host)
    .bind(username)
    .bind(sealed_password)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_registry(db: &Db, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM registries WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

// ---- vpn peers ----

#[derive(Debug, Clone, FromRow)]
pub struct VpnPeer {
    pub id: i64,
    pub name: String,
    pub public_key: String,
    pub sealed_psk: Vec<u8>,
    pub ip: String,
    pub scope: String,
    pub created: String,
}

pub async fn vpn_peers(db: &Db) -> Result<Vec<VpnPeer>> {
    Ok(sqlx::query_as("SELECT * FROM vpn_peers ORDER BY name").fetch_all(db).await?)
}

pub async fn add_vpn_peer(db: &Db, name: &str, public_key: &str, sealed_psk: &[u8], ip: &str, scope: &str) -> Result<()> {
    sqlx::query("INSERT INTO vpn_peers (name, public_key, sealed_psk, ip, scope, created) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(name)
        .bind(public_key)
        .bind(sealed_psk)
        .bind(ip)
        .bind(scope)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_vpn_peer(db: &Db, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM vpn_peers WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

// ---- jobs ----

#[derive(Debug, Clone, FromRow)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub app_id: Option<i64>,
    /// queued | running | done | failed
    pub status: String,
    pub log: String,
    pub created: String,
    pub finished: Option<String>,
}

pub async fn create_job(db: &Db, kind: &str, app_id: Option<i64>) -> Result<i64> {
    let r = sqlx::query("INSERT INTO jobs (kind, app_id, status, created) VALUES (?, ?, 'queued', ?)")
        .bind(kind)
        .bind(app_id)
        .bind(now())
        .execute(db)
        .await?;
    Ok(r.last_insert_rowid())
}

pub async fn job(db: &Db, id: i64) -> Result<Option<Job>> {
    Ok(sqlx::query_as("SELECT * FROM jobs WHERE id = ?").bind(id).fetch_optional(db).await?)
}

pub async fn jobs_of(db: &Db, app_id: i64, limit: i64) -> Result<Vec<Job>> {
    Ok(sqlx::query_as("SELECT * FROM jobs WHERE app_id = ? ORDER BY id DESC LIMIT ?").bind(app_id).bind(limit).fetch_all(db).await?)
}

pub async fn recent_jobs(db: &Db, limit: i64) -> Result<Vec<Job>> {
    Ok(sqlx::query_as("SELECT * FROM jobs ORDER BY id DESC LIMIT ?").bind(limit).fetch_all(db).await?)
}

pub async fn active_job_of(db: &Db, app_id: i64) -> Result<Option<Job>> {
    Ok(sqlx::query_as("SELECT * FROM jobs WHERE app_id = ? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1")
        .bind(app_id)
        .fetch_optional(db)
        .await?)
}

pub async fn job_set_status(db: &Db, id: i64, status: &str) -> Result<()> {
    let finished = if status == "done" || status == "failed" { Some(now()) } else { None };
    sqlx::query("UPDATE jobs SET status = ?, finished = COALESCE(?, finished) WHERE id = ?")
        .bind(status)
        .bind(finished)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn job_append_log(db: &Db, id: i64, line: &str) -> Result<()> {
    sqlx::query("UPDATE jobs SET log = log || ? WHERE id = ?").bind(format!("{line}\n")).bind(id).execute(db).await?;
    Ok(())
}

/// Jobs still marked running from before a restart are failed.
pub async fn fail_stale_jobs(db: &Db) -> Result<()> {
    sqlx::query("UPDATE jobs SET status = 'failed', finished = ?, log = log || 'daemon restarted while the job was running\n' WHERE status IN ('queued','running')")
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

// ---- certificates ----

#[derive(Debug, Clone, FromRow)]
pub struct Certificate {
    pub domain: String,
    pub not_after: Option<String>,
    pub last_error: String,
    pub updated: String,
}

pub async fn certificates(db: &Db) -> Result<Vec<Certificate>> {
    Ok(sqlx::query_as("SELECT * FROM certificates ORDER BY domain").fetch_all(db).await?)
}

pub async fn put_certificate(db: &Db, domain: &str, not_after: Option<&str>, last_error: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO certificates (domain, not_after, last_error, updated) VALUES (?, ?, ?, ?)
         ON CONFLICT (domain) DO UPDATE SET not_after = COALESCE(excluded.not_after, certificates.not_after), last_error = excluded.last_error, updated = excluded.updated",
    )
    .bind(domain)
    .bind(not_after)
    .bind(last_error)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

// ---- audit & kv ----

#[derive(Debug, Clone, FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub at: String,
    pub username: String,
    pub action: String,
    pub detail: String,
}

pub async fn audit(db: &Db, username: &str, action: &str, detail: &str) -> Result<()> {
    sqlx::query("INSERT INTO audit (at, username, action, detail) VALUES (?, ?, ?, ?)")
        .bind(now())
        .bind(username)
        .bind(action)
        .bind(detail)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn audit_entries(db: &Db, limit: i64) -> Result<Vec<AuditEntry>> {
    Ok(sqlx::query_as("SELECT * FROM audit ORDER BY id DESC LIMIT ?").bind(limit).fetch_all(db).await?)
}

