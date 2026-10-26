pub mod acme;
pub mod backup;
pub mod caddy;
pub mod compose;
pub mod config;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod docker;
pub mod jobs;
pub mod reconcile;
pub mod state;
pub mod system;
pub mod web;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

use crate::cli::{ServerArgs, ServerCommand};
use crate::crypto::MasterKey;
use crate::hetzner::Hetzner;
use config::Config;
use state::{Shared, State};

pub async fn run(args: ServerArgs) -> Result<()> {
    let config = Config::load(&args.config)?;
    match args.command.unwrap_or(ServerCommand::Run) {
        ServerCommand::Run => daemon(config).await,
        ServerCommand::Firewall => {
            let state = build_state(config).await?;
            let apps = db::apps(&state.db).await?;
            let bridges: Vec<(String, String)> = apps.iter().map(|a| (crate::firewall::bridge_name(&a.name), a.egress.clone())).collect();
            let wan = system::wan_interface().await.unwrap_or_else(|_| "eth0".into());
            print!("{}", crate::firewall::render(&crate::firewall::FirewallSpec { wan: &wan, vpn_port: state.config.vpn.port, bridges: &bridges }));
            Ok(())
        }
        ServerCommand::Restore { app, snapshot } => {
            let state = build_state(config).await?;
            let a = db::app_by_name(&state.db, &app).await?.ok_or_else(|| anyhow::anyhow!("no app {app}"))?;
            let redact = deploy::secret_values(&state, a.id).await?;
            let app_id = a.id;
            let id = jobs::spawn(&state, "restore", Some(a.id), redact, move |s, log| backup::restore_app(s, app_id, snapshot, log)).await?;
            wait_for_job(&state, id).await
        }
        ServerCommand::Backup => {
            let state = build_state(config).await?;
            let id = backup::spawn_job(&state).await?;
            wait_for_job(&state, id).await
        }
        ServerCommand::Apply => {
            let state = build_state(config).await?;
            refresh_public_ips(&state).await?;
            reconcile::apply(&state).await?;
            println!("applied");
            Ok(())
        }
        ServerCommand::Passwd { username } => {
            let state = build_state(config).await?;
            let pw = dialoguer::Password::new().with_prompt(format!("new password for {username}")).with_confirmation("repeat", "passwords differ").interact()?;
            let hash = crate::crypto::hash_password(&pw)?;
            if db::set_password(&state.db, &username, &hash).await? {
                println!("password changed");
            } else {
                db::create_user(&state.db, &username, &hash).await?;
                println!("user created");
            }
            Ok(())
        }
    }
}

/// Wait for a job started from the shell; the log lines already print through tracing.
async fn wait_for_job(state: &Shared, id: i64) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let job = db::job(&state.db, id).await?.ok_or_else(|| anyhow::anyhow!("job vanished"))?;
        if job.status != "running" && job.status != "queued" {
            println!("job #{id}: {}", job.status);
            if job.status != "done" {
                std::process::exit(1);
            }
            return Ok(());
        }
    }
}

async fn build_state(config: Config) -> Result<Shared> {
    let waf_available = config.dev || system::caddy_has_waf().await;
    if !waf_available {
        tracing::warn!("caddy has no Coraza module; public routes run without the WAF until `pocketcloud upgrade` installs the bundled build");
    }
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::create_dir_all(config.apps_dir())?;
    std::fs::create_dir_all(config.certs_dir())?;
    std::fs::create_dir_all(config.run_dir())?;
    crate::install::set_mode(&config.data_dir, 0o700)?;
    crate::install::set_mode(&config.run_dir(), 0o700)?;
    let key_hex = std::fs::read_to_string(&config.master_key_file)
        .with_context(|| format!("read master key {}", config.master_key_file.display()))?;
    let key = MasterKey::from_hex(&key_hex)?;
    let db = db::open(&config.db_path()).await?;
    if db::user_count(&db).await? == 0 {
        if let Some(u) = &config.bootstrap_user {
            db::create_user(&db, &u.username, &u.password_hash).await?;
            tracing::info!("created interface user {}", u.username);
        }
    }
    if db::vpn_peers(&db).await?.is_empty() {
        if let Some(p) = &config.vpn.initial_peer {
            db::add_vpn_peer(&db, &p.name, &p.public_key, &key.seal(p.psk.as_bytes()), &p.ip, &p.scope).await?;
            tracing::info!("imported first VPN device {}", p.name);
        }
    }
    let docker = if config.dev { None } else { docker::connect().ok() };
    let dns_api = Hetzner::new(config.hetzner.dns_token());
    // every process that may reconcile needs the public addresses, not only the daemon
    let public_ips = if config.dev { vec!["127.0.0.1".into()] } else { system::local_public_ips().await.unwrap_or_default() };
    Ok(Arc::new(State {
        db,
        key,
        docker,
        dns_api,
        internal_names: Default::default(),
        public_ips: RwLock::new(public_ips),
        reconcile_lock: Mutex::new(()),
        host: RwLock::new(Default::default()),
        started: chrono::Utc::now(),
        pending_configs: Mutex::new(HashMap::new()),
        waf_available,
        config,
    }))
}

/// The server's public addresses, from its own interface; no API involved.
async fn refresh_public_ips(state: &Shared) -> Result<()> {
    if state.config.dev {
        *state.public_ips.write().await = vec!["127.0.0.1".into()];
        return Ok(());
    }
    *state.public_ips.write().await = system::local_public_ips().await?;
    Ok(())
}

async fn daemon(config: Config) -> Result<()> {
    let state = build_state(config).await?;
    db::fail_stale_jobs(&state.db).await?;
    tracing::info!("pocketcloud {} starting, interface at https://{}", env!("CARGO_PKG_VERSION"), state.config.interface_host);

    // public ips: the interface's own global addresses; retried until the network is up
    if let Err(e) = refresh_public_ips(&state).await {
        tracing::warn!("no public addresses yet: {e:#}");
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if refresh_public_ips(&st).await.is_ok() {
                    let _ = reconcile::apply(&st).await;
                    break;
                }
            }
        });
    }

    // the VPN resolver on the hub address
    if !state.config.dev {
        let st = state.clone();
        tokio::spawn(async move {
            let upstreams: Vec<std::net::SocketAddr> = st.config.vpn.dns_upstreams.iter().filter_map(|u| u.parse().ok()).collect();
            let bind: std::net::SocketAddr = format!("{}:53", crate::wireguard::HUB_IP).parse().unwrap();
            // wg0 must be up before we can bind to its address
            for _ in 0..30 {
                if dns::serve(bind, upstreams.clone(), st.internal_names.clone()).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    if let Err(e) = reconcile::apply(&state).await {
        tracing::error!("initial reconcile: {e:#}");
    }

    // the web interface
    let web_state = state.clone();
    let listen = state.config.listen.clone();
    tokio::spawn(async move {
        if let Err(e) = web::serve(web_state, &listen).await {
            tracing::error!("web: {e:#}");
        }
    });

    // dns records, certificates, then the apps
    let st = state.clone();
    tokio::spawn(async move {
        if let Err(e) = reconcile::ensure_dns_records(&st).await {
            tracing::error!("dns records: {e:#}");
        }
        loop {
            match reconcile::ensure_certificates(&st).await {
                Ok(true) => {
                    if let Err(e) = reconcile::apply(&st).await {
                        tracing::error!("reconcile after certificates: {e:#}");
                    }
                }
                Ok(false) => {}
                Err(e) => tracing::error!("certificates: {e:#}"),
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });

    let st = state.clone();
    tokio::spawn(async move {
        if !st.config.dev {
            // give docker a moment after boot
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = deploy::resume_all(st).await {
                tracing::error!("resume apps: {e:#}");
            }
        }
    });

    // host status, hourly the slow parts
    let st = state.clone();
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            if !st.config.dev {
                let mut s = system::quick_status().await;
                let prev = st.host.read().await.clone();
                s.pending_updates = prev.pending_updates;
                s.pending_checked = prev.pending_checked;
                s.aide_report = prev.aide_report;
                s.aide_checked = prev.aide_checked;
                s.audit_summary = prev.audit_summary;
                s.latest_version = prev.latest_version;
                if tick.is_multiple_of(1440) {
                    s.latest_version = system::newer_release().await;
                }
                if tick.is_multiple_of(60) {
                    match system::pending_updates().await {
                        Ok(p) => {
                            s.pending_updates = p;
                            s.pending_checked = db::now();
                        }
                        Err(e) => tracing::warn!("pending updates: {e}"),
                    }
                    let (report, checked) = system::aide_report();
                    s.aide_report = report;
                    s.aide_checked = checked;
                    s.audit_summary = system::audit_summary().await;
                }
                *st.host.write().await = s;
            }
            let _ = db::purge_sessions(&st.db).await;
            backup::tick(&st).await;
            tick += 1;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
