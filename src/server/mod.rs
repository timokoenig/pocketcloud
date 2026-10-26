pub mod acme;
pub mod alerts;
pub mod backup;
pub mod caddy;
pub mod compose;
pub mod config;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod docker;
pub mod events;
pub mod jobs;
pub mod notify;
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
        ServerCommand::Renew => {
            // issued by the daemon (it runs the challenge nameserver); this only asks and waits
            let db = db::open(&config.db_path()).await?;
            let requested_at = db::now();
            let before: Vec<Option<std::time::SystemTime>> = config.domains.iter().map(|d| std::fs::metadata(config.certs_dir().join(d).join("fullchain.pem")).and_then(|m| m.modified()).ok()).collect();
            db::kv_set(&db, "acme.renew_requested", "1").await?;
            println!("renewal requested; the daemon issues within a minute");
            for _ in 0..90 {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut done = true;
                for (d, old) in config.domains.iter().zip(&before) {
                    let now = std::fs::metadata(config.certs_dir().join(d).join("fullchain.pem")).and_then(|m| m.modified()).ok();
                    if now.is_none() || now == *old {
                        done = false;
                    }
                }
                let errors: Vec<db::Certificate> = db::certificates(&db).await?.into_iter().filter(|c| !c.last_error.is_empty() && c.updated > requested_at).collect();
                if !errors.is_empty() {
                    for c in errors {
                        println!("{}: {}", c.domain, c.last_error);
                    }
                    std::process::exit(1);
                }
                if done {
                    for d in &config.domains {
                        let c = db::certificates(&db).await?.into_iter().find(|c| &c.domain == d);
                        println!("{d}: valid until {}", c.and_then(|c| c.not_after).unwrap_or_default());
                    }
                    return Ok(());
                }
            }
            anyhow::bail!("no new certificate after 7 minutes; see journalctl -u pocketcloud")
        }
        ServerCommand::NotifyTest => {
            let state = build_state(config).await?;
            alerts::send_test(&state).await?;
            println!("test notification sent");
            Ok(())
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
    let acme_txt = dns::AcmeTxt::new(db.clone());
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
    // every process that may reconcile needs the public addresses, not only the daemon
    let public_ips = if config.dev { vec!["127.0.0.1".into()] } else { system::local_public_ips().await.unwrap_or_default() };
    Ok(Arc::new(State {
        db,
        key,
        docker,
        acme_txt,
        internal_names: Default::default(),
        public_ips: RwLock::new(public_ips),
        reconcile_lock: Mutex::new(()),
        host: RwLock::new(Default::default()),
        started: chrono::Utc::now(),
        pending_configs: Mutex::new(HashMap::new()),
        waf_available,
        sample: RwLock::new(Default::default()),
        docker_ok: std::sync::atomic::AtomicBool::new(true),
        alert_pending: Mutex::new(HashMap::new()),
        notify_queue: Mutex::new(Vec::new()),
        point_events: Mutex::new(std::collections::HashSet::new()),
        tick_ok: std::sync::atomic::AtomicBool::new(true),
        journal_seen: std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp()),
        probe_failures: Mutex::new(HashMap::new()),
        notified: Mutex::new(HashMap::new()),
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
    // notification settings: the config file seeds the database once; from then on the Alerts page owns them
    if db::kv_get(&state.db, "notify.settings").await?.is_none() && (state.config.notify.any() || !state.config.notify.heartbeat_url.is_empty()) {
        notify::save_settings(&state, &state.config.notify).await?;
        tracing::info!("notification settings taken from the config file into the database");
    }
    if db::kv_get(&state.db, "backup.settings").await?.is_none() {
        if let Some(b) = &state.config.backup {
            backup::save_settings(&state, Some(b)).await?;
            tracing::info!("backup settings taken from the config file into the database");
        }
    }
    if let Some(e) = &notify::settings(&state).await.email {
        let bad = notify::bad_addresses(e);
        if !bad.is_empty() {
            let _ = db::kv_set(&state.db, "notify.last_error", &format!("email addresses do not parse: {}", bad.join(", "))).await;
        }
    }
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
        let _ = db::kv_set(&state.db, "reconcile.last_error", &format!("{e:#}")).await;
    }

    // the web interface
    let web_state = state.clone();
    let listen = state.config.listen.clone();
    tokio::spawn(async move {
        if let Err(e) = web::serve(web_state, &listen).await {
            tracing::error!("web: {e:#}");
        }
    });

    // the challenge nameserver on the public addresses, then certificates
    let st = state.clone();
    tokio::spawn(async move {
        if st.config.dev {
            return;
        }
        let ips: Vec<std::net::IpAddr> = loop {
            let ips: Vec<std::net::IpAddr> = st.public_ips.read().await.iter().filter_map(|i| i.parse().ok()).collect();
            if !ips.is_empty() {
                break ips;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        };
        let zone = dns::PublicZone { domains: st.config.domains.clone(), ips: ips.clone(), txt: st.acme_txt.clone() };
        let binds: Vec<std::net::SocketAddr> = ips.iter().map(|ip| std::net::SocketAddr::new(*ip, 53)).collect();
        loop {
            if let Err(e) = dns::serve_public(zone.clone(), binds.clone()).await {
                tracing::error!("challenge nameserver: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    // certificates, then the apps
    let st = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut n = 0u64;
        loop {
            // `pocketcloud server renew` and the interface set this flag; issuing happens here, in the daemon,
            // next to the nameserver that serves the challenge
            let requested = db::kv_get(&st.db, "acme.renew_requested").await.ok().flatten().as_deref() == Some("1");
            if requested {
                let _ = db::kv_set(&st.db, "acme.renew_requested", "").await;
                for d in &st.config.domains {
                    let _ = std::fs::remove_file(st.config.certs_dir().join(d).join("fullchain.pem"));
                }
            }
            if requested || n % 360 == 0 {
                match reconcile::ensure_certificates(&st).await {
                    Ok(true) => {
                        if let Err(e) = reconcile::apply(&st).await {
                            tracing::error!("reconcile after certificates: {e:#}");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => tracing::error!("certificates: {e:#}"),
                }
            }
            n += 1;
            tokio::time::sleep(Duration::from_secs(60)).await;
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

    // collectors: journal facts, auditd, falco, docker events
    if !state.config.dev {
        tokio::spawn(events::journal_tailer(state.clone()));
        tokio::spawn(events::file_tailer(state.clone(), "/var/log/audit/audit.log", "audit", events::audit_fact));
        tokio::spawn(events::file_tailer(state.clone(), "/var/log/infra/falco.jsonl", "falco", events::falco_fact));
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = events::docker_events(st).await {
                tracing::warn!("docker events: {e:#}");
            }
        });
    }

    // alerts: evaluate every minute (every 5 s in dev mode), notify in batches, heartbeat every 5 minutes
    let st = state.clone();
    tokio::spawn(async move {
        let period = if st.config.dev { 5 } else { 60 };
        let mut n = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(period)).await;
            match alerts::tick(&st).await {
                Ok(()) => st.tick_ok.store(true, std::sync::atomic::Ordering::Relaxed),
                Err(e) => {
                    st.tick_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!("alerts: {e:#}");
                }
            }
            n += 1;
            if n % (60 / period) == 0 {
                alerts::flush_notifications(&st).await;
                notify::stream_events(&st).await;
            }
            if n % (300 / period) == 0 {
                notify::heartbeat(&st).await;
            }
            // the configuration is re-applied every ten minutes: idempotent, and it catches drift
            // (a flushed ruleset, a Caddy that lost its config, a removed peer)
            if !st.config.dev && n % (600 / period) == 0 {
                let err = match reconcile::apply(&st).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:#}"),
                };
                let _ = db::kv_set(&st.db, "reconcile.last_error", &err).await;
            }
        }
    });

    // host status, hourly the slow parts
    let st = state.clone();
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            if !st.config.dev {
                let sample = system::sample().await;
                let _ = db::add_metrics(&st.db, &sample.metrics()).await;
                *st.sample.write().await = sample;
                st.docker_ok.store(docker::ping(&st).await, std::sync::atomic::Ordering::Relaxed);
                system::ensure_falco(system::falco_wanted(&st).await).await;
                if tick.is_multiple_of(60) {
                    let now = chrono::Utc::now();
                    let _ = db::purge_monitoring(
                        &st.db,
                        &(now - chrono::Duration::days(14)).to_rfc3339(),
                        &(now - chrono::Duration::hours(48)).to_rfc3339(),
                        &(now - chrono::Duration::days(90)).to_rfc3339(),
                    )
                    .await;
                }
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
