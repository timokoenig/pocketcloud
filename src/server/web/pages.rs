use axum::extract::{Path, Query, State};
use axum::Form;
use serde::Deserialize;

use super::auth::{Flash, User};
use super::{back, html, views, R};
use crate::server::state::Shared;
use crate::server::{db, docker, jobs, reconcile, system};
use crate::wireguard;

pub async fn dashboard(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    let apps = db::apps(&state.db).await?;
    let routes = db::routes(&state.db).await?;
    let rows = apps
        .iter()
        .map(|a| views::AppRow {
            id: a.id,
            name: a.name.clone(),
            status: a.status.clone(),
            status_detail: a.status_detail.clone(),
            hosts: routes.iter().filter(|r| r.app_id == a.id).map(|r| r.host.clone()).collect::<Vec<_>>().join(", "),
            updated: views::ago(&a.updated),
        })
        .collect();
    let jobs = db::recent_jobs(&state.db, 8)
        .await?
        .into_iter()
        .map(|j| views::JobRow {
            id: j.id,
            kind: j.kind,
            app_name: j.app_id.and_then(|id| apps.iter().find(|a| a.id == id)).map(|a| a.name.clone()).unwrap_or_default(),
            status: j.status,
            created: views::ago(&j.created),
        })
        .collect();
    let cert_problem = db::certificates(&state.db).await?.into_iter().find(|c| !c.last_error.is_empty()).map(|c| format!("{}: {}", c.domain, c.last_error));
    html(views::Dashboard {
        base: views::Base::new("Apps", &user.username, &state.config.name, &f),
        apps: rows,
        jobs,
        host: state.host.read().await.clone(),
        docker_ok: docker::ping(&state).await,
        cert_problem,
        backup_warning: backup_warning(&state).await,
        open_alerts: {
            let a = db::open_alerts(&state.db).await?;
            (a.iter().filter(|x| x.severity == "critical").count(), a.iter().filter(|x| x.severity == "warning").count())
        },
        day_events: db::event_kinds_since(&state.db, &(chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339())
            .await?
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", "),
    })
}

pub async fn alerts(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    use crate::server::alerts;
    let view = |a: &db::Alert| views::AlertView {
        severity: a.severity.clone(),
        summary: a.summary.clone(),
        opened: views::ago(&a.opened),
        resolved: a.resolved.as_deref().map(views::ago).unwrap_or_default(),
    };
    let open: Vec<views::AlertView> = db::open_alerts(&state.db).await?.iter().map(view).collect();
    let since = (chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339();
    let resolved: Vec<views::AlertView> = db::resolved_alerts(&state.db, &since).await?.iter().map(view).collect();
    let kv = |k: &str| {
        let k = k.to_string();
        let db = state.db.clone();
        async move { db::kv_get(&db, &k).await.ok().flatten().unwrap_or_default() }
    };
    let n = crate::server::notify::settings(&state).await;
    let mut channels = Vec::new();
    if let Some(e) = &n.email {
        channels.push(format!("e-mail to {}", e.to.join(", ")));
    }
    if n.webhook.is_some() {
        channels.push("webhook".to_string());
    }
    let hb_at = kv("notify.heartbeat_at").await;
    let heartbeat = if n.heartbeat_url.is_empty() {
        String::new()
    } else if hb_at.is_empty() {
        "not sent yet".into()
    } else {
        format!("{} {}", if kv("notify.heartbeat_ok").await == "1" { "ok" } else { "FAILED" }, views::ago(&hb_at))
    };
    let day = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let mut metrics = Vec::new();
    for name in ["cpu.busy_pct", "mem.available_pct", "disk.used_pct", "disk.inodes_pct", "load.1", "pressure.mem_full_avg10", "pressure.io_full_avg10", "mem.swap_used_pct"] {
        let series = db::metric_series(&state.db, name, &day).await?;
        if series.is_empty() {
            continue;
        }
        let values: Vec<f64> = series.iter().map(|(_, v)| *v).collect();
        let min = values.iter().cloned().fold(f64::MAX, f64::min);
        let max = values.iter().cloned().fold(f64::MIN, f64::max);
        let avg = values.iter().sum::<f64>() / values.len() as f64;
        metrics.push((name.to_string(), format!("min {min:.1} · avg {avg:.1} · max {max:.1} · now {:.1}", values.last().copied().unwrap_or(0.0))));
    }
    let last = kv("notify.last_at").await;
    html(views::AlertsPage {
        base: views::Base::new("Alerts", &user.username, &state.config.name, &f),
        open,
        resolved,
        t: alerts::thresholds(&state).await,
        notify_configured: n.any(),
        channels: channels.join(", "),
        notify: views::NotifyForm {
            to: n.email.as_ref().map(|e| e.to.join(", ")).unwrap_or_default(),
            from: n.email.as_ref().map(|e| e.from.clone()).unwrap_or_default(),
            smtp_host: n.email.as_ref().map(|e| e.smtp_host.clone()).unwrap_or_default(),
            smtp_port: n.email.as_ref().map(|e| e.smtp_port).unwrap_or(587),
            smtp_tls: n.email.as_ref().map(|e| e.smtp_tls.clone()).unwrap_or_else(|| "starttls".into()),
            smtp_user: n.email.as_ref().map(|e| e.smtp_user.clone()).unwrap_or_default(),
            has_password: n.email.as_ref().map(|e| !e.smtp_password.is_empty()).unwrap_or(false),
            webhook_url: n.webhook.as_ref().map(|w| w.url.clone()).unwrap_or_default(),
            has_webhook_token: n.webhook.as_ref().map(|w| !w.token.is_empty()).unwrap_or(false),
            heartbeat_url: n.heartbeat_url.clone(),
        },
        notify_last: if last.is_empty() { String::new() } else { views::ago(&last) },
        notify_error: kv("notify.last_error").await,
        heartbeat,
        metrics,
    })
}

pub async fn set_thresholds(State(state): State<Shared>, user: User, Form(t): Form<crate::server::alerts::Thresholds>) -> R {
    if t.disk_warn > t.disk_crit || t.mem_crit > t.mem_warn {
        return Ok(back("/alerts", None, Some("warning thresholds must come before critical ones")));
    }
    crate::server::alerts::set_thresholds(&state, &t).await?;
    db::audit(&state.db, &user.username, "alerts.thresholds", &serde_json::to_string(&t).unwrap_or_default()).await?;
    Ok(back("/alerts", Some("thresholds saved"), None))
}

#[derive(Deserialize)]
pub struct NotifySettingsForm {
    #[serde(default)]
    to: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    smtp_host: String,
    #[serde(default)]
    smtp_port: Option<u16>,
    #[serde(default)]
    smtp_tls: String,
    #[serde(default)]
    smtp_user: String,
    /// empty keeps the stored password
    #[serde(default)]
    smtp_password: String,
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    webhook_token: String,
    #[serde(default)]
    heartbeat_url: String,
}

/// Save where alerts go. E-mail is on when a host and a recipient are given, the webhook when it has a URL.
pub async fn save_notify(State(state): State<Shared>, user: User, Form(f): Form<NotifySettingsForm>) -> R {
    use crate::server::config::{EmailConfig, NotifyConfig, WebhookConfig};
    let current = crate::server::notify::settings(&state).await;
    let to: Vec<String> = f.to.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let email = if f.smtp_host.trim().is_empty() && to.is_empty() {
        None
    } else {
        if f.smtp_host.trim().is_empty() || to.is_empty() || f.from.trim().is_empty() {
            return Ok(back("/alerts", None, Some("e-mail needs recipients, a from address and an SMTP host")));
        }
        if !matches!(f.smtp_tls.as_str(), "starttls" | "implicit" | "none") {
            return Ok(back("/alerts", None, Some("TLS must be starttls, implicit or none")));
        }
        let password = if f.smtp_password.is_empty() { current.email.as_ref().map(|e| e.smtp_password.clone()).unwrap_or_default() } else { f.smtp_password.clone() };
        let e = EmailConfig { to, from: f.from.trim().to_string(), smtp_host: f.smtp_host.trim().to_string(), smtp_port: f.smtp_port.unwrap_or(587), smtp_tls: f.smtp_tls.clone(), smtp_user: f.smtp_user.trim().to_string(), smtp_password: password };
        let bad = crate::server::notify::bad_addresses(&e);
        if !bad.is_empty() {
            return Ok(back("/alerts", None, Some(&format!("these addresses do not parse: {}", bad.join(", ")))));
        }
        Some(e)
    };
    let webhook = if f.webhook_url.trim().is_empty() {
        None
    } else {
        if !f.webhook_url.trim().starts_with("https://") && !f.webhook_url.trim().starts_with("http://") {
            return Ok(back("/alerts", None, Some("the webhook URL must start with http:// or https://")));
        }
        let token = if f.webhook_token.is_empty() { current.webhook.as_ref().map(|w| w.token.clone()).unwrap_or_default() } else { f.webhook_token.clone() };
        Some(WebhookConfig { url: f.webhook_url.trim().to_string(), token })
    };
    let heartbeat_url = f.heartbeat_url.trim().to_string();
    if !heartbeat_url.is_empty() && !heartbeat_url.starts_with("https://") && !heartbeat_url.starts_with("http://") {
        return Ok(back("/alerts", None, Some("the heartbeat URL must start with http:// or https://")));
    }
    let cfg = NotifyConfig { email, webhook, heartbeat_url };
    crate::server::notify::save_settings(&state, &cfg).await?;
    let _ = db::kv_set(&state.db, "notify.last_error", "").await;
    let _ = db::kv_set(&state.db, "notify.failures", "0").await;
    db::audit(&state.db, &user.username, "alerts.notify", &format!("email={} webhook={} heartbeat={}", cfg.email.is_some(), cfg.webhook.is_some(), !cfg.heartbeat_url.is_empty())).await?;
    Ok(back("/alerts", Some("notification settings saved; send a test to prove them"), None))
}

pub async fn test_notification(State(state): State<Shared>, user: User) -> R {
    db::audit(&state.db, &user.username, "alerts.test", "").await?;
    match crate::server::alerts::send_test(&state).await {
        Ok(()) => Ok(back("/alerts", Some("test notification sent"), None)),
        Err(e) => Ok(back("/alerts", None, Some(&format!("{e:#}")))),
    }
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    q: String,
}

pub async fn events(State(state): State<Shared>, user: User, Query(f): Query<Flash>, Query(e): Query<EventsQuery>) -> R {
    let events = db::events(&state.db, e.kind.trim(), e.q.trim(), 300)
        .await?
        .into_iter()
        .map(|x| views::EventView { ts: views::short_time(&x.ts), kind: x.kind, source: x.source, summary: x.summary })
        .collect();
    html(views::EventsPage {
        base: views::Base::new("Events", &user.username, &state.config.name, &f),
        events,
        kinds: db::event_kinds(&state.db).await?,
        kind: e.kind.trim().to_string(),
        q: e.q.trim().to_string(),
    })
}

async fn backup_view(state: &Shared) -> views::BackupView {
    let s = crate::server::backup::status(state).await;
    views::BackupView {
        enabled: s.enabled,
        repo: s.repo,
        time: format!("{:02}:30", s.hour),
        last_ok: if s.last_ok.is_empty() { "never".into() } else { views::ago(&s.last_ok) },
        last_error: s.last_error,
        last_snapshot: s.last_snapshot,
        snapshots: s.snapshots,
        size: s.bytes.parse::<u64>().map(|b| format!("{:.1} GB", b as f64 / 1e9)).unwrap_or_default(),
        last_check: if s.last_check.is_empty() { "not yet".into() } else { views::ago(&s.last_check) },
    }
}

/// Dashboard notice: a failed last run, or no success for two days.
async fn backup_warning(state: &Shared) -> Option<String> {
    if crate::server::backup::settings(state).await.is_none() {
        return None;
    }
    let s = crate::server::backup::status(state).await;
    if !s.last_error.is_empty() {
        return Some(format!("The last backup failed: {}", s.last_error));
    }
    if let Some(t) = db::parse_time(&s.last_ok) {
        if chrono::Utc::now() - t > chrono::Duration::hours(48) {
            return Some(format!("The last successful backup was {}.", views::ago(&s.last_ok)));
        }
    }
    None
}

pub async fn job(State(state): State<Shared>, user: User, Path(id): Path<i64>, Query(f): Query<Flash>) -> R {
    let j = db::job(&state.db, id).await?.ok_or_else(|| anyhow::anyhow!("job {id} not found"))?;
    let app_name = match j.app_id {
        Some(a) => db::app(&state.db, a).await?.map(|a| a.name).unwrap_or_default(),
        None => String::new(),
    };
    let running = j.status == "queued" || j.status == "running";
    html(views::JobPage {
        base: views::Base::new(&format!("{} #{}", j.kind, j.id), &user.username, &state.config.name, &f),
        id: j.id,
        kind: j.kind,
        status: j.status,
        app_id: j.app_id,
        app_name,
        created: views::short_time(&j.created),
        finished: j.finished.as_deref().map(views::short_time).unwrap_or_default(),
        log: j.log,
        running,
    })
}

// ---- vpn ----

async fn peer_views(state: &Shared) -> anyhow::Result<Vec<views::PeerView>> {
    let live = if state.config.dev { vec![] } else { system::wireguard_peers().await };
    Ok(db::vpn_peers(&state.db)
        .await?
        .into_iter()
        .map(|p| {
            let l = live.iter().find(|l| l.public_key == p.public_key);
            let last = l.and_then(|l| l.last_handshake).map(|t| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0).map(|d| views::ago(&d.to_rfc3339())).unwrap_or_default()
            });
            views::PeerView {
                id: p.id,
                name: p.name,
                ip: p.ip,
                scope: p.scope,
                created: views::short_time(&p.created),
                last_handshake: last.unwrap_or_else(|| "never".into()),
                endpoint: l.map(|l| l.endpoint.clone()).unwrap_or_default(),
            }
        })
        .collect())
}

pub async fn vpn(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    html(views::VpnPage {
        base: views::Base::new("VPN devices", &user.username, &state.config.name, &f),
        peers: peer_views(&state).await?,
        new_peer: None,
        apps_cidr: crate::firewall::APPS_CIDR.into(),
    })
}

#[derive(Deserialize)]
pub struct PeerForm {
    name: String,
    scope: String,
}

pub async fn vpn_add(State(state): State<Shared>, user: User, Form(f): Form<PeerForm>) -> R {
    let name = f.name.trim().to_string();
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Ok(back("/vpn", None, Some("device names: letters, digits, dashes, underscores")));
    }
    let scope = match wireguard::Scope::parse(&f.scope) {
        Ok(s) => s,
        Err(e) => return Ok(back("/vpn", None, Some(&e.to_string()))),
    };
    let used: Vec<std::net::Ipv4Addr> = db::vpn_peers(&state.db).await?.iter().filter_map(|p| p.ip.parse().ok()).collect();
    let ip = wireguard::next_ip(scope, &used)?;
    let keys = wireguard::generate_keypair();
    let psk = wireguard::generate_psk();
    if let Err(e) = db::add_vpn_peer(&state.db, &name, &keys.public, &state.key.seal(psk.as_bytes()), &ip.to_string(), scope.as_str()).await {
        return Ok(back("/vpn", None, Some(&format!("not added: {e}"))));
    }
    db::audit(&state.db, &user.username, "vpn.add", &format!("{name} {} {ip}", scope.as_str())).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} added VPN device {name} ({}, {ip})", user.username, scope.as_str()), &serde_json::json!({"user": user.username, "action": "vpn.add"})).await;
    reconcile::apply(&state).await?;
    let endpoint = state.public_ips.read().await.iter().find(|i| !i.contains(':')).cloned().unwrap_or_default();
    let hub_pub = wireguard::public_key_of(&state.config.vpn.hub_private_key)?;
    let config = wireguard::client_config(&wireguard::ClientConfig {
        private_key: &keys.private,
        ip,
        hub_public_key: &hub_pub,
        psk: &psk,
        endpoint_host: &endpoint,
        endpoint_port: state.config.vpn.port,
        scope,
        apps_cidr: crate::firewall::APPS_CIDR,
    });
    let qr_svg = qrcode::QrCode::new(config.as_bytes())
        .map(|c| c.render::<qrcode::render::svg::Color>().min_dimensions(260, 260).quiet_zone(true).build())
        .unwrap_or_default();
    // the file name becomes the tunnel name on import
    let file_name = format!("pocketcloud-{}-{}.conf", state.config.name, name);
    let download_token = crate::crypto::random_token(16);
    {
        let mut pending = state.pending_configs.lock().await;
        pending.retain(|_, (_, _, t)| t.elapsed() < std::time::Duration::from_secs(600));
        pending.insert(download_token.clone(), (file_name.clone(), config.clone(), std::time::Instant::now()));
    }
    html(views::VpnPage {
        base: views::Base::new("VPN devices", &user.username, &state.config.name, &Flash { msg: None, error: None }),
        peers: peer_views(&state).await?,
        new_peer: Some(views::NewPeer { name, config, qr_svg, file_name, download_token }),
        apps_cidr: crate::firewall::APPS_CIDR.into(),
    })
}

/// One-time download of a config created moments ago.
pub async fn vpn_download(State(state): State<Shared>, _user: User, Path(token): Path<String>) -> R {
    let entry = state.pending_configs.lock().await.remove(&token);
    let Some((file_name, config, _)) = entry else {
        return Ok(back("/vpn", None, Some("that download is no longer available; create the device again")));
    };
    let mut resp = axum::response::Response::new(axum::body::Body::from(config));
    resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/octet-stream"));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{file_name}\""))?,
    );
    Ok(resp)
}

pub async fn vpn_delete(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    let peers = db::vpn_peers(&state.db).await?;
    if peers.len() <= 1 {
        return Ok(back("/vpn", None, Some("the last device cannot be removed, you would lock yourself out")));
    }
    let name = peers.iter().find(|p| p.id == id).map(|p| p.name.clone()).unwrap_or_default();
    db::delete_vpn_peer(&state.db, id).await?;
    db::audit(&state.db, &user.username, "vpn.delete", &name).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} revoked VPN device {name}", user.username), &serde_json::json!({"user": user.username, "action": "vpn.delete"})).await;
    reconcile::apply(&state).await?;
    Ok(back("/vpn", Some("device removed, its tunnel is closed"), None))
}

// ---- registries ----

pub async fn registries(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    let registries = db::registries(&state.db)
        .await?
        .into_iter()
        .map(|r| views::RegistryView { id: r.id, host: r.host, username: r.username, updated: views::ago(&r.updated) })
        .collect();
    html(views::RegistriesPage { base: views::Base::new("Registries", &user.username, &state.config.name, &f), registries })
}

#[derive(Deserialize)]
pub struct RegistryForm {
    host: String,
    username: String,
    password: String,
}

pub async fn registry_put(State(state): State<Shared>, user: User, Form(f): Form<RegistryForm>) -> R {
    let host = f.host.trim().trim_start_matches("https://").trim_end_matches('/').to_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(' ') {
        return Ok(back("/registries", None, Some("registry host like ghcr.io or registry.example.com")));
    }
    if f.username.trim().is_empty() || f.password.is_empty() {
        return Ok(back("/registries", None, Some("username and token are required")));
    }
    db::put_registry(&state.db, &host, f.username.trim(), &state.key.seal(f.password.trim().as_bytes())).await?;
    db::audit(&state.db, &user.username, "registry.put", &host).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} set registry credentials for {host}", user.username), &serde_json::json!({"user": user.username, "action": "registry.put"})).await;
    Ok(back("/registries", Some("registry saved"), None))
}

pub async fn registry_delete(State(state): State<Shared>, user: User, Path(id): Path<i64>) -> R {
    db::delete_registry(&state.db, id).await?;
    db::audit(&state.db, &user.username, "registry.delete", &id.to_string()).await?;
    Ok(back("/registries", Some("registry removed"), None))
}

// ---- server ----

pub async fn server(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    let host = state.host.read().await.clone();
    let certs = db::certificates(&state.db)
        .await?
        .into_iter()
        .map(|c| {
            let days = c.not_after.as_deref().and_then(db::parse_time).map(|t| (t - chrono::Utc::now()).num_days()).unwrap_or(0);
            views::CertView {
                domain: c.domain,
                not_after: c.not_after.as_deref().map(views::short_time).unwrap_or_else(|| "none".into()),
                days_left: days,
                last_error: c.last_error,
            }
        })
        .collect();
    let mem_used_pct = if host.mem_total_mb > 0 { (host.mem_total_mb - host.mem_available_mb) * 100 / host.mem_total_mb } else { 0 };
    let disk_used_pct = if host.disk_total_gb > 0.0 { (host.disk_used_gb / host.disk_total_gb * 100.0) as u64 } else { 0 };
    let uptime = if host.uptime_hours >= 48.0 { format!("{:.0} days", host.uptime_hours / 24.0) } else { format!("{:.1} h", host.uptime_hours) };
    html(views::ServerPage {
        base: views::Base::new("Server", &user.username, &state.config.name, &f),
        pending_checked: if host.pending_checked.is_empty() { "not yet".into() } else { views::ago(&host.pending_checked) },
        aide_checked: if host.aide_checked.is_empty() { "not yet".into() } else { views::ago(&host.aide_checked) },
        certs,
        public_ips: state.public_ips.read().await.clone(),
        domains: state.config.domains.clone(),
        interface_host: state.config.interface_host.clone(),
        vpn_port: state.config.vpn.port,
        daemon_started: views::ago(&state.started.to_rfc3339()),
        waf_available: state.waf_available,
        waf_events: if state.config.dev { vec![] } else { system::waf_events(50).await },
        jails: if state.config.dev { vec![] } else { system::fail2ban_status().await },
        backup: backup_view(&state).await,
        snapshots: crate::server::backup::cached_snapshots(&state).await,
        backup_form: {
            let c = crate::server::backup::settings(&state).await;
            views::BackupForm {
                s3_endpoint: c.as_ref().map(|c| c.s3_endpoint.clone()).unwrap_or_else(|| "https://fsn1.your-objectstorage.com".into()),
                bucket: c.as_ref().map(|c| c.bucket.clone()).unwrap_or_default(),
                access_key: c.as_ref().map(|c| c.access_key.clone()).unwrap_or_default(),
                has_secret: c.is_some(),
                hour: c.as_ref().map(|c| c.hour).unwrap_or(3),
            }
        },
        falco_on: crate::server::system::falco_wanted(&state).await,
        newer_release: host.latest_version.clone(),
        host,
        uptime,
        mem_used_pct,
        disk_used_pct,
    })
}

pub async fn check_updates(State(state): State<Shared>, user: User) -> R {
    db::audit(&state.db, &user.username, "server.check_updates", "").await?;
    let job = jobs::spawn(&state, "check-updates", None, vec![], |s, log| async move {
        let p = system::pending_updates().await?;
        log.line(format!("{} packages can be upgraded", p.len())).await;
        for x in &p {
            log.line(format!("  {x}")).await;
        }
        let mut h = s.host.write().await;
        h.pending_updates = p;
        h.pending_checked = db::now();
        Ok(())
    })
    .await?;
    Ok(back(&format!("/jobs/{job}"), None, None))
}

pub async fn upgrade(State(state): State<Shared>, user: User) -> R {
    db::audit(&state.db, &user.username, "server.upgrade", "").await?;
    let job = jobs::spawn(&state, "apt-upgrade", None, vec![], |s, log| async move {
        let out = system::apt_upgrade().await?;
        for l in out.lines() {
            log.line(l).await;
        }
        let mut h = s.host.write().await;
        h.pending_updates = vec![];
        h.pending_checked = db::now();
        h.reboot_required = std::path::Path::new("/var/run/reboot-required").exists();
        log.line(if h.reboot_required { "a reboot is required" } else { "no reboot required" }).await;
        Ok(())
    })
    .await?;
    Ok(back(&format!("/jobs/{job}"), None, None))
}

#[derive(Deserialize)]
pub struct BackupSettingsForm {
    s3_endpoint: String,
    bucket: String,
    access_key: String,
    /// empty keeps the stored key
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    hour: Option<u8>,
}

/// Configure or change nightly backups from the server page; the restic password is derived from the master key.
pub async fn save_backup(State(state): State<Shared>, user: User, Form(f): Form<BackupSettingsForm>) -> R {
    use crate::server::config::BackupConfig;
    let current = crate::server::backup::settings(&state).await;
    let endpoint = f.s3_endpoint.trim().trim_end_matches('/').to_string();
    let bucket = f.bucket.trim().to_string();
    let access_key = f.access_key.trim().to_string();
    if endpoint.is_empty() || bucket.is_empty() || access_key.is_empty() {
        return Ok(back("/server", None, Some("endpoint, bucket and access key are needed")));
    }
    if !bucket.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return Ok(back("/server", None, Some("the bucket name looks wrong")));
    }
    let secret_key = if f.secret_key.is_empty() { current.as_ref().map(|c| c.secret_key.clone()).unwrap_or_default() } else { f.secret_key.clone() };
    if secret_key.is_empty() {
        return Ok(back("/server", None, Some("the secret key is needed the first time")));
    }
    let hour = f.hour.unwrap_or(3).min(23);
    let cfg = BackupConfig { s3_endpoint: endpoint, bucket, access_key, secret_key, hour };
    crate::server::backup::save_settings(&state, Some(&cfg)).await?;
    let _ = db::kv_set(&state.db, "backup.last_error", "").await;
    db::audit(&state.db, &user.username, "backup.settings", &format!("s3://{}", cfg.bucket)).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} configured backups to {}", user.username, crate::server::backup::repo_of(&cfg)), &serde_json::json!({"user": user.username, "action": "backup.settings"})).await;
    Ok(back("/server", Some("backup settings saved; Back up now proves them"), None))
}

pub async fn disable_backup(State(state): State<Shared>, user: User, Form(f): Form<ConfirmForm>) -> R {
    if f.confirm.trim() != "disable" {
        return Ok(back("/server", None, Some("type disable to confirm")));
    }
    crate::server::backup::save_settings(&state, None).await?;
    db::audit(&state.db, &user.username, "backup.disable", "").await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} switched backups off", user.username), &serde_json::json!({"user": user.username, "action": "backup.disable"})).await;
    Ok(back("/server", Some("backups switched off; snapshots stay in the bucket"), None))
}

#[derive(Deserialize)]
pub struct OnOff {
    value: String,
}

/// Falco runtime detection on or off; the daemon applies it to the service within a minute.
pub async fn set_falco(State(state): State<Shared>, user: User, Form(f): Form<OnOff>) -> R {
    let on = f.value == "on";
    db::kv_set(&state.db, "monitor.falco", if on { "1" } else { "0" }).await?;
    db::audit(&state.db, &user.username, "monitor.falco", &on.to_string()).await?;
    if !on {
        let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} switched Falco off", user.username), &serde_json::json!({"user": user.username, "action": "monitor.falco"})).await;
    }
    Ok(back("/server", Some(if on { "Falco switched on" } else { "Falco switched off" }), None))
}

pub async fn backup_now(State(state): State<Shared>, user: User) -> R {
    if crate::server::backup::settings(&state).await.is_none() {
        return Ok(back("/server", None, Some("backups are not configured")));
    }
    db::audit(&state.db, &user.username, "server.backup", "").await?;
    match crate::server::backup::spawn_job(&state).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back("/server", None, Some(&e.to_string()))),
    }
}

pub async fn refresh_snapshots(State(state): State<Shared>, user: User) -> R {
    if crate::server::backup::settings(&state).await.is_none() {
        return Ok(back("/server", None, Some("backups are not configured")));
    }
    db::audit(&state.db, &user.username, "server.snapshots", "").await?;
    match crate::server::backup::refresh_snapshots(&state).await {
        Ok(list) => Ok(back("/server", Some(&format!("{} snapshot(s) in the repository", list.len())), None)),
        Err(e) => Ok(back("/server", None, Some(&format!("{e:#}")))),
    }
}

#[derive(Deserialize)]
pub struct RestoreForm {
    snapshot: String,
    confirm: String,
}

/// Import the apps of a snapshot (an earlier installation) and restore their data.
pub async fn restore_import(State(state): State<Shared>, user: User, Form(f): Form<RestoreForm>) -> R {
    if crate::server::backup::settings(&state).await.is_none() {
        return Ok(back("/server", None, Some("backups are not configured")));
    }
    if f.confirm.trim() != "restore" {
        return Ok(back("/server", None, Some("type restore to confirm")));
    }
    db::audit(&state.db, &user.username, "server.restore", &f.snapshot).await?;
    let _ = db::add_event(&state.db, "admin_action", "pocketcloud", &format!("{} started a restore of all apps from snapshot {}", user.username, f.snapshot.trim()), &serde_json::json!({"user": user.username, "action": "server.restore"})).await;
    let redact = crate::server::backup::settings(&state).await.map(|b| vec![b.secret_key]).unwrap_or_default();
    let snap = f.snapshot.trim().to_string();
    match jobs::spawn(&state, "restore-all", None, redact, move |s, log| crate::server::backup::restore_import(s, snap, log)).await {
        Ok(job) => Ok(back(&format!("/jobs/{job}"), None, None)),
        Err(e) => Ok(back("/server", None, Some(&e.to_string()))),
    }
}

#[derive(Deserialize)]
pub struct UnbanForm {
    jail: String,
    ip: String,
}

pub async fn unban(State(state): State<Shared>, user: User, Form(f): Form<UnbanForm>) -> R {
    let ok_jail = matches!(f.jail.as_str(), "sshd" | "pocketcloud-waf");
    let ok_ip = f.ip.parse::<std::net::IpAddr>().is_ok();
    if !ok_jail || !ok_ip {
        return Ok(back("/server", None, Some("unknown jail or address")));
    }
    db::audit(&state.db, &user.username, "server.unban", &format!("{} {}", f.jail, f.ip)).await?;
    match system::run("fail2ban-client", &["set", &f.jail, "unbanip", &f.ip]).await {
        Ok(_) => Ok(back("/server", Some(&format!("{} unbanned", f.ip)), None)),
        Err(e) => Ok(back("/server", None, Some(&e.to_string()))),
    }
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    confirm: String,
}

pub async fn reboot(State(state): State<Shared>, user: User, Form(f): Form<ConfirmForm>) -> R {
    if f.confirm.trim() != "reboot" {
        return Ok(back("/server", None, Some("type reboot to confirm")));
    }
    db::audit(&state.db, &user.username, "server.reboot", "").await?;
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = system::reboot().await;
    });
    Ok(back("/server", Some("rebooting; apps come back on their own, the interface in about a minute"), None))
}

pub async fn renew_certificates(State(state): State<Shared>, user: User) -> R {
    db::audit(&state.db, &user.username, "server.renew_certificates", "").await?;
    let job = jobs::spawn(&state, "certificates", None, vec![], |s, log| async move {
        for d in &s.config.domains {
            let dir = s.config.certs_dir().join(d);
            let _ = std::fs::remove_file(dir.join("fullchain.pem"));
            log.line(format!("renewing {d}")).await;
        }
        let changed = reconcile::ensure_certificates(&s).await?;
        if changed {
            reconcile::apply(&s).await?;
        }
        log.line("done").await;
        Ok(())
    })
    .await?;
    Ok(back(&format!("/jobs/{job}"), None, None))
}

pub async fn audit(State(state): State<Shared>, user: User, Query(f): Query<Flash>) -> R {
    let entries = db::audit_entries(&state.db, 300)
        .await?
        .into_iter()
        .map(|e| views::AuditView { at: views::short_time(&e.at), username: e.username, action: e.action, detail: e.detail })
        .collect();
    html(views::AuditPage { base: views::Base::new("Audit log", &user.username, &state.config.name, &f), entries })
}
