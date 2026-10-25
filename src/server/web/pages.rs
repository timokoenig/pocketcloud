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
    })
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
        host,
        certs,
        public_ips: state.public_ips.read().await.clone(),
        domains: state.config.domains.clone(),
        interface_host: state.config.interface_host.clone(),
        vpn_port: state.config.vpn.port,
        daemon_started: views::ago(&state.started.to_rfc3339()),
        waf_available: state.waf_available,
        waf_events: if state.config.dev { vec![] } else { system::waf_events(50).await },
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
