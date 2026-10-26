//! Make the host match the database: firewall, WireGuard peers, VPN names, Caddy routes.
use anyhow::{Context, Result};
use std::net::Ipv4Addr;

use super::state::{Shared, State};
use super::{caddy, compose, db, system};
use crate::firewall;
use crate::wireguard;

pub async fn apply(state: &Shared) -> Result<()> {
    let _guard = state.reconcile_lock.lock().await;
    let apps = db::apps(&state.db).await?;
    let routes = db::routes(&state.db).await?;

    // internal names for the VPN resolver
    let mut names = vec![state.config.interface_host.clone()];
    names.extend(routes.iter().filter(|r| r.expose == "internal").map(|r| r.host.clone()));
    state.internal_names.set(names).await;

    // caddy routes: upstream addresses are the static ips from the compose rendering
    let mut specs = Vec::new();
    for app in &apps {
        if app.desired != "running" {
            continue;
        }
        let env_dir = state.config.run_dir().join("env");
        let Ok(r) = compose::render(&app.compose, &app.name, app.net_index as u32, &env_dir.display().to_string()) else {
            continue;
        };
        for route in routes.iter().filter(|r| r.app_id == app.id) {
            if let Some((_, ip)) = r.services.iter().find(|(s, _)| s == &route.service) {
                specs.push(caddy::RouteSpec {
                    host: route.host.clone(),
                    upstream: format!("{ip}:{}", route.port),
                    public: route.expose == "public",
                    waf: route.waf != 0,
                    headers: route.headers != 0,
                });
            }
        }
    }
    let ips = state.public_ips.read().await.clone();
    if ips.is_empty() && !state.config.dev {
        // a config without public listeners would take every app offline; better to leave Caddy as it is
        anyhow::bail!("public addresses unknown, caddy configuration not touched");
    }
    let certs = caddy::cert_files(&state.config.certs_dir(), &state.config.domains);
    let cfg = caddy::render(&caddy::CaddySpec {
        public_ips: &ips,
        domains: &state.config.domains,
        routes: &specs,
        interface_host: &state.config.interface_host,
        interface_upstream: &state.config.listen,
        waf_available: state.waf_available,
        certificates: &certs,
    });

    if state.config.dev {
        tracing::debug!("dev mode: skipping nftables, wireguard and caddy");
        return Ok(());
    }

    // firewall
    let bridges: Vec<(String, String)> = apps.iter().filter(|a| a.desired == "running").map(|a| (firewall::bridge_name(&a.name), a.egress.clone())).collect();
    let wan = system::wan_interface().await?;
    let ruleset = firewall::render(&firewall::FirewallSpec { wan: &wan, vpn_port: state.config.vpn.port, bridges: &bridges });
    system::apply_nftables(&ruleset).await.context("apply nftables")?;

    // wireguard
    let conf = hub_config(state).await?;
    system::apply_wireguard(&conf).await.context("apply wireguard")?;

    caddy::push(&cfg).await.context("push caddy config")?;
    Ok(())
}

pub async fn hub_config(state: &State) -> Result<String> {
    let mut peers = Vec::new();
    for p in db::vpn_peers(&state.db).await? {
        peers.push(wireguard::Peer {
            name: p.name,
            public_key: p.public_key,
            psk: state.key.open_string(&p.sealed_psk)?.to_string(),
            ip: p.ip.parse::<Ipv4Addr>()?,
        });
    }
    Ok(wireguard::hub_config(&state.config.vpn.hub_private_key, state.config.vpn.port, &peers))
}

/// Public DNS: the domain and its wildcard point at the server.
pub async fn ensure_dns_records(state: &Shared) -> Result<()> {
    let ips = state.public_ips.read().await.clone();
    let v4: Vec<String> = ips.iter().filter(|i| !i.contains(':')).cloned().collect();
    let v6: Vec<String> = ips.iter().filter(|i| i.contains(':')).cloned().collect();
    for d in &state.config.domains {
        let zone = state.dns_api.zone_for(d).await?;
        for name in [d.clone(), format!("*.{d}")] {
            let rel = crate::hetzner::relative_name(&name, &zone.name);
            if !v4.is_empty() {
                state.dns_api.rrset_set(&zone.name, &rel, "A", 300, &v4).await?;
            }
            if !v6.is_empty() {
                state.dns_api.rrset_set(&zone.name, &rel, "AAAA", 300, &v6).await?;
            }
        }
        // CAA: only Let's Encrypt may issue for the domain; left alone when one exists already
        let rel = crate::hetzner::relative_name(d, &zone.name);
        if state.dns_api.rrset(&zone.name, &rel, "CAA").await?.is_none() {
            state.dns_api.rrset_set(&zone.name, &rel, "CAA", 3600, &["0 issue \"letsencrypt.org\"".to_string()]).await?;
            tracing::info!("dns: CAA record for {d} limits issuance to Let's Encrypt");
        }
        tracing::info!("dns: {d} and *.{d} -> {}", ips.join(", "));
    }
    Ok(())
}

/// Issue or renew the wildcard certificate of every domain when needed. Returns true when something changed.
pub async fn ensure_certificates(state: &Shared) -> Result<bool> {
    let mut changed = false;
    for d in &state.config.domains {
        let path = state.config.certs_dir().join(d).join("fullchain.pem");
        let not_after = super::acme::not_after_of_file(&path);
        let needs = match not_after {
            Some(t) => t - chrono::Utc::now() < chrono::Duration::days(30),
            None => true,
        };
        if let Some(t) = not_after {
            db::put_certificate(&state.db, d, Some(&t.to_rfc3339()), "").await?;
        }
        if !needs {
            continue;
        }
        if state.config.dev {
            tracing::info!("dev mode: would issue certificate for {d}");
            continue;
        }
        tracing::info!("acme: issuing certificate for {d}");
        match super::acme::issue(
            d,
            &state.config.acme_dir(),
            &state.config.certs_dir(),
            &state.config.acme.email,
            state.config.acme.directory_url(),
            &state.dns_api,
        )
        .await
        {
            Ok(issued) => {
                db::put_certificate(&state.db, d, Some(&issued.not_after.to_rfc3339()), "").await?;
                changed = true;
            }
            Err(e) => {
                tracing::error!("acme: {d}: {e:#}");
                db::put_certificate(&state.db, d, None, &format!("{e:#}")).await?;
            }
        }
    }
    Ok(changed)
}
