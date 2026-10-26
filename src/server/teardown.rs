//! Tear the installation down from the interface. The recovery phrase is the proof (checked by the handler);
//! then every app goes with its volumes, optionally the DNS records and the cloud resources (tokens used once,
//! never stored), and a transient unit outside the daemon's sandbox wipes the server's own state including the
//! master key and powers the machine off. Backup snapshots in the bucket are left alone.
use anyhow::{Context, Result};

use crate::hetzner::{relative_name, Hetzner};
use crate::server::jobs::Log;
use crate::server::state::Shared;
use crate::server::{db, deploy, notify, system};

pub struct Tokens {
    pub cloud: Option<String>,
    pub dns: Option<String>,
}

/// Runs as `pocketcloud-teardown` outside the sandbox, after the job had time to finish its log.
const WIPE: &str = "sleep 15; \
systemctl stop pocketcloud caddy 2>/dev/null; \
docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1; \
docker volume ls -q | xargs -r docker volume rm -f >/dev/null 2>&1; \
docker network prune -f >/dev/null 2>&1; \
shred -u /etc/pocketcloud/master.key 2>/dev/null || rm -f /etc/pocketcloud/master.key; \
rm -rf /etc/pocketcloud /var/lib/pocketcloud /run/pocketcloud /var/log/pocketcloud /etc/caddy /var/lib/caddy; \
systemctl stop wg-quick@wg0 2>/dev/null; rm -rf /etc/wireguard; \
systemctl poweroff";

pub async fn teardown_job(state: Shared, tokens: Tokens, log: Log) -> Result<()> {
    let name = state.config.name.clone();
    log.line(format!("tearing down {name}: this interface stops answering once the tunnel is gone")).await;
    if state.config.dev {
        log.line("dev mode: nothing is torn down").await;
        return Ok(());
    }
    // tell the outside world first; the notifier's minute batch would never get to run
    let change = notify::Change {
        event: "opened".into(),
        key: "teardown".into(),
        severity: "critical".into(),
        summary: format!("{name} is being torn down from the interface"),
        at: chrono::Utc::now().to_rfc3339(),
    };
    if notify::deliver(&state, &[change]).await {
        log.line("notification sent").await;
    }

    for app in db::apps(&state.db).await? {
        log.line(format!("removing app {} with its volumes", app.name)).await;
        if let Err(e) = deploy::remove(state.clone(), app.id, true, log.clone()).await {
            log.line(format!("  {e:#}; the wipe takes care of what is left")).await;
        }
    }

    if let Some(t) = tokens.dns.as_deref().or(tokens.cloud.as_deref()) {
        delete_dns(&state, &Hetzner::new(t), &log).await;
    } else {
        log.line("no DNS token: remove the records of the domain in the Hetzner console yourself").await;
    }

    let cloud = tokens.cloud.as_deref().map(Hetzner::new);
    let mut server_id = None;
    if let Some(cloud) = &cloud {
        server_id = delete_cloud_resources(cloud, &name, &log).await;
    }

    system::run("systemd-run", &["--unit", "pocketcloud-teardown", "--collect", "--quiet", "/bin/sh", "-c", WIPE]).await.context("start the wipe")?;
    log.line("wipe scheduled: in 15 seconds the state, the master key and the WireGuard config are deleted and the server powers off").await;
    log.line("backup snapshots stay in the bucket; the recovery phrase plus the bucket credentials still restore them").await;

    match (cloud, server_id) {
        (Some(cloud), Some(id)) => match cloud.delete_server(id).await {
            Ok(()) => log.line("cloud: server deleted; nothing of this installation is left").await,
            Err(e) => log.line(format!("cloud: server not deleted ({e:#}); delete it in the Hetzner console")).await,
        },
        _ => log.line("delete the powered-off server in the Hetzner console; its disk holds nothing usable").await,
    }
    Ok(())
}

/// The records setup wrote, as far as they still point at this server.
async fn delete_dns(state: &Shared, dns: &Hetzner, log: &Log) {
    let ips = state.public_ips.read().await.clone();
    for d in &state.config.domains {
        let zone = match dns.zone_for(d).await {
            Ok(z) => z,
            Err(e) => {
                log.line(format!("dns: {d}: {e:#}")).await;
                continue;
            }
        };
        let rel = |h: &str| relative_name(h, &zone.name);
        for host in [d.clone(), format!("*.{d}"), format!("acme-ns.{d}")] {
            for rtype in ["A", "AAAA"] {
                let Ok(Some(set)) = dns.rrset(&zone.name, &rel(&host), rtype).await else { continue };
                if !set.records.iter().all(|r| ips.contains(&r.value)) {
                    log.line(format!("dns: {host} {rtype} points elsewhere, left alone")).await;
                    continue;
                }
                report(log, &format!("{host} {rtype}"), dns.rrset_delete(&zone.name, &rel(&host), rtype).await).await;
            }
        }
        let challenge = format!("_acme-challenge.{d}");
        report(log, &format!("{challenge} NS"), dns.rrset_delete(&zone.name, &rel(&challenge), "NS").await).await;
        if let Ok(Some(caa)) = dns.rrset(&zone.name, &rel(d), "CAA").await {
            if caa.records.len() == 1 && caa.records[0].value.contains("letsencrypt.org") {
                report(log, &format!("{d} CAA"), dns.rrset_delete(&zone.name, &rel(d), "CAA").await).await;
            }
        }
    }
}

async fn report(log: &Log, what: &str, r: Result<()>) {
    match r {
        Ok(()) => log.line(format!("dns: removed {what}")).await,
        Err(e) => log.line(format!("dns: {what}: {e:#}")).await,
    }
}

/// Firewall and ssh key now, the server itself last (after the wipe is scheduled); returns the server's id.
async fn delete_cloud_resources(cloud: &Hetzner, name: &str, log: &Log) -> Option<i64> {
    let rname = format!("pocketcloud-{name}");
    let server = match cloud.server_by_name(&rname).await {
        Ok(Some(s)) => Some(s),
        Ok(None) => {
            log.line(format!("cloud: no server named {rname} in this project")).await;
            None
        }
        Err(e) => {
            log.line(format!("cloud: {e:#}")).await;
            None
        }
    };
    if let Ok(Some(fw)) = cloud.firewall_by_name(&rname).await {
        if let Some(s) = &server {
            if let Err(e) = cloud.firewall_remove_from_server(fw.id, s.id).await {
                log.line(format!("cloud: detach firewall: {e:#}")).await;
            }
        }
        // detaching is an action that takes a moment
        let mut result = Ok(());
        for _ in 0..10 {
            result = cloud.delete_firewall(fw.id).await;
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match result {
            Ok(()) => log.line("cloud: firewall deleted").await,
            Err(e) => log.line(format!("cloud: firewall not deleted ({e:#})")).await,
        }
    }
    if let Ok(Some(k)) = cloud.ssh_key_by_name(&rname).await {
        match cloud.delete_ssh_key(k.id).await {
            Ok(()) => log.line("cloud: ssh key deleted").await,
            Err(e) => log.line(format!("cloud: ssh key not deleted ({e:#})")).await,
        }
    }
    server.map(|s| s.id)
}
