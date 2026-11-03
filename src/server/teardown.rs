//! Tear the installation down from the interface. The recovery phrase is the proof (checked by the handler);
//! then every app goes with its volumes, optionally the DNS records (Hetzner DNS) and the cloud resources (tokens used once,
//! never stored), and a transient unit outside the daemon's sandbox wipes the server's own state including the
//! master key and powers the machine off. Backup snapshots in the bucket are left alone.
use anyhow::{Context, Result};

use crate::dnsrecords;
use crate::hetzner::Hetzner;
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

    // the records setup wrote, as far as they still point at this server; with another DNS provider the
    // owner deletes them, so the job lists them
    let ips = state.public_ips.read().await.clone();
    match tokens.dns.as_deref().or(tokens.cloud.as_deref()) {
        Some(t) => {
            for line in dnsrecords::remove(&Hetzner::new(t), &state.config.domains, &ips).await {
                log.line(format!("dns: {line}")).await;
            }
        }
        None => {
            log.line("no Hetzner DNS token: delete these records at your DNS provider yourself:").await;
            let v4 = ips.iter().find(|ip| ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_ipv4())).cloned();
            let v6 = ips.iter().find(|ip| ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_ipv6())).cloned();
            for d in &state.config.domains {
                for r in dnsrecords::plan_domain(d, v4.as_deref(), v6.as_deref()) {
                    log.line(format!("  {r}")).await;
                }
            }
        }
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
