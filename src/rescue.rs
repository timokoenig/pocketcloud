//! `pocketcloud rescue <name> ...`: works without the interface and without the VPN.
use anyhow::{anyhow, bail, Result};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};

use crate::cli::{RescueArgs, RescueCommand};
use crate::crypto::MasterKey;
use crate::hetzner::Hetzner;
use crate::install::Installation;
use crate::remote::{self, Ssh};
use crate::setup::firewall_rules;
use crate::wireguard::HUB_IP;

fn token(inst: &Installation) -> Result<String> {
    Ok(std::fs::read_to_string(inst.hetzner_token_path()?)?.trim().to_string())
}

pub async fn run(args: RescueArgs) -> Result<()> {
    let inst = Installation::load(&args.name)?;
    let hetzner = Hetzner::new(&token(&inst)?);
    let server_id = inst.hetzner.server_id.ok_or_else(|| anyhow!("installation has no server yet"))?;
    let fw_id = inst.hetzner.firewall_id.ok_or_else(|| anyhow!("installation has no firewall"))?;
    let ip = inst.server.ipv4.clone().unwrap_or_default();
    match args.command {
        RescueCommand::Status => {
            let s = hetzner.server(server_id).await?;
            println!("{}", style("hetzner").bold());
            println!("  server    {} #{} {} ({}, {})", s.name, s.id, style(&s.status).bold(), s.server_type.name, s.location_name());
            println!("  address   {}  {}", s.ipv4().unwrap_or_default(), s.ipv6().unwrap_or_default());
            let fw = hetzner.firewall(fw_id).await?;
            let ssh_rule = fw.rules.iter().find(|r| r.port.as_deref() == Some("22"));
            println!("  firewall  {} rules, public ssh {}", fw.rules.len(), match ssh_rule { Some(r) => format!("open for {}", r.source_ips.join(", ")), None => "closed".into() });
            println!("{}", style("reachability").bold());
            let (a1, a2, a3, a4) = (format!("{ip}:443"), format!("{ip}:22"), format!("{HUB_IP}:443"), format!("{HUB_IP}:22"));
            let (https, ssh_pub, vpn_https, vpn_ssh) =
                tokio::join!(remote::tcp_open(&a1, 4), remote::tcp_open(&a2, 4), remote::tcp_open(&a3, 3), remote::tcp_open(&a4, 3));
            let mark = |b: bool| if b { style("open").green() } else { style("closed").red() };
            println!("  public    443 {}   22 {}", mark(https), mark(ssh_pub));
            println!("  vpn       443 {}   22 {}   (needs the tunnel active on this device)", mark(vpn_https), mark(vpn_ssh));
            if vpn_ssh {
                let ssh = Ssh::for_installation(&inst, &HUB_IP.to_string())?;
                if let Ok(out) = ssh.run("systemctl is-active pocketcloud docker caddy wg-quick@wg0 nftables 2>/dev/null; uptime -p").await {
                    println!("{}", style("services").bold());
                    for (u, l) in ["pocketcloud", "docker", "caddy", "wg-quick@wg0", "nftables", "uptime"].iter().zip(out.lines()) {
                        println!("  {u:<14} {l}");
                    }
                }
            }
        }
        RescueCommand::OpenSsh => {
            let my_ip = remote::my_public_ipv4().await?;
            hetzner.set_firewall_rules(fw_id, &firewall_rules(inst.vpn.port, Some(&my_ip))).await?;
            println!("ssh open for {my_ip}: ssh -i {} {}@{ip}", inst.ssh_key_path()?.display(), inst.server.ssh_user);
            println!("close it again with: pocketcloud rescue {} close-ssh", inst.name);
        }
        RescueCommand::CloseSsh => {
            hetzner.set_firewall_rules(fw_id, &firewall_rules(inst.vpn.port, None)).await?;
            println!("public ssh closed");
        }
        RescueCommand::Reboot => {
            if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt(format!("Reboot {}? Apps restart on their own.", inst.hetzner.server_name)).default(false).interact()? {
                bail!("aborted");
            }
            hetzner.server_action(server_id, "reboot").await?;
            println!("reboot requested");
        }
        RescueCommand::Ssh => {
            let host = pick_host(&inst, &ip).await?;
            Ssh::for_installation(&inst, &host)?.shell().await?;
        }
        RescueCommand::RestoreKey => {
            let phrase: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Recovery phrase (24 words)").interact_text()?;
            let key = MasterKey::from_phrase(&phrase)?;
            let host = pick_host(&inst, &ip).await?;
            let ssh = Ssh::for_installation(&inst, &host)?;
            ssh.write_root_file("/etc/pocketcloud/master.key", "0600", &format!("{}\n", *key.to_hex())).await?;
            ssh.run("sudo systemctl restart pocketcloud").await?;
            println!("master key restored, daemon restarted");
        }
    }
    Ok(())
}

async fn pick_host(inst: &Installation, public_ip: &str) -> Result<String> {
    if remote::tcp_open(&format!("{HUB_IP}:22"), 3).await {
        return Ok(HUB_IP.to_string());
    }
    if remote::tcp_open(&format!("{public_ip}:22"), 4).await {
        return Ok(public_ip.to_string());
    }
    bail!("neither the VPN address nor public ssh is reachable; activate the tunnel or run: pocketcloud rescue {} open-ssh", inst.name)
}
