//! `pocketcloud setup <name>`: the interactive wizard that creates and enrolls a server.
//! Every step saves its result, a re-run continues where it stopped.
use anyhow::{anyhow, bail, Context, Result};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::cli::{SetupArgs, VpnArgs};
use crate::crypto::{self, MasterKey};
use crate::hetzner::{FirewallRule, Hetzner};
use crate::install::{self, Installation, Step};
use crate::remote::{self, Ssh};
use crate::wireguard;

const IMAGE: &str = "ubuntu-24.04";

fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

fn step(title: &str) {
    println!("\n{}", style(title).bold().cyan());
}

fn ok(msg: &str) {
    println!("  {} {msg}", style("✔").green());
}

fn info(msg: &str) {
    println!("  {msg}");
}

fn labels(name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("pocketcloud".to_string(), name.to_string())])
}

fn resource_name(name: &str) -> String {
    format!("pocketcloud-{name}")
}

/// Everything setup needs between steps and does not want in install.toml.
struct Secrets {
    hetzner_token: String,
    dns_token: String,
    server_config: String,
}

impl Secrets {
    fn save(&self, inst: &Installation) -> Result<()> {
        let d = inst.dir()?;
        install::write_private(&inst.hetzner_token_path()?, &self.hetzner_token)?;
        install::write_private(&d.join("hetzner-dns.token"), &self.dns_token)?;
        install::write_private(&d.join("server-config.toml"), &self.server_config)
    }

    fn load(inst: &Installation) -> Result<Secrets> {
        let d = inst.dir()?;
        Ok(Secrets {
            hetzner_token: std::fs::read_to_string(inst.hetzner_token_path()?).context("hetzner.token")?.trim().to_string(),
            dns_token: std::fs::read_to_string(d.join("hetzner-dns.token")).unwrap_or_default().trim().to_string(),
            server_config: std::fs::read_to_string(d.join("server-config.toml")).context("server-config.toml")?,
        })
    }
}

pub async fn run(args: SetupArgs) -> Result<()> {
    let mut inst = Installation::load_or_new(&args.name)?;
    install::ensure_dir(&args.name)?;
    println!("{} setup of installation {}", style("pocketcloud").bold(), style(&args.name).bold());
    if inst.step != Step::New {
        info(&format!("continuing at step {:?}", inst.step));
    }

    let mut master_key: Option<MasterKey> = None;
    if inst.step == Step::New {
        let (secrets, key) = plan(&mut inst, &args).await?;
        secrets.save(&inst)?;
        master_key = Some(key);
        inst.step = Step::Planned;
        inst.created = Some(chrono::Utc::now());
        inst.save()?;
    }
    let secrets = Secrets::load(&inst)?;
    let hetzner = Hetzner::new(&secrets.hetzner_token);

    if inst.step == Step::Planned {
        create(&mut inst, &hetzner, &Hetzner::new(&secrets.dns_token), &args).await?;
        inst.step = Step::Created;
        inst.save()?;
    }
    if inst.step == Step::Created {
        let key = match master_key.take() {
            Some(k) => k,
            None => {
                step("Recovery phrase");
                info("the master key only existed in memory during the first run; enter the recovery phrase");
                let phrase: String = Input::with_theme(&theme()).with_prompt("24 words").interact_text()?;
                MasterKey::from_phrase(&phrase)?
            }
        };
        install_server(&inst, &secrets, &key, &hetzner, &args).await?;
        inst.step = Step::Installed;
        inst.save()?;
    }
    if inst.step == Step::Installed {
        verify_vpn(&inst).await?;
        inst.step = Step::VpnVerified;
        inst.save()?;
    }
    if inst.step == Step::VpnVerified {
        lock_down(&inst, &hetzner).await?;
        inst.step = Step::Done;
        inst.save()?;
    }
    summary(&inst)?;
    Ok(())
}

async fn plan(inst: &mut Installation, args: &SetupArgs) -> Result<(Secrets, MasterKey)> {
    step("Hetzner");
    let hetzner_token: String = Password::with_theme(&theme()).with_prompt("Hetzner Cloud API token (project of the server, read & write)").interact()?;
    let hetzner = Hetzner::new(&hetzner_token);
    hetzner.check_token().await.context("the token was rejected")?;
    ok("token works");

    let separate = Confirm::with_theme(&theme()).with_prompt("Are the DNS zones in a different Hetzner project?").default(false).interact()?;
    let dns_token = if separate {
        let t: String = Password::with_theme(&theme()).with_prompt("API token of the DNS project").interact()?;
        Hetzner::new(&t).check_token().await.context("the DNS token was rejected")?;
        t
    } else {
        hetzner_token.clone()
    };
    let dns = Hetzner::new(&dns_token);
    let zones = dns.zones().await.context("list DNS zones")?;
    if zones.is_empty() {
        bail!("the DNS project has no zones; create the zone of your domain in the Hetzner console first");
    }
    info(&format!("zones: {}", zones.iter().map(|z| z.name.as_str()).collect::<Vec<_>>().join(", ")));

    step("Domains");
    let domains: String = Input::with_theme(&theme())
        .with_prompt("Domains that get a wildcard certificate (comma separated, e.g. example.com, staging.example.com)")
        .default(zones[0].name.clone())
        .interact_text()?;
    let domains: Vec<String> = domains.split(',').map(|d| d.trim().trim_end_matches('.').to_lowercase()).filter(|d| !d.is_empty()).collect();
    for d in &domains {
        dns.zone_for(d).await?;
    }
    let interface_host: String = Input::with_theme(&theme())
        .with_prompt("Host name of the interface")
        .default(format!("pocketcloud.{}", domains[0]))
        .validate_with(|h: &String| -> Result<(), String> {
            if domains.iter().any(|d| h.ends_with(&format!(".{d}")) && h.matches('.').count() == d.matches('.').count() + 1) {
                Ok(())
            } else {
                Err("one label under one of the domains".into())
            }
        })
        .interact_text()?;

    step("Server");
    let locations = hetzner.locations().await?;
    let loc_labels: Vec<String> = locations.iter().map(|l| format!("{} ({}, {})", l.name, l.city, l.country)).collect();
    let default_loc = locations.iter().position(|l| l.name == "fsn1").unwrap_or(0);
    let li = Select::with_theme(&theme()).with_prompt("Location").items(&loc_labels).default(default_loc).interact()?;
    let location = locations[li].name.clone();
    let mut types: Vec<_> = hetzner.server_types().await?.into_iter().filter(|t| t.monthly_gross(&location).is_some()).collect();
    types.sort_by(|a, b| a.monthly_gross(&location).partial_cmp(&b.monthly_gross(&location)).unwrap());
    let type_labels: Vec<String> = types
        .iter()
        .map(|t| format!("{:<6} {} vCPU {:>3} GB RAM {:>4} GB disk  {:>7.2} €/month  ({})", t.name, t.cores, t.memory as u32, t.disk, t.monthly_gross(&location).unwrap_or(0.0), t.architecture))
        .collect();
    let default_type = types.iter().position(|t| t.name == "cx23").unwrap_or(0);
    let ti = Select::with_theme(&theme()).with_prompt("Server type").items(&type_labels).default(default_type).interact()?;
    let server_type = types[ti].clone();
    let ssh_user: String = Input::with_theme(&theme()).with_prompt("SSH user on the server").default("admin".into()).interact_text()?;

    step("Interface login");
    let default_user = std::env::var("USER").unwrap_or_else(|_| "admin".into());
    let username: String = Input::with_theme(&theme()).with_prompt("Username").default(default_user).interact_text()?;
    let password = Password::with_theme(&theme())
        .with_prompt("Password (12+ characters)")
        .with_confirmation("Repeat", "passwords differ")
        .validate_with(|p: &String| if p.len() >= 12 { Ok(()) } else { Err("at least 12 characters") })
        .interact()?;

    step("VPN");
    let default_device = hostname().unwrap_or_else(|| "laptop".into());
    let device: String = Input::with_theme(&theme()).with_prompt("Name of this device (first WireGuard client, full scope)").default(default_device).interact_text()?;
    let vpn_port: u16 = Input::with_theme(&theme()).with_prompt("WireGuard port").default(wireguard::DEFAULT_PORT).interact_text()?;

    step("Certificates");
    let email: String = Input::with_theme(&theme()).with_prompt("E-mail for Let's Encrypt (expiry warnings, optional)").allow_empty(true).default(String::new()).interact_text()?;
    let staging = Confirm::with_theme(&theme()).with_prompt("Use the Let's Encrypt staging environment (untrusted certificates, for trying things out)?").default(false).interact()?;

    step("Plan");
    let price = server_type.monthly_gross(&location).unwrap_or(0.0);
    println!("  server      {} in {location}, {IMAGE}, {price:.2} €/month", server_type.name);
    println!("  firewall    inbound 80, 443, {vpn_port}/udp, icmp; ssh 22 only from your address while setting up");
    println!("  domains     {}", domains.join(", "));
    println!("  interface   https://{interface_host} (VPN only)");
    println!("  dns         {} and *.{} → server; _acme-challenge delegated to the server (no DNS token on it)", domains.join(", "), domains.join(", *."));
    println!("  ssh         user {ssh_user}, key only, via VPN after setup");
    println!("  afterwards  backups, alerts, Falco and apps are configured in the interface");
    if !args.yes && !Confirm::with_theme(&theme()).with_prompt("Create this?").default(true).interact()? {
        bail!("aborted");
    }

    // keys
    let dir = inst.dir()?;
    let key_path = inst.ssh_key_path()?;
    if !key_path.exists() {
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &format!("pocketcloud-{}", inst.name), "-f"])
            .arg(&key_path)
            .status()?;
        if !st.success() {
            bail!("ssh-keygen failed");
        }
    }
    let hub = wireguard::generate_keypair();
    let device_keys = wireguard::generate_keypair();
    let psk = wireguard::generate_psk();
    let device_ip = wireguard::next_ip(wireguard::Scope::Full, &[])?;

    step("Recovery phrase");
    let reuse = Confirm::with_theme(&theme())
        .with_prompt("Reuse the recovery phrase of an earlier installation? (needed to restore its backups)")
        .default(false)
        .interact()?;
    let master = if reuse {
        let phrase: String = Input::with_theme(&theme()).with_prompt("24 words").interact_text()?;
        let m = MasterKey::from_phrase(&phrase)?;
        ok("master key restored from the phrase; backups of the earlier installation can be read");
        m
    } else {
        MasterKey::generate()
    };
    let phrase = master.phrase();
    if !reuse {
    println!("  The master key encrypts every secret on the server. This phrase is the only way to recover it.");
    println!("  Store it in your password manager now. It is shown once and never stored by pocketcloud.\n");
    for (i, chunk) in phrase.split_whitespace().collect::<Vec<_>>().chunks(6).enumerate() {
        println!("    {}", chunk.iter().enumerate().map(|(j, w)| format!("{:>2} {:<10}", i * 6 + j + 1, w)).collect::<String>());
    }
    println!();
    if !args.yes {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let mut positions: Vec<usize> = (0..24).collect();
        use rand::seq::SliceRandom;
        positions.shuffle(&mut rand::thread_rng());
        for p in positions.iter().take(3) {
            loop {
                let w: String = Input::with_theme(&theme()).with_prompt(format!("Word {}", p + 1)).interact_text()?;
                if w.trim() == words[*p] {
                    break;
                }
                println!("  {} that is not word {}", style("✗").red(), p + 1);
            }
        }
        ok("phrase confirmed");
    }
    }

    let server_config = render_server_config(&ServerConfigInput {
        name: &inst.name,
        domains: &domains,
        interface_host: &interface_host,
        vpn_port,
        hub_private_key: &hub.private,
        device: &device,
        device_public_key: &device_keys.public,
        psk: &psk,
        device_ip: &device_ip.to_string(),
        email: &email,
        staging,
        username: &username,
        password_hash: &crypto::hash_password(&password)?,
    });

    // the client config needs the server address; written now with a placeholder and completed after creation
    let client = wireguard::client_config(&wireguard::ClientConfig {
        private_key: &device_keys.private,
        ip: device_ip,
        hub_public_key: &hub.public,
        psk: &psk,
        endpoint_host: "SERVER_IP",
        endpoint_port: vpn_port,
        scope: wireguard::Scope::Full,
        apps_cidr: crate::firewall::APPS_CIDR,
    });
    inst.vpn = install::Vpn { port: vpn_port, hub_public_key: hub.public.clone(), device_name: device.clone(), device_ip: device_ip.to_string() };
    install::write_private(&inst.vpn_config_path()?, &client)?;
    inst.domains = domains;
    inst.hetzner.server_name = resource_name(&inst.name);
    inst.hetzner.dns_separate_project = separate;
    inst.server = install::ServerInfo { ipv4: None, ipv6: None, location, server_type: server_type.name.clone(), ssh_user, interface_host };
    let _ = dir;
    Ok((Secrets { hetzner_token, dns_token, server_config }, master))
}

struct ServerConfigInput<'a> {
    name: &'a str,
    domains: &'a [String],
    interface_host: &'a str,
    vpn_port: u16,
    hub_private_key: &'a str,
    device: &'a str,
    device_public_key: &'a str,
    psk: &'a str,
    device_ip: &'a str,
    email: &'a str,
    staging: bool,
    username: &'a str,
    password_hash: &'a str,
}

fn render_server_config(c: &ServerConfigInput) -> String {
    let domains = c.domains.iter().map(|d| format!("{d:?}")).collect::<Vec<_>>().join(", ");

    format!(
        r#"# written by pocketcloud setup
name = {name:?}
domains = [{domains}]
interface_host = {interface_host:?}

[vpn]
port = {vpn_port}
hub_private_key = {hub_private_key:?}

[vpn.initial_peer]
name = {device:?}
public_key = {device_public_key:?}
psk = {psk:?}
ip = {device_ip:?}
scope = "full"

[acme]
email = {email:?}
environment = {env:?}

[bootstrap_user]
username = {username:?}
password_hash = {password_hash:?}
"#,
        name = c.name,
        interface_host = c.interface_host,
        vpn_port = c.vpn_port,
        hub_private_key = c.hub_private_key,
        device = c.device,
        device_public_key = c.device_public_key,
        psk = c.psk,
        device_ip = c.device_ip,
        email = c.email,
        env = if c.staging { "staging" } else { "production" },
        username = c.username,
        password_hash = c.password_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_parses() {
        let s = render_server_config(&ServerConfigInput {
            name: "demo",
            domains: &["example.com".into(), "staging.example.com".into()],
            interface_host: "pocketcloud.example.com",
            vpn_port: 51820,
            hub_private_key: "k=",
            device: "mac",
            device_public_key: "p=",
            psk: "s=",
            device_ip: "10.8.0.2",
            email: "",
            staging: true,
            username: "timo",
            password_hash: "$argon2id$x",

        });
        let c: crate::server::config::Config = toml::from_str(&s).unwrap();
        assert_eq!(c.domains.len(), 2);
        assert!(c.hetzner.dns_token.is_empty(), "no DNS token on the server");
        assert_eq!(c.vpn.initial_peer.unwrap().ip, "10.8.0.2");
        assert_eq!(c.acme.environment, "staging");
        assert!(c.bootstrap_user.is_some());
    }

    #[test]
    fn rules() {
        assert_eq!(firewall_rules(51820, None).len(), 4);
        assert_eq!(firewall_rules(51820, Some("1.2.3.4")).len(), 5);
    }
}

pub fn firewall_rules(vpn_port: u16, ssh_from: Option<&str>) -> Vec<FirewallRule> {
    let any = ["0.0.0.0/0", "::/0"];
    let mut rules = vec![
        FirewallRule::inbound("tcp", Some("80"), &any, "http"),
        FirewallRule::inbound("tcp", Some("443"), &any, "https"),
        FirewallRule::inbound("udp", Some(&vpn_port.to_string()), &any, "wireguard"),
        FirewallRule::inbound("icmp", None, &any, "ping"),
    ];
    if let Some(ip) = ssh_from {
        let src = format!("{ip}/32");
        rules.push(FirewallRule::inbound("tcp", Some("22"), &[&src], "ssh during setup or rescue"));
    }
    rules
}

async fn create(inst: &mut Installation, hetzner: &Hetzner, dns: &Hetzner, _args: &SetupArgs) -> Result<()> {
    step("Creating resources");
    let name = resource_name(&inst.name);
    let labels = labels(&inst.name);
    let pubkey = std::fs::read_to_string(inst.ssh_key_path()?.with_extension("pub"))?;

    let key = match hetzner.ssh_key_by_name(&name).await? {
        Some(k) if k.public_key.trim() == pubkey.trim() => k,
        Some(_) => bail!("an ssh key named {name} exists in the project with a different key; remove it first"),
        None => hetzner.create_ssh_key(&name, &pubkey, &labels).await?,
    };
    inst.hetzner.ssh_key_id = Some(key.id);
    ok(&format!("ssh key {name}"));

    let my_ip = remote::my_public_ipv4().await?;
    let rules = firewall_rules(inst.vpn.port, Some(&my_ip));
    let fw = match hetzner.firewall_by_name(&name).await? {
        Some(f) => {
            hetzner.set_firewall_rules(f.id, &rules).await?;
            f
        }
        None => hetzner.create_firewall(&name, &rules, &labels).await?,
    };
    inst.hetzner.firewall_id = Some(fw.id);
    ok(&format!("firewall {name}, ssh open for {my_ip}"));
    inst.save()?;

    let server = match hetzner.server_by_name(&name).await? {
        Some(s) => {
            info(&format!("server {name} exists, reusing it"));
            s
        }
        None => {
            let user_data = crate::cloudinit::render(&crate::cloudinit::CloudInit { hostname: &inst.name, ssh_user: &inst.server.ssh_user, ssh_public_key: &pubkey });
            info(&format!("creating server {name} ({}) in {}", inst.server.server_type, inst.server.location));
            hetzner.create_server(&name, &inst.server.server_type, IMAGE, &inst.server.location, key.id, fw.id, &user_data, &labels).await?
        }
    };
    inst.hetzner.server_id = Some(server.id);
    inst.server.ipv4 = server.ipv4();
    inst.server.ipv6 = server.ipv6();
    inst.save()?;
    ok(&format!("server {name} #{} at {}", server.id, inst.server.ipv4.clone().unwrap_or_default()));

    // public records, from here with the DNS token; the server answers the certificate challenge itself
    for l in crate::dnsrecords::apply(dns, &inst.domains, inst.server.ipv4.as_deref(), inst.server.ipv6.as_deref()).await? {
        info(&l);
    }
    ok("dns records written");

    // complete the local client config with the address
    let path = inst.vpn_config_path()?;
    let conf = std::fs::read_to_string(&path)?.replace("SERVER_IP", inst.server.ipv4.as_deref().unwrap_or(""));
    install::write_private(&path, &conf)?;
    Ok(())
}

async fn wait_for_ssh(ssh: &Ssh) -> Result<()> {
    info("waiting for ssh");
    for _ in 0..90 {
        if ssh.reachable().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    bail!("server did not become reachable over ssh; check the Hetzner console")
}

async fn install_server(inst: &Installation, secrets: &Secrets, key: &MasterKey, hetzner: &Hetzner, args: &SetupArgs) -> Result<()> {
    step("Installing");
    let ip = inst.server.ipv4.clone().ok_or_else(|| anyhow!("server has no address"))?;
    // the cloud firewall may still carry an old address of ours
    if let Some(fw) = inst.hetzner.firewall_id {
        let my_ip = remote::my_public_ipv4().await?;
        hetzner.set_firewall_rules(fw, &firewall_rules(inst.vpn.port, Some(&my_ip))).await?;
    }
    let ssh = Ssh::for_installation(inst, &ip)?;
    wait_for_ssh(&ssh).await?;
    ssh.run("cloud-init status --wait >/dev/null 2>&1 || true").await?;
    ok("first boot finished");

    let server = hetzner.server(inst.hetzner.server_id.unwrap()).await?;
    let types = hetzner.server_types().await?;
    let arch = types.iter().find(|t| t.name == server.server_type.name).map(|t| t.architecture.clone()).unwrap_or_else(|| "x86".into());
    let target = remote::linux_target(&arch);

    let stage = tempdir(inst, "stage")?;
    remote::fetch_server_binary(args.server_binary.as_deref(), target, &stage.join("pocketcloud")).await?;
    remote::fetch_caddy_binary(args.caddy_binary.as_deref(), target, &stage.join("caddy")).await?;
    install::write_private(&stage.join("config.toml"), &secrets.server_config)?;
    install::write_private(&stage.join("master.key"), &format!("{}\n", *key.to_hex()))?;
    write_assets(&stage)?;
    info("uploading");
    ssh.upload_dir(&stage, "/opt/pocketcloud/stage").await?;
    let _ = std::fs::remove_dir_all(&stage);
    info("running the installer (a few minutes)");
    ssh.run_live("sudo bash /opt/pocketcloud/stage/install.sh").await?;
    ok("pocketcloud daemon is running");
    // the installer upgraded every package; a new kernel only takes effect after a reboot
    if ssh.run("test -f /var/run/reboot-required && echo yes || true").await?.trim() == "yes" {
        info("the system updates need a reboot; rebooting now");
        let _ = ssh.run("sudo systemctl reboot").await;
        tokio::time::sleep(Duration::from_secs(15)).await;
        wait_for_ssh(&ssh).await?;
        ssh.run("for i in $(seq 30); do systemctl is-active --quiet pocketcloud && exit 0; sleep 2; done; exit 1")
            .await
            .context("pocketcloud did not come back after the reboot")?;
        ok("rebooted, daemon is back");
    }
    Ok(())
}

pub fn write_assets(stage: &Path) -> Result<()> {
    std::fs::create_dir_all(stage.join("units"))?;
    std::fs::write(stage.join("install.sh"), include_str!("../assets/install.sh"))?;
    std::fs::write(stage.join("units/pocketcloud.service"), include_str!("../assets/units/pocketcloud.service"))?;
    std::fs::write(stage.join("units/pocketcloud-aide.service"), include_str!("../assets/units/pocketcloud-aide.service"))?;
    std::fs::write(stage.join("units/pocketcloud-aide.timer"), include_str!("../assets/units/pocketcloud-aide.timer"))?;
    std::fs::write(stage.join("audit.rules"), include_str!("../assets/audit.rules"))?;
    std::fs::write(stage.join("aide.conf"), include_str!("../assets/aide.conf"))?;
    std::fs::write(stage.join("logrotate"), include_str!("../assets/logrotate"))?;
    std::fs::create_dir_all(stage.join("hardening"))?;
    std::fs::write(stage.join("hardening/sshd.conf"), include_str!("../assets/hardening/sshd.conf"))?;
    std::fs::write(stage.join("hardening/sysctl.conf"), include_str!("../assets/hardening/sysctl.conf"))?;
    std::fs::write(stage.join("hardening/fail2ban.local"), include_str!("../assets/hardening/fail2ban.local"))?;
    std::fs::write(stage.join("hardening/fail2ban-waf.conf"), include_str!("../assets/hardening/fail2ban-waf.conf"))?;
    std::fs::write(stage.join("hardening/fail2ban-main.local"), include_str!("../assets/hardening/fail2ban-main.local"))?;
    std::fs::write(stage.join("hardening/apt-unattended.conf"), include_str!("../assets/hardening/apt-unattended.conf"))?;
    std::fs::write(stage.join("hardening/journald.conf"), include_str!("../assets/hardening/journald.conf"))?;
    Ok(())
}

pub fn tempdir(inst: &Installation, what: &str) -> Result<std::path::PathBuf> {
    let d = inst.dir()?.join(format!(".{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d)?;
    install::set_mode(&d, 0o700)?;
    Ok(d)
}

async fn verify_vpn(inst: &Installation) -> Result<()> {
    step("VPN");
    let conf = std::fs::read_to_string(inst.vpn_config_path()?)?;
    println!("  Import this WireGuard configuration on this device and activate the tunnel.");
    println!("  macOS: WireGuard app → Import tunnel(s) from file: {}", inst.vpn_config_path()?.display());
    println!("  The tunnel is then called pocketcloud-{}.", inst.name);
    println!("  or scan it with the WireGuard app on a phone:\n");
    println!("{}", wireguard::qr(&conf)?);
    println!("  Public ssh stays open until the tunnel works. Waiting for the tunnel (ctrl-c to stop and continue later)...");
    let ssh = Ssh::for_installation(inst, &wireguard::HUB_IP.to_string())?;
    for i in 0..600 {
        if remote::tcp_open(&format!("{}:443", wireguard::HUB_IP), 2).await && ssh.reachable().await {
            ok("tunnel works: ssh and the interface answer on 10.8.0.1");
            return Ok(());
        }
        if i % 15 == 14 {
            info("still waiting; is the tunnel active?");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    bail!("the tunnel did not come up; run setup again once it does, public ssh is still open")
}

async fn lock_down(inst: &Installation, hetzner: &Hetzner) -> Result<()> {
    step("Locking down");
    let fw = inst.hetzner.firewall_id.ok_or_else(|| anyhow!("no firewall id"))?;
    hetzner.set_firewall_rules(fw, &firewall_rules(inst.vpn.port, None)).await?;
    ok("public ssh closed in the cloud firewall; ssh now only through the VPN");
    Ok(())
}

fn summary(inst: &Installation) -> Result<()> {
    step("Done");
    println!("  interface   {}  (with the VPN active; the certificate may take a few minutes)", inst.interface_url());
    println!("  ssh         ssh -i {} {}@{}", inst.ssh_key_path()?.display(), inst.server.ssh_user, wireguard::HUB_IP);
    println!("  files       {}", inst.dir()?.display());
    println!("  rescue      pocketcloud rescue {} status", inst.name);
    println!("\n  Keep the recovery phrase and this directory safe; both are needed to get back in.");
    Ok(())
}

fn hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
}

pub async fn vpn(args: VpnArgs) -> Result<()> {
    let inst = Installation::load(&args.name)?;
    let conf = std::fs::read_to_string(inst.vpn_config_path()?)?;
    if args.qr {
        println!("{}", wireguard::qr(&conf)?);
    } else {
        print!("{conf}");
    }
    Ok(())
}
