//! `pocketcloud recover`: run from Hetzner's rescue system against the mounted disk when every device is lost.
//! The recovery phrase must match the master key on the disk; then a new VPN device is created (config and QR)
//! and, on request, the interface password is reset. The daemon applies the device at the next boot.
use anyhow::{bail, Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use std::path::Path;

use crate::cli::RecoverArgs;
use crate::crypto::{self, MasterKey};
use crate::server::{config::Config, db};
use crate::wireguard;

pub async fn run(args: RecoverArgs) -> Result<()> {
    let root = Path::new(&args.root);
    let config_path = root.join("etc/pocketcloud/config.toml");
    let key_path = root.join("etc/pocketcloud/master.key");
    if !config_path.exists() {
        bail!("{} not found; mount the server's disk (rescue system: mount /dev/sda1 /mnt) and pass --root", config_path.display());
    }
    let config: Config = toml::from_str(&std::fs::read_to_string(&config_path)?).context("config.toml")?;
    let on_disk = std::fs::read_to_string(&key_path).context("master.key")?.trim().to_string();
    println!("installation {} ({})", config.name, config.interface_host);

    // the phrase is the proof of ownership; console access alone is not enough
    let phrase: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Recovery phrase (24 words)").interact_text()?;
    let key = MasterKey::from_phrase(&phrase)?;
    if *key.to_hex() != on_disk {
        bail!("the phrase does not match this server's master key");
    }
    println!("phrase accepted");

    let db_path = root.join(config.data_dir.strip_prefix("/").unwrap_or(&config.data_dir)).join("pocketcloud.db");
    let db = db::open(&db_path).await.with_context(|| format!("open {}", db_path.display()))?;

    let device: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Name of the new VPN device").default("recovery".into()).interact_text()?;
    let device = device.trim().to_string();
    if device.is_empty() || device.len() > 32 || !device.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("device names: letters, digits, dashes, underscores");
    }
    let used: Vec<std::net::Ipv4Addr> = db::vpn_peers(&db).await?.iter().filter_map(|p| p.ip.parse().ok()).collect();
    let ip = wireguard::next_ip(wireguard::Scope::Full, &used)?;
    let keys = wireguard::generate_keypair();
    let psk = wireguard::generate_psk();
    db::add_vpn_peer(&db, &device, &keys.public, &key.seal(psk.as_bytes()), &ip.to_string(), "full").await?;
    db::audit(&db, "recover", "vpn.add", &format!("{device} full {ip}")).await?;
    let _ = db::add_event(&db, "admin_action", "pocketcloud", &format!("VPN device {device} added by pocketcloud recover from the rescue system"), &serde_json::json!({"action": "vpn.add", "user": "recover"})).await;

    let endpoint = db::kv_get(&db, "host.public_ips")
        .await?
        .and_then(|s| s.split(',').find(|i| !i.contains(':')).map(str::to_string))
        .filter(|s| !s.is_empty());
    let endpoint = match endpoint {
        Some(e) => e,
        None => Input::with_theme(&ColorfulTheme::default()).with_prompt("Public IPv4 address of the server").interact_text()?,
    };
    let hub_pub = wireguard::public_key_of(&config.vpn.hub_private_key)?;
    let conf = wireguard::client_config(&wireguard::ClientConfig {
        private_key: &keys.private,
        ip,
        hub_public_key: &hub_pub,
        psk: &psk,
        endpoint_host: &endpoint,
        endpoint_port: config.vpn.port,
        scope: wireguard::Scope::Full,
        apps_cidr: crate::firewall::APPS_CIDR,
    });

    if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Also reset the interface password?").default(false).interact()? {
        let users = db::users(&db).await?;
        let username: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").default(users.first().map(|u| u.username.clone()).unwrap_or_default()).interact_text()?;
        let pw = Password::with_theme(&ColorfulTheme::default()).with_prompt("New password (12+ characters)").with_confirmation("Repeat", "passwords differ").interact()?;
        if pw.chars().count() < 12 {
            bail!("the password needs at least 12 characters");
        }
        let hash = crypto::hash_password(&pw)?;
        if !db::set_password(&db, &username, &hash).await? {
            db::create_user(&db, &username, &hash).await?;
        }
        db::audit(&db, "recover", "account.password", &username).await?;
        println!("password set for {username}");
    }
    db.close().await;

    println!("\n# save as pocketcloud-{}-{device}.conf and import it into WireGuard, or scan the code\n{conf}", config.name);
    println!("{}", wireguard::qr(&conf)?);
    println!("Now reboot into the normal system (unmount, then reboot); the tunnel works once pocketcloud has started.");
    Ok(())
}
