//! `pocketcloud upgrade <name>`: new binary and units onto the server, daemon restarted.
use anyhow::Result;

use crate::cli::UpgradeArgs;
use crate::install::Installation;
use crate::remote::{self, Ssh};
use crate::wireguard::HUB_IP;

pub async fn run(args: UpgradeArgs) -> Result<()> {
    let inst = Installation::load(&args.name)?;
    let ip = inst.server.ipv4.clone().unwrap_or_default();
    let host = if remote::tcp_open(&format!("{HUB_IP}:22"), 3).await {
        HUB_IP.to_string()
    } else if remote::tcp_open(&format!("{ip}:22"), 4).await {
        ip
    } else {
        anyhow::bail!("server not reachable; activate the VPN or run: pocketcloud rescue {} open-ssh", inst.name);
    };
    let ssh = Ssh::for_installation(&inst, &host)?;
    let arch = ssh.run("uname -m").await?.trim().to_string();
    let target = if arch == "aarch64" { "aarch64-unknown-linux-musl" } else { "x86_64-unknown-linux-musl" };
    let stage = crate::setup::tempdir(&inst, "upgrade")?;
    remote::fetch_server_binary(args.server_binary.as_deref(), target, &stage.join("pocketcloud")).await?;
    if !args.skip_caddy {
        remote::fetch_caddy_binary(args.caddy_binary.as_deref(), target, &stage.join("caddy")).await?;
    }
    crate::setup::write_assets(&stage)?;
    println!("uploading to {host}");
    ssh.upload_dir(&stage, "/opt/pocketcloud/stage").await?;
    let _ = std::fs::remove_dir_all(&stage);
    ssh.run_live("sudo bash /opt/pocketcloud/stage/install.sh").await?;
    println!("upgraded to {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
