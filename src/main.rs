mod backup_cli;
mod cli;
mod cloudinit;
mod crypto;
mod firewall;
mod hetzner;
mod install;
mod remote;
mod rescue;
mod server;
mod setup;
mod upgrade;
mod wireguard;

use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    let default_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)))
        .with_target(false)
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        match args.command {
            cli::Command::Setup(a) => setup::run(a).await,
            cli::Command::Server(a) => server::run(a).await,
            cli::Command::Rescue(a) => rescue::run(a).await,
            cli::Command::Upgrade(a) => upgrade::run(a).await,
            cli::Command::Vpn(a) => setup::vpn(a).await,
            cli::Command::Backup(a) => backup_cli::run(a).await,
            cli::Command::HashPassword { password } => {
                println!("{}", crypto::hash_password(&password)?);
                Ok(())
            }
            cli::Command::RenderCompose { file, app, index } => {
                let text = std::fs::read_to_string(&file)?;
                let r = server::compose::render(&text, &app, index, &format!("/run/pocketcloud/env/{app}.env"))?;
                print!("{}", r.yaml);
                Ok(())
            }
        }
    })
}
