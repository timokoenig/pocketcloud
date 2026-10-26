mod cli;
mod cloudinit;
mod crypto;
mod dnsrecords;
mod firewall;
mod hetzner;
mod install;
mod recover;
mod release;
mod remote;
mod server;
mod setup;
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
            cli::Command::Recover(a) => recover::run(a).await,
            cli::Command::ResticPassword => {
                let phrase: String = dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default()).with_prompt("Recovery phrase (24 words)").interact_text()?;
                let key = crypto::MasterKey::from_phrase(&phrase)?;
                println!("export RESTIC_PASSWORD={}", *key.derive("restic"));
                println!("# plus RESTIC_REPOSITORY=s3:<endpoint>/<bucket>, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY of the bucket; then: restic snapshots");
                Ok(())
            }
            cli::Command::KeyPhrase { hex } => {
                println!("{}", *crypto::MasterKey::from_hex(&hex)?.phrase());
                Ok(())
            }
            cli::Command::HashPassword { password } => {
                println!("{}", crypto::hash_password(&password)?);
                Ok(())
            }
            cli::Command::RenderCompose { file, app, index } => {
                let text = std::fs::read_to_string(&file)?;
                let r = server::compose::render(&text, &app, index, "/run/pocketcloud/env")?;
                print!("{}", r.yaml);
                Ok(())
            }
        }
    })
}
