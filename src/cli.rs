use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pocketcloud", version, about = "Your own small cloud on one Hetzner server")]
pub struct Cli {
    /// Debug output
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Provision a new server (interactive, runs on your machine)
    Setup(SetupArgs),
    /// Run the daemon on the server
    Server(ServerArgs),
    /// From Hetzner's rescue system: prove the recovery phrase, add a VPN device, optionally reset the password
    Recover(RecoverArgs),
    /// The restic password of an installation from its recovery phrase, for a restore with plain restic
    ResticPassword,
    /// Print the argon2 hash of a password (for config files)
    #[command(hide = true)]
    HashPassword { password: String },
    /// Print the recovery phrase of a master key given as hex (testing)
    #[command(hide = true)]
    KeyPhrase { hex: String },
    /// Render a compose file the way the server would (debugging)
    #[command(hide = true)]
    RenderCompose {
        file: PathBuf,
        #[arg(default_value = "app")]
        app: String,
        #[arg(default_value_t = 1)]
        index: u32,
    },
}

#[derive(Args)]
pub struct SetupArgs {
    /// Name of the installation (directory under ~/.config/pocketcloud)
    pub name: String,
    /// Linux binary to install on the server instead of downloading the release
    #[arg(long)]
    pub server_binary: Option<PathBuf>,
    /// Caddy binary (built with Coraza, scripts/build-caddy.sh) instead of downloading the release
    #[arg(long)]
    pub caddy_binary: Option<PathBuf>,
    /// Answer yes to confirmations
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct ServerArgs {
    /// Config file
    #[arg(long, default_value = "/etc/pocketcloud/config.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<ServerCommand>,
}

#[derive(Subcommand)]
pub enum ServerCommand {
    /// Run the daemon (default)
    Run,
    /// Print the nftables ruleset that would be applied
    Firewall,
    /// Apply system configuration once (firewall, wireguard, caddy) and exit
    Apply,
    /// Reset the password of the interface user
    Passwd { username: String },
    /// Run a backup now and wait for it (same job the interface starts)
    Backup,
    /// Restore an app's data from a snapshot ("latest" or an id) and wait for it
    Restore { app: String, snapshot: String },
    /// Send a test notification through the configured channels
    NotifyTest,
    /// Request new certificates now and wait (same job the interface starts)
    Renew,
    /// Upgrade pocketcloud and Caddy to a release (the newest by default) or from staged binaries
    Upgrade {
        /// Release version, e.g. 0.2.0; empty for the newest
        #[arg(long, default_value = "")]
        version: String,
        /// Use binaries from this directory (pocketcloud, caddy) instead of downloading
        #[arg(long)]
        from_dir: Option<PathBuf>,
    },
    /// Hand ssh over to the interface: from now on authorized_keys holds only the keys added there
    SshFinish,
    /// Add a VPN device and print its WireGuard config (and a QR code): the way back in when every device is lost
    VpnAdd {
        /// Device name
        name: String,
        /// full (everything) or web (interface and internal routes only)
        #[arg(long, default_value = "full")]
        scope: String,
    },
}

#[derive(Args)]
pub struct RecoverArgs {
    /// Where the server's disk is mounted
    #[arg(long, default_value = "/mnt")]
    pub root: String,
}

