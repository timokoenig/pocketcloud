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
    /// Reach a server when the interface or VPN is down
    Rescue(RescueArgs),
    /// Upload a new binary to the server and restart the daemon
    Upgrade(UpgradeArgs),
    /// Print the WireGuard config of the device created during setup
    Vpn(VpnArgs),
    /// Switch nightly backups on or off, or derive the restic password for a manual restore
    Backup(BackupArgs),
    /// Print the argon2 hash of a password (for config files)
    #[command(hide = true)]
    HashPassword { password: String },
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
}

#[derive(Args)]
pub struct RescueArgs {
    /// Name of the installation
    pub name: String,
    #[command(subcommand)]
    pub command: RescueCommand,
}

#[derive(Subcommand)]
pub enum RescueCommand {
    /// Server status from the Hetzner API and reachability checks
    Status,
    /// Allow SSH from your current public IP in the cloud firewall
    OpenSsh,
    /// Remove the public SSH rule from the cloud firewall
    CloseSsh,
    /// Reboot the server through the Hetzner API
    Reboot,
    /// Open an SSH session (through the VPN if up, otherwise after open-ssh)
    Ssh,
    /// Restore the master key on the server from the recovery phrase
    RestoreKey,
}

#[derive(Args)]
pub struct UpgradeArgs {
    /// Name of the installation
    pub name: String,
    /// Linux binary to upload instead of downloading the release
    #[arg(long)]
    pub server_binary: Option<PathBuf>,
    /// Caddy binary (built with Coraza, scripts/build-caddy.sh) instead of downloading the release
    #[arg(long)]
    pub caddy_binary: Option<PathBuf>,
    /// Keep the Caddy that is installed
    #[arg(long)]
    pub skip_caddy: bool,
}

#[derive(Args)]
pub struct BackupArgs {
    /// Name of the installation
    pub name: String,
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Configure Hetzner Object Storage and start nightly backups
    Enable,
    /// Stop backups (snapshots stay in the bucket)
    Disable,
    /// Print the restic password derived from the recovery phrase, for restores without pocketcloud
    Password,
}

#[derive(Args)]
pub struct VpnArgs {
    /// Name of the installation
    pub name: String,
    /// Show as QR code
    #[arg(long)]
    pub qr: bool,
}
