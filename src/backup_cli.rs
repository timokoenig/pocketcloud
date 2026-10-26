//! `pocketcloud backup <name> password`: the restic password derived from the recovery phrase, for restoring
//! a backup with plain restic when no server is left. Backups themselves are configured in the interface.
use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input};

use crate::cli::{BackupArgs, BackupCommand};
use crate::crypto::MasterKey;
use crate::install::Installation;

pub async fn run(args: BackupArgs) -> Result<()> {
    let _ = Installation::load(&args.name)?;
    match args.command {
        BackupCommand::Password => {
            let phrase: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Recovery phrase (24 words)").interact_text()?;
            let key = MasterKey::from_phrase(&phrase)?;
            println!("export RESTIC_PASSWORD={}", *key.derive("restic"));
            println!("# plus RESTIC_REPOSITORY=s3:<endpoint>/<bucket>, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY of the bucket; then: restic snapshots");
            Ok(())
        }
    }
}
