use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "iam")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    User { #[command(subcommand)] action: UserCommands },
    Group { #[command(subcommand)] action: GroupCommands },
    Signin { #[command(subcommand)] action: SigninCommands },
    Error { code: String },
    Auth { #[command(subcommand)] action: AuthCommands },
}

#[derive(Subcommand)]
pub enum UserCommands { Get { upn: String }, Create { #[arg(short, long)] file: String } }
#[derive(Subcommand)]
pub enum GroupCommands { Diff { user1: String, user2: String }, Memberships { upn: String }, Add { upn: String, group: String } }
#[derive(Subcommand)]
pub enum SigninCommands { Bulk { #[arg(short, long)] file: String, #[arg(short, long, default_value = "50")] limit: u32 } }
#[derive(Subcommand)]
pub enum AuthCommands {
    /// Prompt for and store credentials in the OS keyring (overwrites existing entries).
    Set,
    /// Clear all stored credentials from the OS keyring, then re-prompt.
    Reset,
}
