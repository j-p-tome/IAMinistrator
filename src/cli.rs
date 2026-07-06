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
    /// PowerShell-backed utilities (IntuneToolKit, Entra reports, wrappers).
    Ps { #[command(subcommand)] action: PsCommands },
}

#[derive(Subcommand)]
pub enum UserCommands {
    Get { upn: String },
    Create { #[arg(short, long)] file: String },
    /// Show Identity Protection risk state, last risky sign-in date, and last risky sign-in IP.
    RiskInfo { upn: String },
}

#[derive(Subcommand)]
pub enum GroupCommands {
    Diff { user1: String, user2: String },
    Memberships { upn: String },
    Add { upn: String, group: String },
}

#[derive(Subcommand)]
pub enum SigninCommands {
    Bulk {
        #[arg(short, long)]
        file: String,
        #[arg(short, long, default_value = "50")]
        limit: u32,
    },
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Prompt for tenant_id and client_id and save to iam.toml beside the executable.
    Set,
    /// Delete iam.toml beside the executable (clears tenant_id and client_id).
    Reset,
}

#[derive(Subcommand)]
pub enum PsCommands {
    /// Minimal PowerShell-backed smoke test.
    Hello,
}
