mod cli;
mod commands;
mod runtime;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::User { action } => commands::user::handle(action)?,
        Commands::Group { action } => commands::group::handle(action)?,
        Commands::Signin { action } => commands::signin::handle(action)?,
        Commands::Error { code } => commands::error::lookup(&code)?,
        Commands::Auth { action } => {
            let mapped = match action {
                cli::AuthCommands::Set => commands::auth::AuthCommands::Set,
            };
            commands::auth::handle(mapped)?
        }
    }
    Ok(())
}
