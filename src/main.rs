mod cli;
mod commands;
mod runtime;
mod utils;

use clap::Parser;
use cli::{Cli, Commands};
use anyhow::Result;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::User { action } => commands::user::handle(action)?,
        Commands::Group { action } => commands::group::handle(action)?,
        Commands::Signin { action } => commands::signin::handle(action)?,
        Commands::Error { code } => commands::error::lookup(&code)?,
    }
    Ok(())
}

