use crate::cli::SigninCommands;
use anyhow::Result;
use colored::Colorize;

pub fn handle(action: SigninCommands) -> Result<()> {
    match action {
        SigninCommands::Bulk { file, limit } => bulk_signin_audit(&file, limit),
    }
}

fn bulk_signin_audit(file: &str, limit: u32) -> Result<()> {
    // TODO: read UPN list from file, query GET /users/{upn}/signInActivity per user
    //       respect limit to avoid throttling
    println!(
        "{} auditing from '{}' (limit: {})",
        "[signin:bulk]".cyan().bold(),
        file,
        limit
    );
    Ok(())
}
