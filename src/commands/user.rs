use crate::cli::UserCommands;
use anyhow::Result;
use colored::Colorize;

pub fn handle(action: UserCommands) -> Result<()> {
    match action {
        UserCommands::Get { upn } => get_user(&upn),
        UserCommands::Create { file } => create_user(&file),
    }
}

fn get_user(upn: &str) -> Result<()> {
    // TODO: call Graph API GET /users/{upn}
    println!("{} {}", "[user:get]".cyan().bold(), upn);
    Ok(())
}

fn create_user(file: &str) -> Result<()> {
    // TODO: parse JSON/CSV file and POST /users
    println!("{} from file: {}", "[user:create]".cyan().bold(), file);
    Ok(())
}
