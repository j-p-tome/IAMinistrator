use anyhow::Result;
use colored::Colorize;

#[derive(Debug)]
pub enum AuthCommands {
    Set,
}

pub fn handle(action: AuthCommands) -> Result<()> {
    match action {
        AuthCommands::Set => {
            println!(
                "{}",
                "[auth:set] clearing stored credentials and prompting"
                    .cyan()
                    .bold()
            );
            crate::runtime::auth::reset_credentials()
        }
    }
}
