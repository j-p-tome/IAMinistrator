use anyhow::Result;
use colored::Colorize;

#[derive(Debug)]
pub enum AuthCommands {
    /// Prompt for tenant_id and client_id and save them to iam.toml beside the executable.
    /// client_secret is never stored; it will be prompted at runtime.
    Set,
    /// Delete iam.toml beside the executable, clearing tenant_id and client_id.
    Reset,
}

pub fn handle(action: AuthCommands) -> Result<()> {
    match action {
        AuthCommands::Set => {
            println!(
                "{}",
                "[auth:set] prompting for tenant_id and client_id; saving to config file beside executable"
                    .cyan()
                    .bold()
            );
            crate::runtime::auth::set_credentials()
        }
        AuthCommands::Reset => {
            println!(
                "{}",
                "[auth:reset] deleting config file (iam.toml beside executable)"
                    .yellow()
                    .bold()
            );
            crate::runtime::auth::reset_credentials()
        }
    }
}
