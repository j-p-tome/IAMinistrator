use anyhow::Result;
use colored::Colorize;

#[derive(Debug)]
pub enum AuthCommands {
    /// Prompt for credentials and store them in the OS keyring.
    /// Does NOT clear existing entries first — use Reset to wipe and re-enter.
    Set,
    /// Clear all stored credentials from the OS keyring, then re-prompt.
    Reset,
}

pub fn handle(action: AuthCommands) -> Result<()> {
    match action {
        AuthCommands::Set => {
            println!(
                "{}",
                "[auth:set] prompting for credentials and storing in OS keyring"
                    .cyan()
                    .bold()
            );
            crate::runtime::auth::set_credentials()
        }
        AuthCommands::Reset => {
            println!(
                "{}",
                "[auth:reset] clearing stored credentials and prompting for fresh values"
                    .yellow()
                    .bold()
            );
            crate::runtime::auth::reset_credentials()
        }
    }
}
