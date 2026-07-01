use crate::cli::UserCommands;
use anyhow::Result;
use colored::Colorize;
use crate::runtime::graph;
use crate::utils::output;

pub fn handle(action: UserCommands) -> Result<()> {
    match action {
        UserCommands::Get { upn } => get_user(&upn),
        UserCommands::Create { file } => create_user(&file),
    }
}

fn get_user(upn: &str) -> Result<()> {
    println!("{} {}", "[user:get]".cyan().bold(), upn);

    let path = format!(
        "/users/{}?$select=displayName,userPrincipalName,mail,otherMails,proxyAddresses,lastPasswordChangeDateTime",
        upn
    );

    let user = graph::get(&path)?;
    output::print_user_details(&user);

    Ok(())
}

fn create_user(file: &str) -> Result<()> {
    println!(
        "{} from file: {}",
        "[user:create]".cyan().bold(),
        file
    );
    // TODO: read JSON payload and call graph::post("/users", &payload)
    Ok(())
}
