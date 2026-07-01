use crate::cli::GroupCommands;
use anyhow::Result;
use colored::Colorize;

pub fn handle(action: GroupCommands) -> Result<()> {
    match action {
        GroupCommands::Diff { user1, user2 } => diff_groups(&user1, &user2),
        GroupCommands::Memberships { upn } => list_memberships(&upn),
        GroupCommands::Add { upn, group } => add_to_group(&upn, &group),
    }
}

fn diff_groups(user1: &str, user2: &str) -> Result<()> {
    // TODO: GET /users/{id}/memberOf for each user, diff the results
    println!(
        "{} comparing {} vs {}",
        "[group:diff]".cyan().bold(),
        user1,
        user2
    );
    Ok(())
}

fn list_memberships(upn: &str) -> Result<()> {
    // TODO: GET /users/{upn}/memberOf
    println!("{} {}", "[group:memberships]".cyan().bold(), upn);
    Ok(())
}

fn add_to_group(upn: &str, group: &str) -> Result<()> {
    // TODO: POST /groups/{id}/members/$ref
    println!(
        "{} adding {} to {}",
        "[group:add]".cyan().bold(),
        upn,
        group
    );
    Ok(())
}
