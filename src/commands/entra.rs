// src/commands/entra.rs
//
// Rust-native Entra ID report commands for IAMinistrator.
//
// Derived from the following IntuneToolKit scripts by AliAlame
// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit):
//   - Get-EntraAdminRoleReport.ps1
//   - Get-EntraGuestUserAudit.ps1
//   - Get-EntraRiskyUsers.ps1
//   - Get-EntraCAReport.ps1
// Translated and adapted for native Rust / Microsoft Graph REST API.

use anyhow::Result;
use colored::Colorize;

pub fn handle(action: crate::cli::EntraCommands) -> Result<()> {
    match action {
        crate::cli::EntraCommands::AdminRoles => admin_roles(),
        crate::cli::EntraCommands::GuestAudit => guest_audit(),
        crate::cli::EntraCommands::RiskyUsers => risky_users(),
        crate::cli::EntraCommands::CaReport => ca_report(),
    }
}

/// Derived from Get-EntraAdminRoleReport.ps1 by AliAlame.
/// Requires: RoleManagement.Read.Directory
fn admin_roles() -> Result<()> {
    // Graph v1.0 roleManagement/directory/roleAssignments does not support $expand
    // on both principal and roleDefinition in a single call; fetch assignments then
    // resolve role definitions separately.
    let assignments =
        crate::runtime::graph::get_all("/roleManagement/directory/roleAssignments?$top=999")?;

    println!("{}", "Entra Admin Role Assignments".bold().underline());
    println!(
        "{:<40} {:<50} {:<20}",
        "PrincipalId", "RoleDefinitionId", "DirectoryScopeId"
    );
    println!("{}", "-".repeat(112));

    for a in &assignments {
        let principal = a["principalId"].as_str().unwrap_or("").to_string();
        let role_def = a["roleDefinitionId"].as_str().unwrap_or("").to_string();
        let scope = a["directoryScopeId"].as_str().unwrap_or("").to_string();
        println!("{:<40} {:<50} {:<20}", principal, role_def, scope);
    }

    println!("\nTotal assignments: {}", assignments.len());
    Ok(())
}

/// Derived from Get-EntraGuestUserAudit.ps1 by AliAlame.
/// Requires: User.Read.All
fn guest_audit() -> Result<()> {
    let users = crate::runtime::graph::get_all(
        "/users?$filter=userType eq 'Guest'\
         &$select=displayName,mail,userPrincipalName,createdDateTime\
         &$top=999",
    )?;

    println!("{}", "Entra Guest User Audit".bold().underline());
    println!(
        "{:<50} {:<45} {:<24}",
        "UPN", "Mail", "Created"
    );
    println!("{}", "-".repeat(120));

    for u in &users {
        let upn = u["userPrincipalName"].as_str().unwrap_or("").to_string();
        let mail = u["mail"].as_str().unwrap_or("").to_string();
        let created = u["createdDateTime"].as_str().unwrap_or("").to_string();
        println!("{:<50} {:<45} {:<24}", upn, mail, created);
    }

    println!("\nTotal guest users: {}", users.len());
    Ok(())
}

/// Derived from Get-EntraRiskyUsers.ps1 by AliAlame.
/// Requires: IdentityRiskyUser.Read.All
fn risky_users() -> Result<()> {
    let users = crate::runtime::graph::get_all(
        "/identityProtection/riskyUsers\
         ?$filter=riskLevel ne 'none' and riskState ne 'dismissed'\
         &$orderby=riskLevel desc&$top=999",
    )?;

    println!("{}", "Entra Risky Users".bold().underline());
    println!(
        "{:<50} {:<10} {:<18} {:<26}",
        "UPN", "RiskLevel", "RiskState", "LastUpdated"
    );
    println!("{}", "-".repeat(106));

    for u in &users {
        let upn = u["userPrincipalName"].as_str().unwrap_or("").to_string();
        let level = u["riskLevel"].as_str().unwrap_or("").to_string();
        let state = u["riskState"].as_str().unwrap_or("").to_string();
        let updated = u["riskLastUpdatedDateTime"].as_str().unwrap_or("").to_string();

        let colored_level = match level.as_str() {
            "high"   => level.red().to_string(),
            "medium" => level.yellow().to_string(),
            "low"    => level.normal().to_string(),
            _        => level,
        };
        println!("{:<50} {:<10} {:<18} {:<26}", upn, colored_level, state, updated);
    }

    println!("\nTotal risky users: {}", users.len());
    Ok(())
}

/// Derived from Get-EntraCAReport.ps1 by AliAlame.
/// Requires: Policy.Read.All
fn ca_report() -> Result<()> {
    let policies = crate::runtime::graph::get_all(
        "/identity/conditionalAccess/policies\
         ?$select=id,displayName,state\
         &$top=999",
    )?;

    println!("{}", "Conditional Access Policy Report".bold().underline());
    println!("{:<55} {:<12}", "Policy Name", "State");
    println!("{}", "-".repeat(68));

    for p in &policies {
        let name = p["displayName"].as_str().unwrap_or("").to_string();
        let state = p["state"].as_str().unwrap_or("").to_string();
        let colored_state = match state.as_str() {
            "enabled" => state.green().to_string(),
            "disabled" => state.red().to_string(),
            "enabledForReportingButNotEnforced" => state.yellow().to_string(),
            _ => state,
        };
        println!("{:<55} {:<12}", name, colored_state);
    }

    println!("\nTotal CA policies: {}", policies.len());
    Ok(())
}
