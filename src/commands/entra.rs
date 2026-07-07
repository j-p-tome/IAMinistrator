// src/commands/entra.rs
//
// Rust-native Entra ID report commands for IAMinistrator.
//
// Derived from the following IntuneToolKit scripts by AliAlame
// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit):
//   - Get-EntraAdminRoleReport.ps1      → admin_roles()
//   - Get-EntraGuestUserAudit.ps1       → guest_audit()       [delegates to user::guest_audit]
//   - Get-EntraRiskyUsers.ps1           → risky_users()       [delegates to user::risky_users_report]
//   - Get-EntraCAReport.ps1             → ca_report()
//   - Get-EntraAppRegistrationAudit.ps1 → app_registration_audit()
//   - Get-EntraDirectoryAudit.ps1       → directory_audit()
//   - Get-EntraGroupAudit.ps1           → group_audit()       [delegates to group::run_audit]
// Translated and adapted for native Rust / Microsoft Graph REST API.

use anyhow::Result;
use colored::Colorize;

pub fn handle(action: crate::cli::EntraCommands) -> Result<()> {
    match action {
        crate::cli::EntraCommands::AdminRoles                        => admin_roles(),
        crate::cli::EntraCommands::GuestAudit { stale_days }        => crate::commands::user::guest_audit(stale_days),
        crate::cli::EntraCommands::RiskyUsers                        => crate::commands::user::risky_users_report(),
        crate::cli::EntraCommands::CaReport                          => ca_report(),
        crate::cli::EntraCommands::AppRegistrationAudit              => app_registration_audit(),
        crate::cli::EntraCommands::DirectoryAudit { limit }          => directory_audit(limit),
        crate::cli::EntraCommands::GroupAudit                        => crate::commands::group::run_audit(),
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
        let role_def  = a["roleDefinitionId"].as_str().unwrap_or("").to_string();
        let scope     = a["directoryScopeId"].as_str().unwrap_or("").to_string();
        println!("{:<40} {:<50} {:<20}", principal, role_def, scope);
    }

    println!("\nTotal assignments: {}", assignments.len());
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
        let name  = p["displayName"].as_str().unwrap_or("").to_string();
        let state = p["state"].as_str().unwrap_or("").to_string();
        let colored_state = match state.as_str() {
            "enabled"                          => state.green().to_string(),
            "disabled"                         => state.red().to_string(),
            "enabledForReportingButNotEnforced" => state.yellow().to_string(),
            _                                  => state,
        };
        println!("{:<55} {:<12}", name, colored_state);
    }

    println!("\nTotal CA policies: {}", policies.len());
    Ok(())
}

/// Derived from Get-EntraAppRegistrationAudit.ps1 by AliAlame.
/// Lists all app registrations with credential expiry awareness.
/// Requires: Application.Read.All
fn app_registration_audit() -> Result<()> {
    let apps = crate::runtime::graph::get_all(
        "/applications\
         ?$select=displayName,appId,signInAudience,\
passwordCredentials,keyCredentials,createdDateTime\
         &$top=999",
    )?;

    println!("{}", "Entra App Registration Audit".bold().underline());
    println!(
        "{:<45} {:<38} {:<22} {:<8} {:<8} {:<24}",
        "DisplayName", "AppId", "SignInAudience", "Secrets", "Certs", "Created"
    );
    println!("{}", "-".repeat(150));

    let mut expired = 0usize;
    let mut expiring_soon = 0usize;

    for app in &apps {
        let name     = app["displayName"].as_str().unwrap_or("").to_string();
        let app_id   = app["appId"].as_str().unwrap_or("").to_string();
        let audience = app["signInAudience"].as_str().unwrap_or("").to_string();
        let created  = app["createdDateTime"].as_str().unwrap_or("").to_string();

        let secrets = app["passwordCredentials"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0);
        let certs = app["keyCredentials"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0);

        if let Some(creds) = app["passwordCredentials"].as_array() {
            for cred in creds {
                if let Some(exp_str) = cred["endDateTime"].as_str() {
                    let now_approx = chrono_approx_now();
                    let in_30_days = chrono_approx_days(30);
                    if exp_str < now_approx.as_str() {
                        expired += 1;
                    } else if exp_str < in_30_days.as_str() {
                        expiring_soon += 1;
                    }
                }
            }
        }

        println!(
            "{:<45} {:<38} {:<22} {:<8} {:<8} {:<24}",
            truncate(&name, 44),
            app_id,
            truncate(&audience, 21),
            secrets,
            certs,
            &created[..created.len().min(24)],
        );
    }

    println!("\nTotal app registrations : {}", apps.len());
    if expired > 0 {
        println!("{}", format!("Expired credentials     : {expired}").red());
    }
    if expiring_soon > 0 {
        println!("{}", format!("Expiring within 30 days : {expiring_soon}").yellow());
    }
    Ok(())
}

/// Derived from Get-EntraDirectoryAudit.ps1 by AliAlame.
/// Surfaces recent directory audit log entries.
/// Requires: AuditLog.Read.All, Directory.Read.All
fn directory_audit(limit: u32) -> Result<()> {
    let top = limit.min(200);
    let url = format!(
        "/auditLogs/directoryAudits\
         ?$select=activityDateTime,category,activityDisplayName,\
initiatedBy,targetResources,result\
         &$orderby=activityDateTime desc\
         &$top={top}"
    );

    let entries = crate::runtime::graph::get_all(&url)?;

    println!("{}", "Entra Directory Audit Log".bold().underline());
    println!(
        "{:<26} {:<18} {:<40} {:<40} {:<30} {:<8}",
        "DateTime", "Category", "Activity", "InitiatorUPN", "TargetResource", "Result"
    );
    println!("{}", "-".repeat(166));

    for e in &entries {
        let dt       = e["activityDateTime"].as_str().unwrap_or("").to_string();
        let category = e["category"].as_str().unwrap_or("").to_string();
        let activity = e["activityDisplayName"].as_str().unwrap_or("").to_string();
        let result   = e["result"].as_str().unwrap_or("").to_string();

        let initiator = e["initiatedBy"]["user"]["userPrincipalName"]
            .as_str()
            .or_else(|| e["initiatedBy"]["app"]["displayName"].as_str())
            .unwrap_or("")
            .to_string();

        let target = e["targetResources"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|t| t["displayName"].as_str())
            .unwrap_or("")
            .to_string();

        let colored_result = match result.as_str() {
            "success" => result.green().to_string(),
            "failure" => result.red().to_string(),
            _         => result,
        };

        println!(
            "{:<26} {:<18} {:<40} {:<40} {:<30} {:<8}",
            &dt[..dt.len().min(26)],
            truncate(&category, 17),
            truncate(&activity, 39),
            truncate(&initiator, 39),
            truncate(&target, 29),
            colored_result,
        );
    }

    println!("\nEntries shown: {}", entries.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers (kept local to entra.rs; identical copies exist in user.rs)
// ---------------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('\u{2026}');
        t
    }
}

fn chrono_approx_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_iso8601(secs)
}

fn chrono_approx_days(days: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + days * 86_400;
    unix_to_iso8601(secs)
}

fn unix_to_iso8601(secs: u64) -> String {
    let s = secs;
    let days_since_epoch = s / 86_400;
    let time_of_day = s % 86_400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    let mut y = 1970u64;
    let mut d = days_since_epoch;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if d < days_in_year { break; }
        d -= days_in_year;
        y += 1;
    }
    let month_days: [u64; 12] = [
        31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mo = 0usize;
    for &md in &month_days {
        if d < md { break; }
        d -= md;
        mo += 1;
    }
    format!("{y:04}-{:02}-{:02}T{hh:02}:{mm:02}:{ss:02}Z", mo + 1, d + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
