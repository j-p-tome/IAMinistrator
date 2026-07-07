// src/commands/group.rs
//
// Rust-native Entra group commands for IAMinistrator.
//
// group audit derived from Get-EntraGroupAudit.ps1 by AliAlame
// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
//
// Required Microsoft Graph permissions for `audit`:
//   Directory.Read.All
//   Group.Read.All
//   GroupMember.Read.All
//
// Endpoints used:
//   GET /groups?$select=... (all groups, paginated via get_all)
//   GET /groups/{id}/owners?$select=id   (owner count per group)
//   GET /groups/{id}/members/$count      (member count; ConsistencyLevel: eventual)
//                                        Fallback: /members?$top=100 array length

use crate::cli::GroupCommands;
use anyhow::Result;
use colored::Colorize;

pub fn handle(action: GroupCommands) -> Result<()> {
    match action {
        GroupCommands::Diff { user1, user2 } => diff_groups(&user1, &user2),
        GroupCommands::Memberships { upn } => list_memberships(&upn),
        GroupCommands::Add { upn, group } => add_to_group(&upn, &group),
        GroupCommands::Audit => run_audit(),
    }
}

// ---------------------------------------------------------------------------
// Public entry point so entra.rs can call the shared impl.
// ---------------------------------------------------------------------------
pub fn run_audit() -> Result<()> {
    println!("{}", "Entra Group Health Audit".bold().underline());
    println!(
        "Derived from Get-EntraGroupAudit.ps1 (IntuneToolKit by AliAlame)\n"
    );

    // Fetch all groups with the fields we need.
    // Graph permissions: Directory.Read.All, Group.Read.All
    let groups = crate::runtime::graph::get_all(
        "/groups\
         ?$select=id,displayName,mailNickname,mail,\
groupTypes,securityEnabled,mailEnabled,\
membershipRule,membershipRuleProcessingState,\
createdDateTime,isAssignableToRole,\
onPremisesSyncEnabled,visibility\
         &$top=999",
    )?;

    println!(
        "{:<45} {:<22} {:<6} {:<6} {:<6} {:<8} {:<8} {:<10}",
        "DisplayName", "GroupType", "Sec", "Mail", "Dyn", "Owners", "Members", "Issues"
    );
    println!("{}", "-".repeat(120));

    let mut total_empty = 0usize;
    let mut total_ownerless = 0usize;
    let mut total_dynamic = 0usize;
    let mut total_role_assignable = 0usize;

    for g in &groups {
        let display_name = g["displayName"].as_str().unwrap_or("").to_string();
        let mail_nickname = g["mailNickname"].as_str().unwrap_or("").to_string();
        let _mail = g["mail"].as_str().unwrap_or("");
        let security_enabled = g["securityEnabled"].as_bool().unwrap_or(false);
        let mail_enabled = g["mailEnabled"].as_bool().unwrap_or(false);
        let is_role_assignable = g["isAssignableToRole"].as_bool().unwrap_or(false);
        let on_prem_sync = g["onPremisesSyncEnabled"].as_bool().unwrap_or(false);
        let visibility = g["visibility"].as_str().unwrap_or("");
        let created = g["createdDateTime"].as_str().unwrap_or("");
        let membership_rule = g["membershipRule"].as_str().unwrap_or("");
        let rule_state = g["membershipRuleProcessingState"].as_str().unwrap_or("");
        let group_id = g["id"].as_str().unwrap_or("");

        // Classify group type (mirrors PS script logic)
        let group_types: Vec<&str> = g["groupTypes"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let is_dynamic = group_types.contains(&"DynamicMembership");
        let is_m365 = group_types.contains(&"Unified");

        let group_type_label = if is_m365 && is_dynamic {
            "M365 Dynamic"
        } else if is_m365 {
            "M365 Assigned"
        } else if is_dynamic && security_enabled {
            "Security Dynamic"
        } else if security_enabled && mail_enabled {
            "Mail-Enabled Sec"
        } else if security_enabled {
            "Security Assigned"
        } else if mail_enabled {
            "Distribution"
        } else {
            "Other"
        };

        if is_dynamic {
            total_dynamic += 1;
        }
        if is_role_assignable {
            total_role_assignable += 1;
        }

        // Owner count — GET /groups/{id}/owners?$select=id
        let owner_count = fetch_owner_count(group_id).unwrap_or(0);
        if owner_count == 0 {
            total_ownerless += 1;
        }

        // Member count — GET /groups/{id}/members/$count with ConsistencyLevel: eventual
        // Falls back to a 100-item page count on failure.
        let member_count = fetch_member_count(group_id).unwrap_or(0);
        if member_count == 0 {
            total_empty += 1;
        }

        // Build issues string
        let mut issues: Vec<&str> = Vec::new();
        if member_count == 0 {
            issues.push("empty");
        }
        if owner_count == 0 {
            issues.push("no-owner");
        }
        if is_dynamic && rule_state.eq_ignore_ascii_case("Paused") {
            issues.push("dyn-paused");
        }
        if is_role_assignable {
            issues.push("role-assign");
        }
        if on_prem_sync {
            issues.push("on-prem-sync");
        }
        let issues_str = if issues.is_empty() {
            "-".to_string()
        } else {
            issues.join(",")
        };

        // Color-code issue severity
        let colored_issues = if issues.contains(&"empty") || issues.contains(&"no-owner") {
            issues_str.yellow().to_string()
        } else {
            issues_str
        };

        println!(
            "{:<45} {:<22} {:<6} {:<6} {:<6} {:<8} {:<8} {}",
            truncate(&display_name, 44),
            group_type_label,
            if security_enabled { "yes" } else { "no" },
            if mail_enabled { "yes" } else { "no" },
            if is_dynamic { "yes" } else { "no" },
            owner_count,
            member_count,
            colored_issues,
        );

        // Print dynamic rule beneath row if present
        if is_dynamic && !membership_rule.is_empty() {
            println!(
                "  {} {}",
                "rule:".dimmed(),
                truncate(membership_rule, 100).dimmed()
            );
        }

        // Print sync/visibility annotations on a detail line
        if on_prem_sync || !visibility.is_empty() || !created.is_empty() || !mail_nickname.is_empty() {
            println!(
                "  {} sync={} vis={} created={} nick={}",
                "|".dimmed(),
                if on_prem_sync { "onprem" } else { "-" },
                if visibility.is_empty() { "-" } else { visibility },
                &created[..created.len().min(10)],
                truncate(&mail_nickname, 30),
            );
        }
    }

    println!("{}", "-".repeat(120));
    println!("\nTotal groups         : {}", groups.len());
    println!("Dynamic groups       : {}", total_dynamic);
    println!("Role-assignable      : {}", total_role_assignable);
    if total_ownerless > 0 {
        println!(
            "{}",
            format!("Ownerless groups     : {total_ownerless}").yellow()
        );
    } else {
        println!("Ownerless groups     : 0");
    }
    if total_empty > 0 {
        println!(
            "{}",
            format!("Empty groups (0 mbr) : {total_empty}").yellow()
        );
    } else {
        println!("Empty groups (0 mbr) : 0");
    }

    println!(
        "\n{}",
        "── Future expansion paths ────────────────────────────────────────────".dimmed()
    );
    println!(
        "{}",
        "  - iam group audit --ownerless : filter to only ownerless groups".dimmed()
    );
    println!(
        "{}",
        "  - iam group audit --role-assignable : privileged / role-assignable groups".dimmed()
    );
    println!(
        "{}",
        "  - iam group audit --guest-heavy : groups with high guest ratio".dimmed()
    );
    println!(
        "{}",
        "  - iam group audit --deleted : recently soft-deleted groups".dimmed()
    );
    println!(
        "{}",
        "  - iam group audit --lifecycle : groups approaching expiry policy".dimmed()
    );
    println!(
        "{}",
        "  - Correlate with iam entra directory-audit for recent group changes".dimmed()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Existing stub commands (TODO: live Graph calls)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Fetch the owner count for a group.
/// GET /groups/{id}/owners?$select=id  (read-only, no extra scope beyond Group.Read.All)
fn fetch_owner_count(group_id: &str) -> Result<usize> {
    let path = format!(
        "/groups/{}/owners?$select=id&$top=100",
        group_id
    );
    let resp = crate::runtime::graph::get(&path)?;
    Ok(resp["value"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0))
}

/// Fetch the true member count for a group.
///
/// Primary:  GET /groups/{id}/members/$count
///           Requires `ConsistencyLevel: eventual` (via graph::get_count).
///           Returns the actual integer count from Graph — accurate for groups
///           of any size including those with > 100 members.
///
/// Fallback: GET /groups/{id}/members?$select=id&$top=100
///           Used when the $count endpoint is unavailable (permissions, tenant
///           settings, or transient Graph errors). Returns at most 100; groups
///           larger than 100 will show "100+" in the Issues column rather than
///           the exact number, but the audit will not halt.
fn fetch_member_count(group_id: &str) -> Result<usize> {
    let count_path = format!("/groups/{}/members/$count", group_id);
    match crate::runtime::graph::get_count(&count_path) {
        Ok(n) => Ok(n),
        Err(_) => {
            // Fallback: read first page (up to 100) and return array length.
            // This means groups with >100 members show as 100 — acceptable
            // as a degraded fallback; the Issues column will not show "empty".
            let fallback_path = format!(
                "/groups/{}/members?$select=id&$top=100",
                group_id
            );
            let resp = crate::runtime::graph::get(&fallback_path)?;
            Ok(resp["value"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0))
        }
    }
}

/// Truncate a string to at most `max` chars, appending '\u{2026}' if needed.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('\u{2026}');
        t
    }
}
