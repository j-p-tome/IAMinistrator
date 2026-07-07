// src/commands/user.rs
//
// Rust-native user commands for IAMinistrator.
//
// New additions derived from IntuneToolKit scripts by AliAlame
// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit):
//   - guest_audit()        ← Get-EntraGuestUserAudit.ps1
//   - license_report()     ← Get-EntraLicenseReport.ps1
//   - risky_users_report() ← Get-EntraRiskyUsers.ps1
//
// Required Microsoft Graph permissions per function:
//   guest_audit:        User.Read.All, AuditLog.Read.All, Directory.Read.All
//   guest_audit (stale-days path): +AuditLog.Read.All (signInActivity field)
//   license_report:     Organization.Read.All, User.Read.All, Directory.Read.All
//   risky_users_report: IdentityRiskyUser.Read.All
//   get_user_risk (existing): IdentityRiskyUser.Read.All

use crate::cli::UserCommands;
use anyhow::Result;
use colored::Colorize;
use crate::runtime::graph;
use crate::utils::output;

// ---------------------------------------------------------------------------
// User type model
// ---------------------------------------------------------------------------

/// Classification of an Entra ID user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserType {
    Member,
    Guest,
    Unknown(String),
}

impl UserType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "member" => Self::Member,
            "guest"  => Self::Guest,
            other    => Self::Unknown(other.to_owned()),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Member      => "Member",
            Self::Guest       => "Guest",
            Self::Unknown(s)  => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared user row helper
// ---------------------------------------------------------------------------

/// A lightweight, parsed user row shared between guest audit and license report.
pub struct UserRow {
    pub display_name:    String,
    pub upn:             String,
    pub mail:            String,
    pub created:         String,
    pub user_type:       UserType,
    pub account_enabled: bool,
}

/// Parse a Graph user JSON value into a UserRow.
/// Field set assumed: displayName, userPrincipalName, mail, createdDateTime,
/// userType, accountEnabled
pub fn parse_user_row(u: &serde_json::Value) -> UserRow {
    UserRow {
        display_name:    u["displayName"].as_str().unwrap_or("").to_owned(),
        upn:             u["userPrincipalName"].as_str().unwrap_or("").to_owned(),
        mail:            u["mail"].as_str().unwrap_or("").to_owned(),
        created:         u["createdDateTime"].as_str().unwrap_or("").to_owned(),
        user_type:       UserType::from_str(u["userType"].as_str().unwrap_or("")),
        account_enabled: u["accountEnabled"].as_bool().unwrap_or(false),
    }
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

pub fn handle(action: UserCommands) -> Result<()> {
    match action {
        UserCommands::Get { upn }              => get_user(&upn),
        UserCommands::Create { file }          => create_user(&file),
        UserCommands::RiskInfo { upn }         => get_user_risk(&upn),
        UserCommands::GuestAudit { stale_days } => guest_audit(stale_days),
        UserCommands::LicenseReport            => license_report(),
        UserCommands::RiskReport               => risky_users_report(),
    }
}

// ---------------------------------------------------------------------------
// Existing commands
// ---------------------------------------------------------------------------

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

/// Query Identity Protection for risk state, last risky sign-in date, and IP.
///
/// Endpoints used (requires IdentityRiskyUser.Read.All):
///   GET /identityProtection/riskyUsers?$filter=userPrincipalName eq '<upn>'
///         &$select=userPrincipalName,riskState,riskLevel,riskLastUpdatedDateTime
///   GET /identityProtection/riskDetections?$filter=userPrincipalName eq '<upn>'
///         &$orderby=activityDateTime desc&$top=1
///         &$select=activityDateTime,ipAddress,riskState,riskEventType
fn get_user_risk(upn: &str) -> Result<()> {
    println!("{} {}", "[user:risk-info]".cyan().bold(), upn);

    // --- 1. Risky user summary ------------------------------------------------
    let risky_users_path = format!(
        "/identityProtection/riskyUsers?$filter=userPrincipalName eq '{}'&$select=userPrincipalName,riskState,riskLevel,riskLastUpdatedDateTime",
        upn
    );

    let risky_resp = graph::get(&risky_users_path)?;
    let risky_entry = risky_resp["value"]
        .as_array()
        .and_then(|arr| arr.first().cloned());

    let (risk_state, risk_level, risk_last_updated) = match &risky_entry {
        Some(entry) => {
            let state   = entry["riskState"].as_str().unwrap_or("none").to_owned();
            let level   = entry["riskLevel"].as_str().unwrap_or("none").to_owned();
            let updated = entry["riskLastUpdatedDateTime"]
                .as_str()
                .unwrap_or("<unknown>")
                .to_owned();
            (state, level, updated)
        }
        None => ("none".to_owned(), "none".to_owned(), "<not found in Identity Protection>".to_owned()),
    };

    // --- 2. Last risky detection (sign-in date + IP) --------------------------
    let detections_path = format!(
        "/identityProtection/riskDetections?$filter=userPrincipalName eq '{}'&$orderby=activityDateTime desc&$top=1&$select=activityDateTime,ipAddress,riskState,riskEventType",
        upn
    );

    let det_resp  = graph::get(&detections_path)?;
    let det_entry = det_resp["value"]
        .as_array()
        .and_then(|arr| arr.first().cloned());

    let (last_risky_signin, last_risky_ip) = match &det_entry {
        Some(entry) => {
            let ts = entry["activityDateTime"].as_str().unwrap_or("<unknown>").to_owned();
            let ip = entry["ipAddress"].as_str().unwrap_or("<unknown>").to_owned();
            (ts, ip)
        }
        None => (
            "<no risky detections found>".to_owned(),
            "<no risky detections found>".to_owned(),
        ),
    };

    output::print_user_risk_info(
        upn,
        &risk_state,
        &risk_level,
        &risk_last_updated,
        &last_risky_signin,
        &last_risky_ip,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Guest audit  (primary implementation)
// ---------------------------------------------------------------------------
// Derived from Get-EntraGuestUserAudit.ps1 by AliAlame.
// Requires: User.Read.All, AuditLog.Read.All, Directory.Read.All
// When stale_days is Some(n): also requires AuditLog.Read.All for signInActivity.
//
// Endpoints:
//   GET /users?$filter=userType eq 'Guest'
//             &$select=id,userPrincipalName,displayName,mail,createdDateTime,
//                       externalUserState,accountEnabled,userType
//             [+ signInActivity when stale_days is set]
//
// signInActivity.lastSignInDateTime is only returned when explicitly $select-ed
// and requires AuditLog.Read.All. It is omitted when --stale-days is not given
// so the command works without that permission in the base case.

pub fn guest_audit(stale_days: Option<u64>) -> Result<()> {
    println!("{}", "Entra Guest User Audit".bold().underline());
    println!("Derived from Get-EntraGuestUserAudit.ps1 (IntuneToolKit by AliAlame)");

    // Compute the stale cutoff ISO-8601 string once (reused per-row below).
    let stale_cutoff: Option<String> = stale_days.map(|d| approx_days_ago_iso8601(d));
    if let Some(d) = stale_days {
        println!(
            "{} guests with no sign-in in the last {} days will be flagged as stale\n",
            "Note:".yellow().bold(),
            d
        );
    } else {
        println!();
    }

    // Build the $select list — include signInActivity only when --stale-days is set.
    // signInActivity is a complex type; it is included as a navigation property
    // and must be explicitly requested. Requires AuditLog.Read.All.
    let select_fields = if stale_cutoff.is_some() {
        "id,userPrincipalName,displayName,mail,createdDateTime,\
externalUserState,accountEnabled,userType,signInActivity"
    } else {
        "id,userPrincipalName,displayName,mail,createdDateTime,\
externalUserState,accountEnabled,userType"
    };

    let url = format!(
        "/users?$filter=userType eq 'Guest'&$select={select_fields}&$top=999"
    );
    let guests = graph::get_all(&url)?;

    // Column header — add LastSignIn column when --stale-days is active.
    if stale_cutoff.is_some() {
        println!(
            "{:<46} {:<32} {:<24} {:<8} {:<20} {:<8} {}",
            "UPN", "Mail", "Created", "Enabled", "InviteState", "Stale", "LastSignIn"
        );
        println!("{}", "-".repeat(160));
    } else {
        println!(
            "{:<50} {:<35} {:<24} {:<8} {:<20} {}",
            "UPN", "Mail", "Created", "Enabled", "InviteState", "UserType"
        );
        println!("{}", "-".repeat(145));
    }

    let mut disabled_count  = 0usize;
    let mut pending_count   = 0usize;
    let mut never_upn_count = 0usize;
    let mut stale_count     = 0usize;

    for u in &guests {
        let row          = parse_user_row(u);
        let invite_state = u["externalUserState"].as_str().unwrap_or("").to_owned();
        let created_short = &row.created[..row.created.len().min(24)];

        if !row.account_enabled {
            disabled_count += 1;
        }
        if invite_state.eq_ignore_ascii_case("PendingAcceptance") {
            pending_count += 1;
        }
        if row.upn.contains("#EXT#") {
            never_upn_count += 1;
        }

        let enabled_str = if row.account_enabled {
            "yes".green().to_string()
        } else {
            "no".red().to_string()
        };

        let invite_colored = match invite_state.as_str() {
            "Accepted"          => invite_state.green().to_string(),
            "PendingAcceptance" => invite_state.yellow().to_string(),
            _                   => invite_state.clone(),
        };

        if let Some(ref cutoff) = stale_cutoff {
            // Extract lastSignInDateTime from signInActivity complex type.
            // Graph returns: { "signInActivity": { "lastSignInDateTime": "...", ... } }
            let last_signin = u["signInActivity"]["lastSignInDateTime"]
                .as_str()
                .unwrap_or("");

            // A guest is stale if:
            //   - lastSignInDateTime is present and older than the cutoff, OR
            //   - lastSignInDateTime is absent (never signed in)
            let is_stale = last_signin.is_empty() || last_signin < cutoff.as_str();
            if is_stale {
                stale_count += 1;
            }

            let stale_str = if is_stale {
                "YES".red().to_string()
            } else {
                "no".dimmed().to_string()
            };

            let signin_display = if last_signin.is_empty() {
                "never".yellow().to_string()
            } else {
                last_signin[..last_signin.len().min(24)].to_string()
            };

            println!(
                "{:<46} {:<32} {:<24} {:<8} {:<20} {:<8} {}",
                truncate_str(&row.upn, 45),
                truncate_str(&row.mail, 31),
                created_short,
                enabled_str,
                invite_colored,
                stale_str,
                signin_display,
            );
        } else {
            println!(
                "{:<50} {:<35} {:<24} {:<8} {:<20} {}",
                truncate_str(&row.upn, 49),
                truncate_str(&row.mail, 34),
                created_short,
                enabled_str,
                invite_colored,
                row.user_type.label(),
            );
        }
    }

    let sep_width = if stale_cutoff.is_some() { 160 } else { 145 };
    println!("{}", "-".repeat(sep_width));
    println!("\nTotal guest users     : {}", guests.len());
    if disabled_count > 0 {
        println!("{}", format!("Disabled accounts     : {disabled_count}").red());
    }
    if pending_count > 0 {
        println!("{}", format!("Pending invitations   : {pending_count}").yellow());
    }
    println!("EXT# UPNs (no rename) : {}", never_upn_count);
    if let Some(d) = stale_days {
        if stale_count > 0 {
            println!(
                "{}",
                format!("Stale guests (>{d}d)   : {stale_count}").red()
            );
        } else {
            println!("Stale guests (>{d}d)   : 0");
        }
    }

    println!(
        "\n{}",
        "── Future expansion paths ──────────────────────────────────────────────────────────".dimmed()
    );
    println!(
        "{}",
        "  - --inactive-days N flag to surface guests inactive beyond threshold (uses signInActivity)".dimmed()
    );
    println!(
        "{}",
        "  - Correlate group membership count per guest (GroupMember.Read.All)".dimmed()
    );
    println!(
        "{}",
        "  - Export stale guest list to CSV for remediation workflow".dimmed()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// License report
// ---------------------------------------------------------------------------
// Derived from Get-EntraLicenseReport.ps1 by AliAlame.
// Requires: Organization.Read.All, User.Read.All, Directory.Read.All
//
// Endpoints:
//   GET /subscribedSkus
//       &$select=skuId,skuPartNumber,prepaidUnits,consumedUnits
//   GET /users?$select=id,userPrincipalName,displayName,accountEnabled,
//             assignedLicenses,userType

pub fn license_report() -> Result<()> {
    println!("{}", "Entra License Report".bold().underline());
    println!("Derived from Get-EntraLicenseReport.ps1 (IntuneToolKit by AliAlame)\n");

    // --- 1. SKU overview --------------------------------------------------------
    let skus = graph::get("/subscribedSkus")?;
    let sku_arr = skus["value"].as_array().cloned().unwrap_or_default();

    // Build skuId → skuPartNumber lookup
    let mut sku_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for sku in &sku_arr {
        if let (Some(id), Some(name)) = (
            sku["skuId"].as_str(),
            sku["skuPartNumber"].as_str(),
        ) {
            sku_map.insert(id.to_owned(), name.to_owned());
        }
    }

    println!("{}", "SKU Overview".bold());
    println!(
        "{:<42} {:>10} {:>10} {:>10} {:>7}",
        "SKU", "Purchased", "Consumed", "Available", "Util%"
    );
    println!("{}", "-".repeat(82));

    let mut total_purchased = 0i64;
    let mut total_consumed  = 0i64;

    let mut sorted_skus = sku_arr.clone();
    sorted_skus.sort_by(|a, b| {
        let an = a["skuPartNumber"].as_str().unwrap_or("");
        let bn = b["skuPartNumber"].as_str().unwrap_or("");
        an.cmp(bn)
    });

    for sku in &sorted_skus {
        let part  = sku["skuPartNumber"].as_str().unwrap_or("");
        let purch = sku["prepaidUnits"]["enabled"].as_i64().unwrap_or(0);
        let cons  = sku["consumedUnits"].as_i64().unwrap_or(0);
        let avail = purch - cons;
        let util  = if purch > 0 { cons * 100 / purch } else { 0 };

        total_purchased += purch;
        total_consumed  += cons;

        let util_str  = format!("{util}%");
        let avail_str = avail.to_string();

        let colored_util = if util >= 95 {
            util_str.red().to_string()
        } else if util >= 80 {
            util_str.yellow().to_string()
        } else if util < 50 && purch > 5 {
            util_str.yellow().to_string()
        } else {
            util_str.green().to_string()
        };

        let colored_avail = if avail < 0 {
            avail_str.red().to_string()
        } else {
            avail_str
        };

        println!(
            "{:<42} {:>10} {:>10} {:>10} {:>7}",
            truncate_str(part, 41),
            purch,
            cons,
            colored_avail,
            colored_util,
        );
    }

    println!("{}", "-".repeat(82));
    println!(
        "{:<42} {:>10} {:>10} {:>10}",
        "TOTALS",
        total_purchased,
        total_consumed,
        total_purchased - total_consumed,
    );

    // --- 2. User license analysis -----------------------------------------------
    println!("\n{}", "User License Analysis".bold());

    let users = graph::get_all(
        "/users\
         ?$select=id,userPrincipalName,displayName,accountEnabled,assignedLicenses,userType\
         &$top=999",
    )?;

    let mut licensed_count       = 0usize;
    let mut unlicensed_count     = 0usize;
    let mut disabled_licensed    = 0usize;
    let mut guest_licensed       = 0usize;
    let mut wasted_license_seats = 0usize;

    let mut disabled_rows: Vec<(String, String)> = Vec::new();

    for u in &users {
        let row      = parse_user_row(u);
        let licenses = u["assignedLicenses"].as_array().cloned().unwrap_or_default();
        let lic_count = licenses.len();

        if lic_count > 0 {
            licensed_count += 1;
            if !row.account_enabled {
                disabled_licensed += 1;
                wasted_license_seats += lic_count;
                let lic_names = licenses
                    .iter()
                    .map(|l| {
                        l["skuId"]
                            .as_str()
                            .and_then(|id| sku_map.get(id).map(|n| n.as_str()))
                            .unwrap_or("unknown")
                            .to_owned()
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                disabled_rows.push((row.upn.clone(), lic_names));
            }
            if row.user_type == UserType::Guest {
                guest_licensed += 1;
            }
        } else {
            unlicensed_count += 1;
        }
    }

    println!("\n  Total users                : {}", users.len());
    println!("  Licensed users             : {}", licensed_count);
    println!("  Unlicensed users           : {}", unlicensed_count);

    if disabled_licensed > 0 {
        println!(
            "  {}",
            format!(
                "Disabled with licenses     : {disabled_licensed} ({wasted_license_seats} wasted seats)"
            )
            .red()
        );
        for (upn, lics) in disabled_rows.iter().take(15) {
            println!("    {} {}", upn.yellow(), format!("| {lics}").dimmed());
        }
        if disabled_rows.len() > 15 {
            println!("    … and {} more", disabled_rows.len() - 15);
        }
    } else {
        println!("  Disabled with licenses     : 0");
    }

    if guest_licensed > 0 {
        println!(
            "  {}",
            format!("Guests with licenses       : {guest_licensed}").yellow()
        );
    } else {
        println!("  Guests with licenses       : 0");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Risky users report  (primary implementation; entra.rs delegates here)
// ---------------------------------------------------------------------------
// Derived from Get-EntraRiskyUsers.ps1 by AliAlame.
// Requires: IdentityRiskyUser.Read.All
//
// Endpoints:
//   GET /identityProtection/riskyUsers
//       ?$filter=riskLevel ne 'none' and riskState ne 'dismissed'
//       &$orderby=riskLevel desc
//   GET /identityProtection/riskDetections
//       ?$filter=detectedDateTime ge <14-days-ago>
//       &$top=200&$orderby=detectedDateTime desc

pub fn risky_users_report() -> Result<()> {
    println!("{}", "Entra Risky Users Report".bold().underline());
    println!("Derived from Get-EntraRiskyUsers.ps1 (IntuneToolKit by AliAlame)\n");

    // --- 1. Active risky users --------------------------------------------------
    let users = graph::get_all(
        "/identityProtection/riskyUsers\
         ?$filter=riskLevel ne 'none' and riskState ne 'dismissed'\
         &$orderby=riskLevel desc&$top=999",
    )?;

    let high_count   = users.iter().filter(|u| u["riskLevel"].as_str() == Some("high")).count();
    let medium_count = users.iter().filter(|u| u["riskLevel"].as_str() == Some("medium")).count();
    let low_count    = users.iter().filter(|u| u["riskLevel"].as_str() == Some("low")).count();

    println!(
        "  {} {}",
        "High risk  :".bold(),
        if high_count > 0 { high_count.to_string().red().to_string() } else { high_count.to_string() }
    );
    println!(
        "  {} {}",
        "Medium risk:".bold(),
        if medium_count > 0 { medium_count.to_string().yellow().to_string() } else { medium_count.to_string() }
    );
    println!("  {} {}", "Low risk   :".bold(), low_count);
    println!();

    println!(
        "{:<50} {:<10} {:<18} {:<26} {}",
        "UPN", "RiskLevel", "RiskState", "LastUpdated", "Detail"
    );
    println!("{}", "-".repeat(126));

    for u in &users {
        let upn     = u["userPrincipalName"].as_str().unwrap_or("").to_string();
        let level   = u["riskLevel"].as_str().unwrap_or("").to_string();
        let state   = u["riskState"].as_str().unwrap_or("").to_string();
        let updated = u["riskLastUpdatedDateTime"].as_str().unwrap_or("").to_string();
        let detail  = u["riskDetail"].as_str().unwrap_or("").to_string();

        let colored_level = match level.as_str() {
            "high"   => level.red().to_string(),
            "medium" => level.yellow().to_string(),
            "low"    => level.normal().to_string(),
            _        => level,
        };

        println!(
            "{:<50} {:<10} {:<18} {:<26} {}",
            truncate_str(&upn, 49),
            colored_level,
            state,
            &updated[..updated.len().min(26)],
            truncate_str(&detail, 40),
        );
    }

    println!("{}", "-".repeat(126));
    println!("\nTotal risky users (active): {}", users.len());

    // --- 2. Recent risk detections (14 days) ------------------------------------
    println!("\n{}", "Recent Risk Detections (14 days)".bold());

    let since = approx_days_ago_iso8601(14);
    let det_path = format!(
        "/identityProtection/riskDetections\
         ?$filter=detectedDateTime ge {since}\
         &$top=200\
         &$orderby=detectedDateTime desc"
    );
    let detections = match graph::get_all(&det_path) {
        Ok(d) => d,
        Err(_) => {
            println!("  (risk detections unavailable — verify IdentityRiskyUser.Read.All)");
            return Ok(());
        }
    };

    // Detection type breakdown
    let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for d in &detections {
        let t = d["riskEventType"].as_str().unwrap_or("unknown").to_owned();
        *type_counts.entry(t).or_insert(0) += 1;
    }
    let mut type_vec: Vec<(String, usize)> = type_counts.into_iter().collect();
    type_vec.sort_by(|a, b| b.1.cmp(&a.1));

    println!("  Detection types:");
    for (t, c) in &type_vec {
        println!("    {:<45} {}", t, c);
    }

    // Show top high-risk detections
    let high_dets: Vec<_> = detections
        .iter()
        .filter(|d| d["riskLevel"].as_str() == Some("high"))
        .take(10)
        .collect();

    if !high_dets.is_empty() {
        println!("\n  {}", "High-risk detections:".red().bold());
        println!(
            "  {:<40} {:<45} {:<18}",
            "UPN", "EventType", "IP"
        );
        println!("  {}", "-".repeat(106));
        for d in high_dets {
            let upn   = d["userPrincipalName"].as_str().unwrap_or("").to_string();
            let etype = d["riskEventType"].as_str().unwrap_or("").to_string();
            let ip    = d["ipAddress"].as_str().unwrap_or("-").to_string();
            println!(
                "  {:<40} {:<45} {:<18}",
                truncate_str(&upn, 39),
                truncate_str(&etype, 44),
                ip,
            );
        }
    }

    println!("\nTotal detections (14 days): {}", detections.len());

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Truncate a string to at most `max` chars, appending '\u{2026}' if needed.
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('\u{2026}');
        t
    }
}

/// Return ISO-8601 string for `days` days ago.
/// Uses std::time only — no chrono dependency.
pub fn approx_days_ago_iso8601(days: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(days * 86_400);
    unix_to_iso8601(secs)
}

fn unix_to_iso8601(secs: u64) -> String {
    let days_since_epoch = secs / 86_400;
    let time_of_day      = secs % 86_400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    let mut y = 1970u64;
    let mut d = days_since_epoch;
    loop {
        let diy = if is_leap(y) { 366 } else { 365 };
        if d < diy { break; }
        d -= diy;
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
