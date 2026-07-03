use crate::cli::UserCommands;
use anyhow::Result;
use colored::Colorize;
use crate::runtime::graph;
use crate::utils::output;

pub fn handle(action: UserCommands) -> Result<()> {
    match action {
        UserCommands::Get { upn } => get_user(&upn),
        UserCommands::Create { file } => create_user(&file),
        UserCommands::RiskInfo { upn } => get_user_risk(&upn),
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

/// Query Identity Protection for risk state, last risky sign-in date, and IP.
///
/// Endpoints used (requires IdentityRiskEvents.Read.All or IdentityRiskyUser.Read.All):
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
            let state = entry["riskState"].as_str().unwrap_or("none").to_owned();
            let level = entry["riskLevel"].as_str().unwrap_or("none").to_owned();
            let updated = entry["riskLastUpdatedDateTime"]
                .as_str()
                .unwrap_or("<unknown>")
                .to_owned();
            (state, level, updated)
        }
        None => ("none".to_owned(), "none".to_owned(), "<not found in Identity Protection>".to_owned()),
    };

    // --- 2. Last risky detection (sign-in date + IP) --------------------------
    // riskDetections carries per-detection IP; filter to this UPN and take the most recent.
    let detections_path = format!(
        "/identityProtection/riskDetections?$filter=userPrincipalName eq '{}'&$orderby=activityDateTime desc&$top=1&$select=activityDateTime,ipAddress,riskState,riskEventType",
        upn
    );

    let det_resp = graph::get(&detections_path)?;
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
