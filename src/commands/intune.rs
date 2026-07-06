// src/commands/intune.rs
//
// Rust-native Intune device management commands for IAMinistrator.
//
// Derived from the following IntuneToolKit scripts by AliAlame
// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit):
//   - Get-IntuneComplianceReport.ps1
//   - Get-IntuneStaleDevices.ps1
// Translated and adapted for native Rust / Microsoft Graph REST API.

use anyhow::Result;
use chrono::Utc;
use colored::Colorize;

pub fn handle(action: crate::cli::IntuneCommands) -> Result<()> {
    match action {
        crate::cli::IntuneCommands::ComplianceReport => compliance_report(),
        crate::cli::IntuneCommands::StaleDevices { days } => stale_devices(days),
    }
}

/// Derived from Get-IntuneComplianceReport.ps1 by AliAlame.
/// Requires: DeviceManagementManagedDevices.Read.All
fn compliance_report() -> Result<()> {
    let devices = crate::runtime::graph::get_all(
        "/deviceManagement/managedDevices\
         ?$select=deviceName,userPrincipalName,complianceState,\
operatingSystem,osVersion,lastSyncDateTime\
         &$top=999",
    )?;

    println!("{}", "Intune Compliance Report".bold().underline());
    println!(
        "{:<35} {:<42} {:<14} {:<12} {:<24}",
        "Device", "User", "Compliance", "OS", "Last Sync"
    );
    println!("{}", "-".repeat(130));

    let mut compliant = 0usize;
    let mut noncompliant = 0usize;

    for d in &devices {
        let name  = d["deviceName"].as_str().unwrap_or("").to_string();
        let upn   = d["userPrincipalName"].as_str().unwrap_or("").to_string();
        let state = d["complianceState"].as_str().unwrap_or("unknown").to_string();
        let os    = d["operatingSystem"].as_str().unwrap_or("").to_string();
        let sync  = d["lastSyncDateTime"].as_str().unwrap_or("").to_string();

        let colored_state = match state.as_str() {
            "compliant"    => { compliant += 1; state.green().to_string() }
            "noncompliant" => { noncompliant += 1; state.red().to_string() }
            _              => state.yellow().to_string(),
        };

        println!(
            "{:<35} {:<42} {:<14} {:<12} {:<24}",
            name, upn, colored_state, os, sync
        );
    }

    println!(
        "\nTotal: {}  Compliant: {}  Non-compliant: {}",
        devices.len(),
        compliant.to_string().green(),
        noncompliant.to_string().red()
    );
    Ok(())
}

/// Derived from Get-IntuneStaleDevices.ps1 by AliAlame.
/// Requires: DeviceManagementManagedDevices.Read.All
fn stale_devices(days: u32) -> Result<()> {
    let devices = crate::runtime::graph::get_all(
        "/deviceManagement/managedDevices\
         ?$select=deviceName,userPrincipalName,lastSyncDateTime,\
operatingSystem,complianceState\
         &$top=999",
    )?;

    let cutoff = Utc::now() - chrono::Duration::days(days as i64);

    println!(
        "{}",
        format!("Intune Stale Devices (>{} days since last sync)", days)
            .bold()
            .underline()
    );
    println!(
        "{:<35} {:<42} {:<26} {:<12}",
        "Device", "User", "Last Sync", "OS"
    );
    println!("{}", "-".repeat(117));

    let mut count = 0usize;
    for d in &devices {
        let sync_str = d["lastSyncDateTime"].as_str().unwrap_or("");
        let is_stale = chrono::DateTime::parse_from_rfc3339(sync_str)
            .map(|dt| dt.with_timezone(&Utc) < cutoff)
            .unwrap_or(true);

        if is_stale {
            count += 1;
            let name = d["deviceName"].as_str().unwrap_or("").to_string();
            let upn  = d["userPrincipalName"].as_str().unwrap_or("").to_string();
            let os   = d["operatingSystem"].as_str().unwrap_or("").to_string();
            println!("{:<35} {:<42} {:<26} {:<12}", name, upn, sync_str, os);
        }
    }

    println!("\nStale devices: {}", count.to_string().red());
    Ok(())
}
