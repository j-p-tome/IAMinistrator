// src/commands/ps.rs
//
// PowerShell handler for IAMinistrator.
// Thin Rust wrapper around `pwsh` for IntuneToolKit integration.
//
// Attribution: The scripts invoked by the handlers below are part of
// IntuneToolKit by AliAlame (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
// This module invokes them via `pwsh -File` and captures their output.

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

fn run_powershell(command: &str) -> Result<String> {
    let child = Command::new("pwsh")
        .arg("-NoLogo")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "Failed to start `pwsh`. Is PowerShell 7+ (pwsh) installed and on PATH?")?;

    let output = child
        .wait_with_output()
        .with_context(|| "Failed to wait for `pwsh` process to complete")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let msg = if stderr.is_empty() {
            format!("PowerShell exited with code {code} and no stderr output")
        } else {
            format!("PowerShell exited with code {code}: {stderr}")
        };
        return Err(anyhow!(msg));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run an IntuneToolKit script by file path with optional named parameters.
/// `params` is a slice of `("-ParamName", "value")` pairs.
fn run_ps_script(script_path: &Path, params: &[(&str, &str)]) -> Result<String> {
    if !script_path.exists() {
        return Err(anyhow!(
            "Script not found: {}. Ensure IntuneToolKit scripts are in the specified --scripts-dir.",
            script_path.display()
        ));
    }

    let mut cmd = Command::new("pwsh");
    cmd.arg("-NoLogo")
        .arg("-NonInteractive")
        .arg("-File")
        .arg(script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (name, value) in params {
        cmd.arg(name).arg(value);
    }

    let child = cmd
        .spawn()
        .with_context(|| "Failed to start `pwsh`. Is PowerShell 7+ installed and on PATH?")?;

    let output = child
        .wait_with_output()
        .with_context(|| "Failed to wait for `pwsh` process")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let msg = if stderr.is_empty() {
            format!("PowerShell exited with code {code} and no stderr output")
        } else {
            format!("PowerShell exited with code {code}: {stderr}")
        };
        return Err(anyhow!(msg));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn handle(action: crate::cli::PsCommands) -> Result<()> {
    match action {
        crate::cli::PsCommands::Hello => {
            let ps_command = r#"Write-Output "Hello from IAMinistrator PowerShell handler""#;
            let output = run_powershell(ps_command)?;
            let trimmed = output.trim_end();
            if !trimmed.is_empty() {
                println!("{trimmed}");
            }
        }

        crate::cli::PsCommands::ComplianceReport { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Get-IntuneComplianceReport.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::PolicyConflict { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Find-IntunePolicyConflict.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::Dashboard { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Export-IntuneDashboard.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::BitLockerKeys { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Get-IntuneBitLockerKeys.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::BulkActions { scripts_dir, action, device_ids } => {
            let script = Path::new(&scripts_dir).join("Invoke-IntuneBulkActions.ps1");
            let params: Vec<(&str, &str)> = vec![
                ("-Action", &action),
                ("-DeviceIds", &device_ids),
            ];
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::UpdateRingHealth { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Test-IntuneUpdateRingHealth.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::UpdateCompliance { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Get-IntuneUpdateComplianceReport.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::GroupPolicies { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Get-IntuneGroupPolicies.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::AppRegistrationAudit { scripts_dir, output } => {
            let script = Path::new(&scripts_dir).join("Get-EntraAppRegistrationAudit.ps1");
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }
    }

    Ok(())
}
