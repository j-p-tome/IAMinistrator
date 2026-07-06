// src/commands/ps.rs
//
// PowerShell handler for IAMinistrator.
// Thin Rust wrapper around `pwsh` for IntuneToolKit integration.
//
// Attribution: The scripts invoked by the handlers below are part of
// IntuneToolKit by AliAlame (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
// This module invokes them via `pwsh -File` and captures their output.
//
// Script resolution order:
//   1. --scripts-dir <path>/<script>.ps1  (explicit override)
//   2. <exe_dir>/vendor/intunetoolkit/<script>.ps1  (beside the iam binary)
//   3. vendor/intunetoolkit/<script>.ps1  (relative to CWD)

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
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

/// Resolve a vendored IntuneToolKit script by name.
///
/// Resolution order (attributed to AliAlame / IntuneToolKit):
///   1. `--scripts-dir` argument if provided and the script exists there
///   2. `<exe_dir>/vendor/intunetoolkit/<script_name>` (beside the installed binary)
///   3. `vendor/intunetoolkit/<script_name>` (relative to current working directory)
fn resolve_script(script_name: &str, scripts_dir: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = scripts_dir {
        let candidate = Path::new(dir).join(script_name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let exe_dir = std::env::current_exe()
        .context("Failed to determine path of iam executable")?
        .parent()
        .ok_or_else(|| anyhow!("Failed to compute executable directory"))
        .map(|p| p.to_path_buf())?;

    let vendor_paths = [
        exe_dir.join("vendor").join("intunetoolkit").join(script_name),
        Path::new("vendor").join("intunetoolkit").join(script_name),
    ];

    for p in &vendor_paths {
        if p.exists() {
            return Ok(p.clone());
        }
    }

    Err(anyhow!(
        "Script not found: {script_name}. Checked --scripts-dir and vendor/intunetoolkit/."
    ))
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
            let script = resolve_script("Get-IntuneComplianceReport.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::PolicyConflict { scripts_dir, output } => {
            let script = resolve_script("Find-IntunePolicyConflict.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::Dashboard { scripts_dir, output } => {
            let script = resolve_script("Export-IntuneDashboard.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::BitLockerKeys { scripts_dir, output } => {
            let script = resolve_script("Get-IntuneBitLockerKeys.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::BulkActions { scripts_dir, action, device_ids } => {
            let script = resolve_script("Invoke-IntuneBulkActions.ps1", scripts_dir.as_deref())?;
            let params: Vec<(&str, &str)> = vec![
                ("-Action", &action),
                ("-DeviceIds", &device_ids),
            ];
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::UpdateRingHealth { scripts_dir, output } => {
            let script = resolve_script("Test-IntuneUpdateRingHealth.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::UpdateCompliance { scripts_dir, output } => {
            let script = resolve_script("Get-IntuneUpdateComplianceReport.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::GroupPolicies { scripts_dir, output } => {
            let script = resolve_script("Get-IntuneGroupPolicies.ps1", scripts_dir.as_deref())?;
            let out_owned = output.unwrap_or_default();
            let mut params: Vec<(&str, &str)> = vec![];
            if !out_owned.is_empty() {
                params.push(("-OutputPath", &out_owned));
            }
            let result = run_ps_script(&script, &params)?;
            print!("{}", result);
        }

        crate::cli::PsCommands::AppRegistrationAudit { scripts_dir, output } => {
            let script = resolve_script("Get-EntraAppRegistrationAudit.ps1", scripts_dir.as_deref())?;
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
