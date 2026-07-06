// src/commands/ps.rs
//
// PowerShell handler for IAMinistrator.
// This module provides a thin, Rust-y wrapper around `pwsh`
// so we can integrate IntuneToolKit and other PS-based utilities.
//
// NOTE: This initial implementation is a minimal "hello world" smoke test.
// It proves the plumbing from clap -> command dispatch -> pwsh -> stdout/stderr.
// Later commands can reuse `run_powershell` with real script paths and args.

use anyhow::{anyhow, Context, Result};
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
    }

    Ok(())
}
