use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "iam")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    User { #[command(subcommand)] action: UserCommands },
    Group { #[command(subcommand)] action: GroupCommands },
    Signin { #[command(subcommand)] action: SigninCommands },
    Error { code: String },
    Auth { #[command(subcommand)] action: AuthCommands },
    /// PowerShell-backed utilities (IntuneToolKit wrappers, complex endpoints).
    Ps { #[command(subcommand)] action: PsCommands },
    /// Rust-native Entra ID reports (translated from IntuneToolKit by AliAlame).
    Entra { #[command(subcommand)] action: EntraCommands },
    /// Rust-native Intune device management reports (translated from IntuneToolKit by AliAlame).
    Intune { #[command(subcommand)] action: IntuneCommands },
}

#[derive(Subcommand)]
pub enum UserCommands {
    Get { upn: String },
    Create { #[arg(short, long)] file: String },
    /// Show Identity Protection risk state, last risky sign-in date, and last risky sign-in IP.
    RiskInfo { upn: String },
}

#[derive(Subcommand)]
pub enum GroupCommands {
    Diff { user1: String, user2: String },
    Memberships { upn: String },
    Add { upn: String, group: String },
}

#[derive(Subcommand)]
pub enum SigninCommands {
    Bulk {
        #[arg(short, long)]
        file: String,
        #[arg(short, long, default_value = "50")]
        limit: u32,
    },
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Prompt for tenant_id and client_id and save to iam.toml beside the executable.
    Set,
    /// Delete iam.toml beside the executable (clears tenant_id and client_id).
    Reset,
}

/// PowerShell-backed commands. Invoke IntuneToolKit scripts by AliAlame via `pwsh -File`.
#[derive(Subcommand)]
pub enum PsCommands {
    /// Minimal PowerShell-backed smoke test.
    Hello,
    /// Intune compliance report [PS: Get-IntuneComplianceReport.ps1 by AliAlame]
    ComplianceReport {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Find Intune policy conflicts [PS: Find-IntunePolicyConflict.ps1 by AliAlame]
    PolicyConflict {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Export Intune dashboard HTML [PS: Export-IntuneDashboard.ps1 by AliAlame]
    Dashboard {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Intune BitLocker key report [PS: Get-IntuneBitLockerKeys.ps1 by AliAlame]
    BitLockerKeys {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Intune bulk device actions [PS: Invoke-IntuneBulkActions.ps1 by AliAlame]
    BulkActions {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(long, help = "Action to perform (e.g. Retire, Wipe, Sync)")]
        action: String,
        #[arg(long, help = "Comma-separated device IDs")]
        device_ids: String,
    },
    /// WUfB update ring health check [PS: Test-IntuneUpdateRingHealth.ps1 by AliAlame]
    UpdateRingHealth {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// WUfB update compliance report [PS: Get-IntuneUpdateComplianceReport.ps1 by AliAlame]
    UpdateCompliance {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Intune group policies report [PS: Get-IntuneGroupPolicies.ps1 by AliAlame]
    GroupPolicies {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
    /// Entra app registration audit [PS: Get-EntraAppRegistrationAudit.ps1 by AliAlame]
    AppRegistrationAudit {
        #[arg(short, long, help = "Path to IntuneToolKit scripts directory (optional)")]
        scripts_dir: Option<String>,
        #[arg(short, long, help = "Output file path (optional)")]
        output: Option<String>,
    },
}

/// Rust-native Entra ID report commands.
/// Derived from IntuneToolKit scripts by AliAlame
/// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
#[derive(Subcommand)]
pub enum EntraCommands {
    /// List admin role assignments [derived from Get-EntraAdminRoleReport.ps1 by AliAlame]
    AdminRoles,
    /// Audit guest users [derived from Get-EntraGuestUserAudit.ps1 by AliAlame]
    GuestAudit,
    /// List risky users [derived from Get-EntraRiskyUsers.ps1 by AliAlame]
    RiskyUsers,
    /// Conditional Access policy report [derived from Get-EntraCAReport.ps1 by AliAlame]
    CaReport,
}

/// Rust-native Intune device management commands.
/// Derived from IntuneToolKit scripts by AliAlame
/// (https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
#[derive(Subcommand)]
pub enum IntuneCommands {
    /// Managed device compliance report [derived from Get-IntuneComplianceReport.ps1 by AliAlame]
    ComplianceReport,
    /// Stale device report (lastSyncDateTime threshold) [derived from Get-IntuneStaleDevices.ps1 by AliAlame]
    StaleDevices {
        #[arg(long, default_value = "30", help = "Days since last sync to consider a device stale")]
        days: u32,
    },
}
