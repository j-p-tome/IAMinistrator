use anyhow::Result;
use colored::Colorize;

/// Known AADSTS / Graph error codes with descriptions and remediation hints.
static ERROR_TABLE: &[(&str, &str, &str)] = &[
    (
        "AADSTS50034",
        "User account does not exist in the directory.",
        "Verify the UPN or ObjectId. The account may have been deleted or is in a different tenant.",
    ),
    (
        "AADSTS50076",
        "MFA required — user must use multi-factor authentication.",
        "Check Conditional Access policies. If testing, use an MFA-exempt service account or add an exclusion.",
    ),
    (
        "AADSTS50105",
        "User is not assigned to a role for the application.",
        "Assign the user (or their group) to the enterprise app under 'Users and groups'.",
    ),
    (
        "AADSTS65001",
        "The user or administrator has not consented to use the application.",
        "Grant admin consent at: https://portal.azure.com → Enterprise Apps → Permissions → Grant admin consent.",
    ),
    (
        "AADSTS70011",
        "Invalid scope — the provided value for 'scope' is not valid for this application.",
        "Check the API permissions registered on the app. Ensure the scope matches exactly (case-sensitive).",
    ),
    (
        "AADSTS700016",
        "Application not found in directory. It may not be installed in the tenant.",
        "Verify the client_id/app registration exists in this tenant. Check for multi-tenant vs single-tenant config.",
    ),
    (
        "AADSTS90002",
        "Tenant not found — either invalid tenant ID or tenant does not support this flow.",
        "Confirm the tenant ID / domain. Use 'common' or 'organizations' as the authority if multi-tenant.",
    ),
];

pub fn lookup(code: &str) -> Result<()> {
    let normalized = code.trim().to_uppercase();
    let matches: Vec<_> = ERROR_TABLE
        .iter()
        .filter(|(c, _, _)| c.to_uppercase() == normalized)
        .collect();

    if matches.is_empty() {
        println!(
            "{} No entry found for '{}'. Check https://login.microsoftonline.com/error?code={}",
            "[error:lookup]".yellow().bold(),
            code,
            // strip AADSTS prefix if present to build the numeric URL
            normalized.trim_start_matches("AADSTS")
        );
    } else {
        for (c, desc, hint) in matches {
            println!("\n{}", c.bold());
            println!("  {} {}", "Description:".dimmed(), desc);
            println!("  {} {}", "Remediation: ".dimmed(), hint.green());
        }
    }
    Ok(())
}
