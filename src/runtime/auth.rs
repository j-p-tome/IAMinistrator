//! Token acquisition via environment variables.
//!
//! Expected env vars:
//!   IAM_TENANT_ID     – Azure AD tenant ID or domain
//!   IAM_CLIENT_ID     – App registration client ID
//!   IAM_CLIENT_SECRET – App registration secret  (for client_credentials flow)
//!
//! TODO: add device-code / interactive flow for personal use.

use anyhow::{bail, Context, Result};

/// Thin token cache — single token held in memory for the process lifetime.
static mut CACHED_TOKEN: Option<String> = None;

/// Returns a bearer token for the Graph API.
/// On first call, acquires a token via client_credentials; subsequent calls
/// return the cached value (expiry handling is a TODO).
pub fn get_token() -> Result<String> {
    // SAFETY: single-threaded CLI — no concurrent access.
    unsafe {
        if let Some(ref t) = CACHED_TOKEN {
            return Ok(t.clone());
        }
    }

    let token = acquire_client_credentials_token()?;

    unsafe {
        CACHED_TOKEN = Some(token.clone());
    }

    Ok(token)
}

fn acquire_client_credentials_token() -> Result<String> {
    let tenant = std::env::var("IAM_TENANT_ID").context("IAM_TENANT_ID not set")?;
    let client_id = std::env::var("IAM_CLIENT_ID").context("IAM_CLIENT_ID not set")?;
    let client_secret =
        std::env::var("IAM_CLIENT_SECRET").context("IAM_CLIENT_SECRET not set")?;

    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    );

    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
        ("scope", "https://graph.microsoft.com/.default"),
    ];

    // TODO: swap ureq/reqwest in once the http client dependency is added to Cargo.toml.
    //       For now this is a compile-time stub that will fail at runtime with a clear message.
    let _ = (url, params);
    bail!("Token acquisition not yet implemented — add reqwest to Cargo.toml and complete this function.")
}
