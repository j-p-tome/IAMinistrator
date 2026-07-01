//! Token acquisition via environment variables.
//!
//! Expected env vars:
//!   IAM_TENANT_ID     – Azure AD tenant ID or domain
//!   IAM_CLIENT_ID     – App registration client ID
//!   IAM_CLIENT_SECRET – App registration secret  (for client_credentials flow)
//!
//! TODO: add device-code / interactive flow for personal use.

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build reqwest client")
}

/// Returns a bearer token for the Graph API.
/// Reuses a cached token until it is close to expiry.
pub fn get_token() -> Result<String> {
    {
        let cache = TOKEN_CACHE
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock token cache"))?;

        if let Some(cached) = cache.as_ref() {
            if SystemTime::now() < cached.expires_at {
                return Ok(cached.token.clone());
            }
        }
    }

    let tenant = std::env::var("IAM_TENANT_ID").context("IAM_TENANT_ID not set")?;
    let client_id = std::env::var("IAM_CLIENT_ID").context("IAM_CLIENT_ID not set")?;
    let client_secret =
        std::env::var("IAM_CLIENT_SECRET").context("IAM_CLIENT_SECRET not set")?;

    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    );

    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
    ];

    let res = client()?
        .post(&url)
        .form(&form)
        .send()
        .context("Token request failed")?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().unwrap_or_default();
        bail!("Token request failed: {} \u{2013} {}", status, body.trim());
    }

    let token_res: TokenResponse = res.json().context("Failed to parse token response JSON")?;
    let expires_at = SystemTime::now()
        + Duration::from_secs(token_res.expires_in.saturating_sub(60));

    {
        let mut cache = TOKEN_CACHE
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock token cache"))?;

        *cache = Some(CachedToken {
            token: token_res.access_token.clone(),
            expires_at,
        });
    }

    Ok(token_res.access_token)
}
