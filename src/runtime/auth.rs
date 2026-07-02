//! Token acquisition via environment variables or OS keyring.
//!
//! Resolution order:
//!   1. IAM_TENANT_ID / IAM_CLIENT_ID / IAM_CLIENT_SECRET env vars
//!   2. OS keyring entries written by `iam auth set` / `iam auth reset`
//!
//! Stored keyring entries:
//!   service: iaministrator
//!   user: tenant_id      -> tenant/domain
//!   user: client_id      -> app registration client ID
//!   user: client_secret  -> app registration client secret
//!
//! On Linux the keyring crate is compiled with the
//! linux-secret-service-rt-tokio-crypto-rust feature so that it targets
//! the org.freedesktop.secrets DBus interface.  KWallet 5/6 exposes this
//! interface natively; GNOME Keyring does too.  This is required — without
//! that feature the default Linux backend is a no-op stub.
//!
//! TODO: add device-code / interactive flow for personal use.
//! TODO: add certificate auth for production app-only usage.

use anyhow::{bail, Context, Result};
use keyring::{Entry, Error as KeyringError};
use reqwest::blocking::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const KEYRING_SERVICE: &str = "iaministrator";
const KEY_TENANT_ID: &str = "tenant_id";
const KEY_CLIENT_ID: &str = "client_id";
const KEY_CLIENT_SECRET: &str = "client_secret";

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

pub struct StoredCredentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build reqwest client")
}

fn keyring_entry(name: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, name).context("Failed to open keyring entry")
}

fn get_keyring_value(name: &str) -> Result<Option<String>> {
    let entry = keyring_entry(name)?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Failed to read keyring value '{}': {}", name, e)),
    }
}

fn set_keyring_value(name: &str, value: &str) -> Result<()> {
    let entry = keyring_entry(name)?;
    entry
        .set_password(value)
        .with_context(|| format!("Failed to store '{}' in OS keyring", name))
}

fn delete_keyring_value(name: &str) -> Result<()> {
    let entry = keyring_entry(name)?;
    match entry.delete_credential() {
        Ok(_) | Err(KeyringError::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to delete keyring value '{}': {}",
            name,
            e
        )),
    }
}

fn prompt_line(label: &str) -> Result<String> {
    print!("{}", label);
    io::stdout().flush().context("Failed to flush stdout")?;
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("Failed to read input")?;
    Ok(buf.trim().to_string())
}

fn prompt_secret(label: &str) -> Result<SecretString> {
    let value = rpassword::prompt_password(label).context("Failed to read secret input")?;
    Ok(SecretString::new(value))
}

/// Prompt for all three credentials and store them in the OS keyring.
/// Existing entries are overwritten in-place; nothing is deleted first.
/// This is the path taken by `iam auth set`.
pub fn set_credentials() -> Result<()> {
    let tenant_id = prompt_line("Tenant ID / domain: ")?;
    let client_id = prompt_line("Client ID: ")?;
    let client_secret = prompt_secret("Client secret: ")?;

    if tenant_id.is_empty() || client_id.is_empty() || client_secret.expose_secret().is_empty() {
        bail!("All credential fields are required");
    }

    set_keyring_value(KEY_TENANT_ID, &tenant_id)?;
    set_keyring_value(KEY_CLIENT_ID, &client_id)?;
    set_keyring_value(KEY_CLIENT_SECRET, client_secret.expose_secret())?;

    // Invalidate any cached token so the next request uses the new credentials.
    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = None;
    }

    println!("Credentials stored in OS keyring (tenant_id, client_id, client_secret).");
    Ok(())
}

/// Clears any previously stored credentials and re-prompts for fresh values.
/// This is the path taken by `iam auth reset`.
pub fn reset_credentials() -> Result<()> {
    delete_keyring_value(KEY_TENANT_ID)?;
    delete_keyring_value(KEY_CLIENT_ID)?;
    delete_keyring_value(KEY_CLIENT_SECRET)?;

    let tenant_id = prompt_line("Tenant ID / domain: ")?;
    let client_id = prompt_line("Client ID: ")?;
    let client_secret = prompt_secret("Client secret: ")?;

    if tenant_id.is_empty() || client_id.is_empty() || client_secret.expose_secret().is_empty() {
        bail!("All credential fields are required");
    }

    set_keyring_value(KEY_TENANT_ID, &tenant_id)?;
    set_keyring_value(KEY_CLIENT_ID, &client_id)?;
    set_keyring_value(KEY_CLIENT_SECRET, client_secret.expose_secret())?;

    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = None;
    }

    println!("Credentials cleared and re-stored in OS keyring.");
    Ok(())
}

/// Load credentials from env or OS keyring.
pub fn load_credentials() -> Result<StoredCredentials> {
    let tenant_id = match std::env::var("IAM_TENANT_ID") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => get_keyring_value(KEY_TENANT_ID)?
            .context("IAM_TENANT_ID not set and no stored tenant_id in keyring")?,
    };

    let client_id = match std::env::var("IAM_CLIENT_ID") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => get_keyring_value(KEY_CLIENT_ID)?
            .context("IAM_CLIENT_ID not set and no stored client_id in keyring")?,
    };

    let client_secret = match std::env::var("IAM_CLIENT_SECRET") {
        Ok(v) if !v.trim().is_empty() => SecretString::new(v),
        _ => SecretString::new(
            get_keyring_value(KEY_CLIENT_SECRET)?
                .context("IAM_CLIENT_SECRET not set and no stored client_secret in keyring")?,
        ),
    };

    Ok(StoredCredentials {
        tenant_id,
        client_id,
        client_secret,
    })
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

    let creds = load_credentials()?;

    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        creds.tenant_id
    );

    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.expose_secret()),
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
