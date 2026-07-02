//! Token acquisition via environment variables or config file + interactive prompt.
//!
//! Resolution order:
//!   tenant_id:     IAM_TENANT_ID env var  >  iam.toml beside executable  >  error
//!   client_id:     IAM_CLIENT_ID  env var  >  iam.toml beside executable  >  error
//!   client_secret: IAM_CLIENT_SECRET env var  >  visible stdin prompt  (never on disk)
//!
//! Config file (iam.toml beside the iam executable):
//!   tenant_id = "contoso.onmicrosoft.com"
//!   client_id  = "00000000-0000-0000-0000-000000000000"
//!
//! client_secret is NEVER written to disk.
//!
//! Debug logging: IAM_AUTH_DEBUG=1
//!
//! TODO: add device-code / interactive flow for personal use.
//! TODO: add certificate auth for production app-only usage.

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Non-secret configuration persisted beside the executable.
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct StoredConfig {
    pub tenant_id: String,
    pub client_id: String,
}

/// Returns the path to `iam.toml` located beside the running executable.
fn config_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("Failed to determine executable path")?;
    let dir = exe.parent().context("Executable has no parent directory")?;
    Ok(dir.join("iam.toml"))
}

/// Load `StoredConfig` from `iam.toml` beside the executable.
/// Returns `Ok(None)` if the file does not exist.
pub fn load_config() -> Result<Option<StoredConfig>> {
    let path = config_path()?;
    auth_debug(format!("load_config path='{}'", path.display()));
    if !path.exists() {
        auth_debug("load_config: file not found");
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
    let cfg: StoredConfig = toml::from_str(&text)
        .with_context(|| format!("Failed to parse config file '{}'", path.display()))?;
    auth_debug(format!(
        "load_config success tenant_id_mask='{}' client_id_mask='{}'",
        mask_value(&cfg.tenant_id),
        mask_value(&cfg.client_id)
    ));
    Ok(Some(cfg))
}

/// Write `StoredConfig` to `iam.toml` beside the executable.
pub fn save_config(cfg: &StoredConfig) -> Result<()> {
    let path = config_path()?;
    auth_debug(format!("save_config path='{}'", path.display()));
    let text = toml::to_string(cfg).context("Failed to serialize config")?;
    std::fs::write(&path, text).with_context(|| {
        format!(
            "Failed to write config file '{}'. Is the directory read-only?",
            path.display()
        )
    })?;
    auth_debug(format!("save_config success path='{}'", path.display()));
    Ok(())
}

/// Delete `iam.toml` beside the executable if it exists.
pub fn delete_config() -> Result<()> {
    let path = config_path()?;
    auth_debug(format!("delete_config path='{}'", path.display()));
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to delete config file '{}'", path.display()))?;
        auth_debug("delete_config success");
    } else {
        auth_debug("delete_config: file did not exist; nothing to do");
    }
    Ok(())
}

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

fn auth_debug_enabled() -> bool {
    matches!(
        std::env::var("IAM_AUTH_DEBUG").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

fn auth_debug(message: impl AsRef<str>) {
    if auth_debug_enabled() {
        eprintln!("[iam:auth:debug] {}", message.as_ref());
    }
}

fn mask_value(value: &str) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }
    if value.len() <= 4 {
        return "*".repeat(value.len());
    }
    format!("{}***{}", &value[..2], &value[value.len() - 2..])
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build reqwest client")
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

/// Prompt for tenant_id and client_id only and write them to iam.toml beside the executable.
/// client_secret is never written to disk.
pub fn set_credentials() -> Result<()> {
    auth_debug("set_credentials invoked");

    let tenant_id = prompt_line("Tenant ID / domain: ")?;
    let client_id = prompt_line("Client ID: ")?;

    if tenant_id.is_empty() || client_id.is_empty() {
        auth_debug("set_credentials validation failed: one or more fields were empty");
        bail!("tenant_id and client_id are both required");
    }

    let cfg = StoredConfig { tenant_id, client_id };
    save_config(&cfg)?;

    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = None;
    }

    println!(
        "Non-secret config saved to '{}'. Only tenant_id and client_id were stored; client_secret is never written to disk.",
        config_path()?.display()
    );
    Ok(())
}

/// Deletes iam.toml beside the executable (clears tenant_id and client_id).
/// client_secret was never stored, so no secret cleanup is needed.
pub fn reset_credentials() -> Result<()> {
    auth_debug("reset_credentials invoked; deleting config file");
    delete_config()?;
    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = None;
    }
    println!("Config cleared. Run 'iam auth set' to store new tenant_id and client_id.");
    Ok(())
}

/// Load credentials from env vars, config file, and interactive prompt.
/// Resolution order:
///   tenant_id:     IAM_TENANT_ID  >  iam.toml  >  error
///   client_id:     IAM_CLIENT_ID  >  iam.toml  >  error
///   client_secret: IAM_CLIENT_SECRET  >  visible stdin prompt  (never on disk)
pub fn load_credentials() -> Result<StoredCredentials> {
    let env_tenant_id = std::env::var("IAM_TENANT_ID").ok();
    let env_client_id = std::env::var("IAM_CLIENT_ID").ok();
    let env_client_secret = std::env::var("IAM_CLIENT_SECRET").ok();

    auth_debug(format!(
        "load_credentials env-var presence tenant_id={} client_id={} client_secret={}",
        env_tenant_id.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false),
        env_client_id.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false),
        env_client_secret.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false),
    ));

    // Load config file once; only consulted if the env var is absent.
    let config = load_config()?;

    let tenant_id = match env_tenant_id {
        Some(v) if !v.trim().is_empty() => {
            auth_debug("tenant_id: source=env(IAM_TENANT_ID)");
            v
        }
        _ => {
            auth_debug(format!(
                "tenant_id: IAM_TENANT_ID absent; trying config file '{}'",
                config_path()?.display()
            ));
            config
                .as_ref()
                .filter(|c| !c.tenant_id.trim().is_empty())
                .map(|c| c.tenant_id.clone())
                .with_context(|| {
                    "tenant_id not found: IAM_TENANT_ID is not set and iam.toml beside the \
                     executable does not contain a tenant_id. Run 'iam auth set' to configure."
                        .to_string()
                })?
        }
    };

    let client_id = match env_client_id {
        Some(v) if !v.trim().is_empty() => {
            auth_debug("client_id: source=env(IAM_CLIENT_ID)");
            v
        }
        _ => {
            auth_debug(format!(
                "client_id: IAM_CLIENT_ID absent; trying config file '{}'",
                config_path()?.display()
            ));
            config
                .as_ref()
                .filter(|c| !c.client_id.trim().is_empty())
                .map(|c| c.client_id.clone())
                .with_context(|| {
                    "client_id not found: IAM_CLIENT_ID is not set and iam.toml beside the \
                     executable does not contain a client_id. Run 'iam auth set' to configure."
                        .to_string()
                })?
        }
    };

    let client_secret = match env_client_secret {
        Some(v) if !v.trim().is_empty() => {
            auth_debug("client_secret: source=env(IAM_CLIENT_SECRET)");
            SecretString::new(v)
        }
        _ => {
            auth_debug("client_secret: IAM_CLIENT_SECRET absent; prompting interactively");
            let value = prompt_line("Client secret: ")?;
            if value.is_empty() {
                bail!("client_secret is required but was not provided");
            }
            SecretString::new(value)
        }
    };

    auth_debug("load_credentials completed successfully");
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
    let expires_at =
        SystemTime::now() + Duration::from_secs(token_res.expires_in.saturating_sub(60));

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
