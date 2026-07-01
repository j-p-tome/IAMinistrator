//! Typed wrappers around the Microsoft Graph REST API.
//!
//! Each function builds the URL, attaches the bearer token, and returns
//! the raw JSON value. Callers deserialise into their own structs.

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build Graph client")
}

/// GET {base}{path} with the cached bearer token.
pub fn get(path: &str) -> Result<Value> {
    let token = crate::runtime::auth::get_token()?;
    let url = format!("{}{}", GRAPH_BASE, path);

    let res = client()?
        .get(&url)
        .bearer_auth(&token)
        .send()
        .context("Graph GET request failed")?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().unwrap_or_default();
        anyhow::bail!("Graph GET failed: {} \u{2013} {}", status, body.trim());
    }

    let json = res.json().context("Failed to parse Graph GET response JSON")?;
    Ok(json)
}

/// POST {base}{path} with a JSON body.
pub fn post(path: &str, body: &Value) -> Result<Value> {
    let token = crate::runtime::auth::get_token()?;
    let url = format!("{}{}", GRAPH_BASE, path);

    let res = client()?
        .post(&url)
        .bearer_auth(&token)
        .json(body)
        .send()
        .context("Graph POST request failed")?;

    if res.status().as_u16() == 204 {
        return Ok(serde_json::json!({}));
    }

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().unwrap_or_default();
        anyhow::bail!("Graph POST failed: {} \u{2013} {}", status, text.trim());
    }

    let json = res.json().context("Failed to parse Graph POST response JSON")?;
    Ok(json)
}

/// GET all pages of a Graph collection endpoint (follows @odata.nextLink).
pub fn get_all(path: &str) -> Result<Vec<Value>> {
    let first_page = get(path)?;
    let mut items: Vec<Value> = first_page["value"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut next_link = first_page["@odata.nextLink"]
        .as_str()
        .map(str::to_owned);

    while let Some(ref link) = next_link.clone() {
        let token = crate::runtime::auth::get_token()?;
        let res = client()?
            .get(link)
            .bearer_auth(&token)
            .send()
            .context("Graph GET (nextLink) request failed")?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().unwrap_or_default();
            anyhow::bail!("Graph GET (nextLink) failed: {} \u{2013} {}", status, text.trim());
        }

        let page: Value = res.json().context("Failed to parse Graph nextLink JSON")?;
        if let Some(arr) = page["value"].as_array() {
            items.extend_from_slice(arr);
        }
        next_link = page["@odata.nextLink"].as_str().map(str::to_owned);
    }

    Ok(items)
}
