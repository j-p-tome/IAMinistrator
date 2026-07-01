//! Typed wrappers around the Microsoft Graph REST API.
//!
//! Each function builds the URL, attaches the bearer token, and returns
//! the raw JSON value. Callers deserialise into their own structs.

use anyhow::Result;
use serde_json::Value;

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

/// GET {base}{path} with the cached bearer token.
pub fn get(path: &str) -> Result<Value> {
    let _token = crate::runtime::auth::get_token()?;
    let _url = format!("{}{}", GRAPH_BASE, path);
    // TODO: execute HTTP GET with reqwest/ureq, deserialise body.
    todo!("graph::get not yet implemented")
}

/// POST {base}{path} with a JSON body.
pub fn post(path: &str, body: &Value) -> Result<Value> {
    let _token = crate::runtime::auth::get_token()?;
    let _url = format!("{}{}", GRAPH_BASE, path);
    let _ = body;
    // TODO: execute HTTP POST with reqwest/ureq, deserialise body.
    todo!("graph::post not yet implemented")
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
        // strip GRAPH_BASE prefix so we can reuse `get`
        let path_suffix = link
            .strip_prefix(GRAPH_BASE)
            .unwrap_or(link.as_str());
        let page = get(path_suffix)?;
        if let Some(arr) = page["value"].as_array() {
            items.extend_from_slice(arr);
        }
        next_link = page["@odata.nextLink"].as_str().map(str::to_owned);
    }

    Ok(items)
}
