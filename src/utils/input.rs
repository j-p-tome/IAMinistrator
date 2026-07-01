//! File parsing helpers — CSV and JSON UPN lists, bulk-create payloads.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;

/// Read a plain-text file and return one UPN per line, trimmed, no blanks.
pub fn read_upn_list(path: &str) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path).with_context(|| format!("Cannot read file: {}", path))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// Read a JSON file and return the root value.
/// Supports both a single object (for single-user create) and an array.
pub fn read_json_file(path: &str) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("Cannot read file: {}", path))?;
    serde_json::from_str(&raw).with_context(|| format!("Invalid JSON in file: {}", path))
}
