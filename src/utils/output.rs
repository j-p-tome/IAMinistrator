//! Pretty-printing helpers for terminal output.

use colored::Colorize;
use serde_json::Value;

/// Print a single user object in a human-readable key:value block.
pub fn print_user(v: &Value) {
    let fields = [
        ("displayName", "Display Name"),
        ("userPrincipalName", "UPN"),
        ("id", "Object ID"),
        ("accountEnabled", "Enabled"),
        ("jobTitle", "Job Title"),
        ("department", "Department"),
        ("mail", "Mail"),
        ("mobilePhone", "Mobile"),
    ];
    println!();
    for (key, label) in &fields {
        if let Some(val) = v.get(key) {
            let formatted = match val {
                Value::Bool(b) => (if *b { "true".green() } else { "false".red() }).to_string(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            println!("  {:20} {}", label.bold(), formatted);
        }
    }
    println!();
}

/// Print a list of group names (or display names from JSON objects).
pub fn print_group_list(groups: &[Value]) {
    if groups.is_empty() {
        println!("{}", "  (no groups)".dimmed());
        return;
    }
    for g in groups {
        let name = g["displayName"].as_str().unwrap_or("<unnamed>");
        let id = g["id"].as_str().unwrap_or("");
        println!("  {} — {}", name.cyan(), id.dimmed());
    }
}

/// Print a diff of two group membership sets.
pub fn print_group_diff(only_in_a: &[Value], only_in_b: &[Value], a_label: &str, b_label: &str) {
    println!("\n{} (only in {})", "+".green().bold(), a_label.bold());
    if only_in_a.is_empty() {
        println!("  (none)");
    } else {
        print_group_list(only_in_a);
    }

    println!("\n{} (only in {})", "-".red().bold(), b_label.bold());
    if only_in_b.is_empty() {
        println!("  (none)");
    } else {
        print_group_list(only_in_b);
    }
}
