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
        println!("  {} \u{2014} {}", name.cyan(), id.dimmed());
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

/// Print detailed user info: UPN, primary mail, aliases, last password change.
pub fn print_user_details(v: &Value) {
    println!();

    let display_name = v["displayName"].as_str().unwrap_or("<unknown>");
    let upn = v["userPrincipalName"].as_str().unwrap_or("<unknown>");
    let mail = v["mail"].as_str().unwrap_or("<none>");

    println!("  {:20} {}", "Display Name".bold(), display_name);
    println!("  {:20} {}", "UPN".bold(), upn.cyan());
    println!("  {:20} {}", "Primary Mail".bold(), mail);

    let mut aliases: Vec<String> = Vec::new();

    if let Some(proxy) = v["proxyAddresses"].as_array() {
        for a in proxy {
            if let Some(s) = a.as_str() {
                aliases.push(s.to_string());
            }
        }
    }

    if let Some(other) = v["otherMails"].as_array() {
        for a in other {
            if let Some(s) = a.as_str() {
                aliases.push(s.to_string());
            }
        }
    }

    println!("  {:20}", "Aliases".bold());
    if aliases.is_empty() {
        println!("  {:20} {}", "", "(none)".dimmed());
    } else {
        for a in aliases {
            println!("  {:20} {}", "", a);
        }
    }

    let pwd_change = v["lastPasswordChangeDateTime"]
        .as_str()
        .unwrap_or("<unknown>");
    println!(
        "  {:20} {}",
        "Last Password Change".bold(),
        pwd_change.green()
    );

    println!();
}

/// Print Identity Protection risk summary for a user.
///
/// Colour coding:
///   risk_state: atRisk / confirmedCompromised → red; remediated / confirmedSafe → green; others → yellow
///   risk_level: high → red; medium → yellow; low → default; none → green
pub fn print_user_risk_info(
    upn: &str,
    risk_state: &str,
    risk_level: &str,
    risk_last_updated: &str,
    last_risky_signin: &str,
    last_risky_ip: &str,
) {
    println!();
    println!("  {:28} {}", "UPN".bold(), upn.cyan());

    let state_colored = match risk_state {
        "atRisk" | "confirmedCompromised" => risk_state.red().bold().to_string(),
        "remediated" | "confirmedSafe" | "dismissed" => risk_state.green().to_string(),
        "none" => risk_state.green().dimmed().to_string(),
        _ => risk_state.yellow().to_string(),
    };
    println!("  {:28} {}", "Risk State".bold(), state_colored);

    let level_colored = match risk_level {
        "high" => risk_level.red().bold().to_string(),
        "medium" => risk_level.yellow().to_string(),
        "low" => risk_level.normal().to_string(),
        "none" => risk_level.green().dimmed().to_string(),
        _ => risk_level.dimmed().to_string(),
    };
    println!("  {:28} {}", "Risk Level".bold(), level_colored);
    println!("  {:28} {}", "Risk Last Updated".bold(), risk_last_updated.yellow());
    println!("  {:28} {}", "Last Known Risky Sign-In".bold(), last_risky_signin.yellow());
    println!("  {:28} {}", "Last Known Risky Sign-In IP".bold(), last_risky_ip.yellow());
    println!();
}
