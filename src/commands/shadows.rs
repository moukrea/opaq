// opaq: shadows command implementation

use crate::error::Result;
use crate::model::SecretEntry;
use crate::store;

pub fn execute(name: String) -> Result<()> {
    let entries = store::load_store()?;

    // Filter entries by name
    let mut matches: Vec<&SecretEntry> = entries.iter().filter(|e| e.name == name).collect();

    if matches.is_empty() {
        eprintln!("Error: no entries named '{}'", name);
        std::process::exit(1);
    }

    // Sort by specificity descending (most specific first)
    matches.sort_by(|a, b| b.scope.specificity().cmp(&a.scope.specificity()));

    let cwd = std::env::current_dir()?;

    // Find the active entry (highest specificity that contains cwd)
    let active_idx = matches.iter().position(|e| e.scope.contains(&cwd));

    println!("Entries named '{}':", name);

    // Calculate scope column width for alignment
    let max_scope_len = matches
        .iter()
        .map(|e| format!("{}", e.scope).len() + 2) // +2 for brackets
        .max()
        .unwrap_or(0);

    for (i, entry) in matches.iter().enumerate() {
        let is_active = active_idx == Some(i);
        let in_scope = entry.scope.contains(&cwd);
        let icon = if entry.sensitive {
            "\u{1f512}"
        } else {
            "\u{1f4cb}"
        };
        let scope_str = format!("[{}]", entry.scope);
        let scope_padded = format!("{:<width$}", scope_str, width = max_scope_len);

        let prefix = if is_active { "  ->" } else { "    " };

        if in_scope {
            if is_active {
                println!(
                    "{} {} {}  {}    <- active from here",
                    prefix, icon, scope_padded, entry.description
                );
            } else {
                println!(
                    "{} {} {}  {}",
                    prefix, icon, scope_padded, entry.description
                );
            }
        } else {
            // Dim out-of-scope entries
            println!(
                "{} {} {}  {}    \x1b[2m(out of scope)\x1b[0m",
                prefix, icon, scope_padded, entry.description
            );
        }
    }

    Ok(())
}
