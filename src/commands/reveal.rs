// opaq: reveal command implementation

use std::io::Write;

use crate::error::{OpaqError, Result};
use crate::model::Scope;
use crate::store;

pub fn execute(name: String, json: bool, scope_override: Option<String>) -> Result<()> {
    let entries = store::load_store()?;

    // Filter candidates by name
    let candidates: Vec<_> = entries.iter().filter(|e| e.name == name).collect();

    // Apply scope filtering
    let applicable: Vec<_> = if let Some(ref scope_str) = scope_override {
        if scope_str == "global" {
            candidates
                .into_iter()
                .filter(|e| e.scope == Scope::Global)
                .collect()
        } else {
            let canon = std::fs::canonicalize(scope_str)
                .map_err(|_| OpaqError::InvalidScopePath(scope_str.clone()))?;
            if !canon.is_dir() {
                return Err(OpaqError::InvalidScopePath(scope_str.clone()));
            }
            candidates
                .into_iter()
                .filter(|e| e.scope == Scope::Path(canon.clone()))
                .collect()
        }
    } else {
        let cwd = std::env::current_dir()?;
        candidates
            .into_iter()
            .filter(|e| e.scope.contains(&cwd))
            .collect()
    };

    // Pick highest specificity winner
    let winner = applicable
        .into_iter()
        .max_by_key(|e| e.scope.specificity())
        .ok_or_else(|| OpaqError::SecretNotFound(name.clone()))?;

    // Check sensitivity
    if winner.sensitive {
        return Err(OpaqError::RevealSensitive(name));
    }

    // Output
    if json {
        let output = serde_json::json!({
            "name": winner.name,
            "value": String::from_utf8_lossy(&winner.value),
            "scope": format!("{}", winner.scope),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|e| OpaqError::Serialization(e.to_string()))?
        );
    } else {
        std::io::stdout().write_all(&winner.value)?;
    }

    Ok(())
}
