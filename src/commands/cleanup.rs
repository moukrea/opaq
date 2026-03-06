// opaq: cleanup command implementation

use crate::error::{OpaqError, Result};
use crate::model::Scope;
use crate::store;

pub fn execute() -> Result<()> {
    let mut entries = store::load_store()?;

    // Find entries with stale scopes (Path that no longer exists as a directory)
    let stale_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| match &e.scope {
            Scope::Path(p) => !p.is_dir(),
            Scope::Global => false,
        })
        .map(|(i, _)| i)
        .collect();

    if stale_indices.is_empty() {
        eprintln!("All scoped entries point to existing directories.");
        return Ok(());
    }

    eprintln!("Found {} entries with stale scopes:", stale_indices.len());
    for &idx in &stale_indices {
        let entry = &entries[idx];
        let icon = if entry.sensitive { "\u{1F512}" } else { "\u{1F4CB}" };
        eprintln!(
            "  {} {} [{}] \u{2014} {}",
            icon, entry.name, entry.scope, entry.description,
        );
    }
    eprintln!();

    let confirm = inquire::Confirm::new("Remove these entries?")
        .with_default(false)
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    if !confirm {
        return Ok(());
    }

    // Remove stale entries in reverse order to preserve indices
    for &idx in stale_indices.iter().rev() {
        entries.remove(idx);
    }

    store::save_store(&entries)?;

    eprintln!("Removed {} stale entries.", stale_indices.len());
    Ok(())
}
