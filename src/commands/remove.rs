// opaq: remove command implementation

use crate::error::{OpaqError, Result};
use crate::store;

pub fn execute(name: String) -> Result<()> {
    // Load existing store
    let mut entries = store::load_store()?;

    // Find all entries matching the name
    let matching: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.name == name)
        .map(|(i, _)| i)
        .collect();

    let pos = match matching.len() {
        0 => return Err(OpaqError::SecretNotFound(name.clone())),
        1 => matching[0],
        _ => disambiguate(&entries, &matching, &name)?,
    };

    // Prompt for confirmation (default: No)
    let prompt = format!("Remove {}? This cannot be undone.", name);
    let confirm = inquire::Confirm::new(&prompt)
        .with_default(false)
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    if !confirm {
        return Ok(());
    }

    // Remove entry
    entries.remove(pos);

    // Save store atomically
    store::save_store(&entries)?;

    eprintln!("  Secret {} removed", name);
    Ok(())
}

fn disambiguate(
    entries: &[crate::model::SecretEntry],
    indices: &[usize],
    name: &str,
) -> Result<usize> {
    eprintln!("Multiple entries named '{}':", name);
    for (i, &idx) in indices.iter().enumerate() {
        let entry = &entries[idx];
        let icon = if entry.sensitive { "\u{1F512}" } else { "\u{1F4CB}" };
        eprintln!(
            "  {}. {} {} [{}] \u{2014} {}",
            i + 1,
            icon,
            entry.name,
            entry.scope,
            entry.description,
        );
    }

    let prompt = format!("Which entry to remove? (1-{})", indices.len());
    let input = inquire::Text::new(&prompt)
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    let choice: usize = input
        .trim()
        .parse()
        .map_err(|_| OpaqError::AmbiguousEntry(name.to_string()))?;

    if choice < 1 || choice > indices.len() {
        return Err(OpaqError::AmbiguousEntry(name.to_string()));
    }

    Ok(indices[choice - 1])
}
