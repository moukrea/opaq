// opaq: remove command implementation

use crate::error::{OpaqError, Result};
use crate::store;

pub fn execute(name: String) -> Result<()> {
    // Load existing store
    let mut entries = store::load_store()?;

    // Find entry by name
    let pos = entries
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| OpaqError::SecretNotFound(name.clone()))?;

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
