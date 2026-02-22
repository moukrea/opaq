// opaq: add command implementation

use crate::error::{OpaqError, Result};
use crate::model::{normalize_tags, validate_name, SecretEntry};
use crate::store;

pub fn execute(name: String, description: String, tags: Option<String>) -> Result<()> {
    // Validate name format
    validate_name(&name)?;

    // Load existing store (handles keychain retrieval and decryption)
    let mut entries = store::load_store()?;

    // Check name uniqueness
    if entries.iter().any(|e| e.name == name) {
        return Err(OpaqError::DuplicateName(name));
    }

    // Parse and normalize tags
    let tag_list = match tags {
        Some(ref t) => {
            let raw: Vec<String> = t.split(',').map(|s| s.to_string()).collect();
            normalize_tags(&raw)
        }
        None => vec![],
    };

    // Prompt for secret value on /dev/tty (masked with confirmation)
    let value = prompt_secret_value()?;

    // Create new entry
    let entry = SecretEntry::new(name.clone(), description, tag_list, value.into_bytes())?;

    // Add to store
    entries.push(entry);

    // Save store atomically
    store::save_store(&entries)?;

    eprintln!("  Secret {} stored (encrypted)", name);
    Ok(())
}

fn prompt_secret_value() -> Result<String> {
    let value = inquire::Password::new("  Enter secret value:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    let confirm = inquire::Password::new("  Confirm value:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    if value != confirm {
        return Err(OpaqError::Io(std::io::Error::other("Values do not match.")));
    }

    Ok(value)
}
