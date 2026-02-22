// opaq: edit command implementation

use chrono::Utc;

use crate::error::{OpaqError, Result};
use crate::model::normalize_tags;
use crate::store;

pub fn execute(
    name: String,
    desc: Option<String>,
    tags: Option<String>,
    rotate: bool,
) -> Result<()> {
    // Load existing store
    let mut entries = store::load_store()?;

    // Find entry by name
    let entry = entries
        .iter_mut()
        .find(|e| e.name == name)
        .ok_or_else(|| OpaqError::SecretNotFound(name.clone()))?;

    let has_flags = desc.is_some() || tags.is_some() || rotate;

    if has_flags {
        // Flag-based editing
        if let Some(new_desc) = desc {
            entry.description = new_desc;
        }

        if let Some(new_tags) = tags {
            let raw: Vec<String> = new_tags.split(',').map(|s| s.to_string()).collect();
            entry.tags = normalize_tags(&raw);
        }

        if rotate {
            let value = prompt_secret_value()?;
            entry.value = value.into_bytes();
        }
    } else {
        // Interactive menu (no flags provided)
        let options = vec!["Edit description", "Edit tags", "Rotate value"];
        let selection = inquire::Select::new("What would you like to edit?", options)
            .prompt()
            .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

        match selection {
            "Edit description" => {
                let new_desc =
                    inquire::Text::new("  Description:")
                        .with_default(&entry.description)
                        .prompt()
                        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;
                entry.description = new_desc;
            }
            "Edit tags" => {
                let current = entry.tags.join(",");
                let new_tags = inquire::Text::new("  Tags (comma-separated):")
                    .with_default(&current)
                    .prompt()
                    .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;
                let raw: Vec<String> = new_tags.split(',').map(|s| s.to_string()).collect();
                entry.tags = normalize_tags(&raw);
            }
            "Rotate value" => {
                let value = prompt_secret_value()?;
                entry.value = value.into_bytes();
            }
            _ => unreachable!(),
        }
    }

    // Update timestamp
    entry.updated_at = Utc::now();

    // Save store atomically
    store::save_store(&entries)?;

    eprintln!("  Secret {} updated", name);
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
        return Err(OpaqError::Io(std::io::Error::other(
            "Values do not match.",
        )));
    }

    Ok(value)
}
