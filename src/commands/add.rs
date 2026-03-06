// opaq: add command implementation

use std::path::PathBuf;

use crate::error::{OpaqError, Result};
use crate::model::{normalize_tags, validate_name, Scope, SecretEntry};
use crate::store;

#[allow(clippy::too_many_arguments)]
pub fn execute(
    name: String,
    description: String,
    tags: Option<String>,
    secret: bool,
    plain: bool,
    global: bool,
    user: bool,
    current: bool,
) -> Result<()> {
    // Validate name format
    validate_name(&name)?;

    // Load existing store (handles keychain retrieval and decryption)
    let mut entries = store::load_store()?;

    // Parse and normalize tags
    let tag_list = match tags {
        Some(ref t) => {
            let raw: Vec<String> = t.split(',').map(|s| s.to_string()).collect();
            normalize_tags(&raw)
        }
        None => vec![],
    };

    // Resolve sensitivity
    let sensitive = if secret {
        true
    } else if plain {
        false
    } else {
        prompt_sensitivity()?
    };

    // Resolve scope
    let scope = resolve_scope(global, user, current)?;

    // Check name + scope uniqueness
    if entries.iter().any(|e| e.name == name && e.scope == scope) {
        return Err(OpaqError::DuplicateName(name));
    }

    // Prompt for secret value on /dev/tty (masked with confirmation)
    let value = prompt_secret_value()?;

    // Create new entry
    let entry = SecretEntry::new(
        name.clone(),
        description,
        tag_list,
        value.into_bytes(),
        sensitive,
        scope,
    )?;

    // Add to store
    entries.push(entry);

    // Save store atomically
    store::save_store(&entries)?;

    eprintln!("  Secret {} stored (encrypted)", name);
    Ok(())
}

fn resolve_scope(global: bool, user: bool, current: bool) -> Result<Scope> {
    if global {
        Ok(Scope::Global)
    } else if user {
        let home = dirs::home_dir()
            .ok_or_else(|| OpaqError::Io(std::io::Error::other("Cannot determine home directory")))?;
        let canon = std::fs::canonicalize(&home)?;
        Ok(Scope::Path(canon))
    } else if current {
        let cwd = std::env::current_dir()?;
        let canon = std::fs::canonicalize(&cwd)?;
        Ok(Scope::Path(canon))
    } else {
        prompt_scope()
    }
}

pub fn prompt_scope() -> Result<Scope> {
    let cwd_display = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let options = vec![
        "Global -- available everywhere (default)".to_string(),
        "User -- available under your home directory".to_string(),
        format!("Current directory -- available under {}", cwd_display),
        "Other -- specify a custom path".to_string(),
    ];
    let selection = inquire::Select::new("Entry scope:", options.clone())
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    if selection.starts_with("Global") {
        Ok(Scope::Global)
    } else if selection.starts_with("User") {
        let home = dirs::home_dir()
            .ok_or_else(|| OpaqError::Io(std::io::Error::other("Cannot determine home directory")))?;
        let canon = std::fs::canonicalize(&home)?;
        Ok(Scope::Path(canon))
    } else if selection.starts_with("Current") {
        let cwd = std::env::current_dir()?;
        let canon = std::fs::canonicalize(&cwd)?;
        Ok(Scope::Path(canon))
    } else {
        // "Other" -- prompt for path
        let path_str = inquire::Text::new("Directory path:")
            .prompt()
            .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;
        validate_scope_path(&path_str)
    }
}

fn validate_scope_path(path_str: &str) -> Result<Scope> {
    let path = PathBuf::from(path_str);
    let meta = std::fs::metadata(&path).map_err(|_| {
        OpaqError::InvalidScopePath(path_str.to_string())
    })?;
    if !meta.is_dir() {
        return Err(OpaqError::InvalidScopePath(path_str.to_string()));
    }
    let canon = std::fs::canonicalize(&path)?;
    Ok(Scope::Path(canon))
}

fn prompt_sensitivity() -> Result<bool> {
    let options = vec![
        "Secret -- value is masked and scrubbed from output (default)",
        "Plain -- non-sensitive data, can be revealed",
    ];
    let selection = inquire::Select::new("Sensitivity level:", options)
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;
    Ok(selection.starts_with("Secret"))
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
