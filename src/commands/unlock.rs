// opaq: unlock command implementation

use crate::crypto::{derive_key_from_passphrase, key_to_passphrase};
use crate::error::{OpaqError, Result};
use crate::store::{metadata_path, store_path};

pub fn execute() -> Result<()> {
    let store = store_path();
    if !store.exists() {
        return Err(OpaqError::StoreNotFound);
    }

    let meta_path = metadata_path();
    if meta_path.exists() {
        // Passphrase mode
        unlock_passphrase_mode(&meta_path)
    } else {
        // Default mode — check if key is already in keychain
        unlock_default_mode()
    }
}

fn unlock_default_mode() -> Result<()> {
    let keychain = crate::keychain::get_keychain();
    match keychain.retrieve_key() {
        Ok(_) => {
            eprintln!("Store is already unlocked.");
            Ok(())
        }
        Err(OpaqError::StoreLocked) => {
            Err(OpaqError::KeychainError(
                "Master key not found in keychain. In default mode, the key is stored at init time. If you ran `opaq lock`, the key is gone. Re-initialize with `opaq init --force`.".to_string(),
            ))
        }
        Err(e) => Err(e),
    }
}

fn unlock_passphrase_mode(meta_path: &std::path::Path) -> Result<()> {
    use base64::Engine;

    // Read stored metadata
    let meta_content = std::fs::read_to_string(meta_path)?;
    let meta: serde_json::Value = serde_json::from_str(&meta_content)
        .map_err(|e| OpaqError::Serialization(e.to_string()))?;

    let salt_b64 = meta["salt"]
        .as_str()
        .ok_or_else(|| OpaqError::Serialization("Missing salt in metadata".to_string()))?;
    let stored_hash_b64 = meta["verification_hash"]
        .as_str()
        .ok_or_else(|| OpaqError::Serialization("Missing verification_hash in metadata".to_string()))?;

    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|e| OpaqError::Serialization(format!("Invalid salt encoding: {e}")))?;
    let stored_hash = base64::engine::general_purpose::STANDARD
        .decode(stored_hash_b64)
        .map_err(|e| OpaqError::Serialization(format!("Invalid hash encoding: {e}")))?;

    // Prompt for passphrase
    let passphrase = inquire::Password::new("Enter master passphrase:")
        .without_confirmation()
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    // Derive key and verify
    let derived_key = derive_key_from_passphrase(&passphrase, &salt)?;

    if derived_key.as_slice() != stored_hash.as_slice() {
        return Err(OpaqError::InvalidPassphrase);
    }

    // Cache key in OS keychain
    let keychain = crate::keychain::get_keychain();
    keychain.store_key(&derived_key)?;

    // Verify it works by trying to decrypt the store
    let pass = key_to_passphrase(&derived_key);
    crate::store::read_store(&pass)?;

    eprintln!("Store unlocked.");
    Ok(())
}
