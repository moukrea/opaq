// opaq: init command implementation

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use crate::crypto::{
    derive_key_from_passphrase, encrypt_blob, generate_master_key, key_to_passphrase,
};
use crate::error::{OpaqError, Result};
use crate::model::SecretEntry;
use crate::store::{metadata_path, serialize_store, store_dir, store_path};

pub fn execute(passphrase: bool, force: bool) -> Result<()> {
    let path = store_path();

    // Check if store already exists
    if path.exists() && !force {
        return Err(OpaqError::StoreAlreadyExists);
    }

    // If --force, prompt for confirmation
    if path.exists() && force {
        let confirm = inquire::Confirm::new(
            "This will destroy your existing store and all secrets. Continue?",
        )
        .with_default(false)
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

        if !confirm {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    if passphrase {
        execute_passphrase_mode()
    } else {
        execute_default_mode()
    }
}

fn execute_default_mode() -> Result<()> {
    eprintln!();
    eprintln!("  opaq -- First-Time Setup");
    eprintln!();

    // Generate master key
    eprintln!("  Generating master key...");
    let key = generate_master_key();

    // Store in OS keychain
    let keychain = crate::keychain::get_keychain();
    keychain.store_key(&key)?;
    eprintln!("  Master key stored in OS keychain");

    // Create empty encrypted store
    eprintln!();
    eprintln!("  Creating encrypted store...");
    let pass = key_to_passphrase(&key);
    write_empty_store(&pass)?;

    let path = store_path();
    eprintln!("  Store created at {}", path.display());
    eprintln!();
    eprintln!("  Ready. Add your first secret:");
    eprintln!("    opaq add MY_TOKEN \"Description of what this token is for\"");
    eprintln!();

    Ok(())
}

fn execute_passphrase_mode() -> Result<()> {
    eprintln!();
    eprintln!("  opaq -- First-Time Setup (passphrase mode)");
    eprintln!();

    // Prompt for passphrase twice
    let pass1 = inquire::Password::new("  Enter master passphrase:")
        .without_confirmation()
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    let pass2 = inquire::Password::new("  Confirm passphrase:")
        .without_confirmation()
        .prompt()
        .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

    if pass1 != pass2 {
        return Err(OpaqError::PassphraseMismatch);
    }

    // Derive key via Argon2id
    eprintln!();
    eprintln!("  Deriving key (Argon2id)...");
    let salt: [u8; 16] = {
        let mut s = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
        s
    };
    let key = derive_key_from_passphrase(&pass1, &salt)?;

    // Store verification hash (salt + hash) in metadata file
    // We store the salt and a verification hash so `unlock` can verify the passphrase
    let verification_key = derive_key_from_passphrase(&pass1, &salt)?;
    save_passphrase_metadata(&salt, &verification_key)?;

    // Create empty encrypted store using derived key
    let pass = key_to_passphrase(&key);
    write_empty_store(&pass)?;

    let path = store_path();
    eprintln!("  Store created at {}", path.display());
    eprintln!();
    eprintln!("  Your store is locked by default.");
    eprintln!("  Run `opaq unlock` at the start of each session.");
    eprintln!();

    Ok(())
}

fn write_empty_store(passphrase: &str) -> Result<()> {
    let dir = store_dir();
    fs::create_dir_all(&dir)?;

    // Set directory permissions to 0700
    let dir_perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&dir, dir_perms)?;

    let entries: Vec<SecretEntry> = vec![];
    let plaintext = serialize_store(&entries)?;
    let ciphertext = encrypt_blob(&plaintext, passphrase)?;

    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    temp.write_all(&ciphertext)?;
    temp.as_file().sync_all()?;

    let path = store_path();
    temp.persist(&path)
        .map_err(std::io::Error::from)?;

    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&path, perms)?;

    Ok(())
}

/// Save passphrase verification metadata: salt + derived key hash.
/// Format: JSON with salt (base64) and verification_hash (base64).
fn save_passphrase_metadata(salt: &[u8; 16], verification_key: &[u8; 32]) -> Result<()> {
    use base64::Engine;

    let dir = store_dir();
    fs::create_dir_all(&dir)?;

    let metadata = serde_json::json!({
        "mode": "passphrase",
        "salt": base64::engine::general_purpose::STANDARD.encode(salt),
        "verification_hash": base64::engine::general_purpose::STANDARD.encode(verification_key),
    });

    let path = metadata_path();
    let data = serde_json::to_string_pretty(&metadata)
        .map_err(|e| OpaqError::Serialization(e.to_string()))?;

    fs::write(&path, data)?;

    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&path, perms)?;

    Ok(())
}
