// opaq: export command implementation

use std::fs;

use inquire::Password;

use crate::crypto::{decrypt_blob, encrypt_blob, key_to_passphrase};
use crate::error::{OpaqError, Result};
use crate::keychain;
use crate::store::{deserialize_store, store_path};

pub fn execute(file: String) -> Result<()> {
    // 1. Retrieve master key from OS keychain
    let kc = keychain::get_keychain();
    let master_key = kc.retrieve_key()?;
    let master_passphrase = key_to_passphrase(&master_key);

    // 2. Read and decrypt the local store
    let store_file = store_path();
    if !store_file.exists() {
        return Err(OpaqError::StoreNotFound);
    }
    let ciphertext = fs::read(&store_file)?;
    let plaintext = decrypt_blob(&ciphertext, &master_passphrase)?;

    // Count entries for the success message
    let entries = deserialize_store(&plaintext)?;
    let count = entries.len();

    // 3. Prompt for export passphrase (with confirmation)
    let passphrase = Password::new("Enter export passphrase:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

    let confirm = Password::new("Confirm passphrase:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

    if passphrase != confirm {
        return Err(OpaqError::PassphraseMismatch);
    }

    // 4. Re-encrypt the store bytes with the export passphrase
    let export_encrypted = encrypt_blob(&plaintext, &passphrase)?;

    // 5. Write to the output file
    fs::write(&file, &export_encrypted)?;

    println!("Exported {} secrets to {} (encrypted)", count, file);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_blob;
    use crate::store::serialize_store;
    use crate::model::SecretEntry;

    #[test]
    fn round_trip_export_decrypt() {
        // Simulate the export process: serialize entries, encrypt with a
        // passphrase, then decrypt and verify.
        let entries = vec![
            SecretEntry::new(
                "TOKEN_A".to_string(),
                "First token".to_string(),
                vec!["ci".to_string()],
                b"secret_a".to_vec(),
            )
            .unwrap(),
            SecretEntry::new(
                "TOKEN_B".to_string(),
                "Second token".to_string(),
                vec!["api".to_string()],
                b"secret_b".to_vec(),
            )
            .unwrap(),
        ];

        let plaintext = serialize_store(&entries).unwrap();
        let export_passphrase = "export-test-passphrase";

        // Encrypt (simulating export)
        let encrypted = encrypt_blob(&plaintext, export_passphrase).unwrap();

        // Decrypt (simulating import)
        let decrypted = decrypt_blob(&encrypted, export_passphrase).unwrap();

        assert_eq!(decrypted, plaintext);

        // Verify the deserialized entries match
        let loaded = deserialize_store(&decrypted).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "TOKEN_A");
        assert_eq!(loaded[0].value, b"secret_a");
        assert_eq!(loaded[1].name, "TOKEN_B");
        assert_eq!(loaded[1].value, b"secret_b");
    }

    #[test]
    fn wrong_passphrase_fails_decrypt() {
        let entries = vec![SecretEntry::new(
            "MY_SECRET".to_string(),
            "desc".to_string(),
            vec![],
            b"value".to_vec(),
        )
        .unwrap()];

        let plaintext = serialize_store(&entries).unwrap();
        let encrypted = encrypt_blob(&plaintext, "correct-passphrase").unwrap();

        let result = decrypt_blob(&encrypted, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn passphrase_mismatch_error() {
        // Verify the PassphraseMismatch error variant works correctly
        let err = OpaqError::PassphraseMismatch;
        assert_eq!(err.exit_code(), 1);
        assert_eq!(format!("{}", err), "Passphrases do not match.");
    }
}
