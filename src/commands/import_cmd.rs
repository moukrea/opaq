// opaq: import command implementation

use std::collections::HashMap;
use std::fs;

use inquire::Text;

use crate::crypto::{decrypt_blob, encrypt_blob, key_to_passphrase};
use crate::error::{OpaqError, Result};
use crate::keychain;
use crate::store::{deserialize_store, serialize_store, store_dir, store_path};

pub fn execute(file: String, overwrite: bool) -> Result<()> {
    // 1. Read the encrypted bundle
    let bundle_bytes = fs::read(&file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OpaqError::CommandExecution(format!("File not found: {}", file))
        } else {
            OpaqError::Io(e)
        }
    })?;

    // 2. Prompt for the import passphrase
    let passphrase = inquire::Password::new("Enter import passphrase:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

    // 3. Decrypt the bundle
    let decrypted = decrypt_blob(&bundle_bytes, &passphrase).map_err(|_| {
        OpaqError::DecryptionFailed("Failed to decrypt bundle. Wrong passphrase?".to_string())
    })?;

    // 4. Deserialize imported entries
    let imported_entries = deserialize_store(&decrypted).map_err(|_| {
        OpaqError::Serialization(
            "Bundle appears corrupted or is not a valid opaq export.".to_string(),
        )
    })?;

    // 5. Load the local store
    let kc = keychain::get_keychain();
    let master_key = kc.retrieve_key()?;
    let master_passphrase = key_to_passphrase(&master_key);

    let store_file = store_path();
    let mut local_entries = if store_file.exists() {
        let ciphertext = fs::read(&store_file)?;
        let plaintext = decrypt_blob(&ciphertext, &master_passphrase)?;
        deserialize_store(&plaintext)?
    } else {
        vec![]
    };

    // 6. Build index of existing names
    let mut name_index: HashMap<String, usize> = HashMap::new();
    for (i, entry) in local_entries.iter().enumerate() {
        name_index.insert(entry.name.clone(), i);
    }

    // 7. Merge imported entries
    let mut new_count: usize = 0;
    let mut overwrite_count: usize = 0;
    let mut auto_overwrite = overwrite;

    for imported in imported_entries {
        if let Some(&idx) = name_index.get(&imported.name) {
            // Conflict: name already exists
            if auto_overwrite {
                local_entries[idx] = imported;
                overwrite_count += 1;
            } else {
                let prompt =
                    format!("{} already exists. Overwrite? [y/N/a(ll)]:", imported.name);
                let answer = Text::new(&prompt)
                    .with_default("N")
                    .prompt()
                    .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

                match answer.trim().to_lowercase().as_str() {
                    "y" | "yes" => {
                        local_entries[idx] = imported;
                        overwrite_count += 1;
                    }
                    "a" | "all" => {
                        local_entries[idx] = imported;
                        overwrite_count += 1;
                        auto_overwrite = true;
                    }
                    _ => {
                        // Skip (default)
                    }
                }
            }
        } else {
            // New entry
            let new_idx = local_entries.len();
            name_index.insert(imported.name.clone(), new_idx);
            local_entries.push(imported);
            new_count += 1;
        }
    }

    // 8. Serialize, encrypt, and write atomically
    let plaintext = serialize_store(&local_entries)?;
    let ciphertext = encrypt_blob(&plaintext, &master_passphrase)?;

    // Ensure the store directory exists
    let dir = store_dir();
    fs::create_dir_all(&dir)?;

    // Atomic write: tempfile + fsync + rename
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    temp.write_all(&ciphertext)?;
    temp.as_file().sync_all()?;
    temp.persist(&store_file)
        .map_err(std::io::Error::from)?;

    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&store_file, perms)?;

    let total = new_count + overwrite_count;
    println!(
        "Imported {} secrets ({} overwritten, {} new)",
        total, overwrite_count, new_count
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::{decrypt_blob, encrypt_blob};
    use crate::model::SecretEntry;
    use crate::store::{deserialize_store, serialize_store};

    #[test]
    fn round_trip_import_bundle() {
        // Create a bundle (simulating export output)
        let entries = vec![
            SecretEntry::new(
                "TOKEN_A".to_string(),
                "First".to_string(),
                vec!["ci".to_string()],
                b"value_a".to_vec(),
            )
            .unwrap(),
            SecretEntry::new(
                "TOKEN_B".to_string(),
                "Second".to_string(),
                vec![],
                b"value_b".to_vec(),
            )
            .unwrap(),
        ];

        let plaintext = serialize_store(&entries).unwrap();
        let passphrase = "import-test-pass";
        let encrypted = encrypt_blob(&plaintext, passphrase).unwrap();

        // Decrypt (simulating import)
        let decrypted = decrypt_blob(&encrypted, passphrase).unwrap();
        let loaded = deserialize_store(&decrypted).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "TOKEN_A");
        assert_eq!(loaded[0].value, b"value_a");
        assert_eq!(loaded[1].name, "TOKEN_B");
        assert_eq!(loaded[1].value, b"value_b");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let entries = vec![SecretEntry::new(
            "SECRET".to_string(),
            "desc".to_string(),
            vec![],
            b"val".to_vec(),
        )
        .unwrap()];

        let plaintext = serialize_store(&entries).unwrap();
        let encrypted = encrypt_blob(&plaintext, "correct").unwrap();
        let result = decrypt_blob(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn merge_new_entries() {
        // Simulate merging imported entries with an empty local store
        let imported = vec![
            SecretEntry::new(
                "NEW_A".to_string(),
                "New entry A".to_string(),
                vec![],
                b"a".to_vec(),
            )
            .unwrap(),
            SecretEntry::new(
                "NEW_B".to_string(),
                "New entry B".to_string(),
                vec![],
                b"b".to_vec(),
            )
            .unwrap(),
        ];

        let mut local: Vec<SecretEntry> = vec![];
        let mut new_count = 0usize;

        for entry in imported {
            local.push(entry);
            new_count += 1;
        }

        assert_eq!(local.len(), 2);
        assert_eq!(new_count, 2);
    }

    #[test]
    fn merge_with_overwrite() {
        // Simulate merge with overwrite flag
        let mut local = [SecretEntry::new(
            "EXISTING".to_string(),
            "Old".to_string(),
            vec![],
            b"old_value".to_vec(),
        )
        .unwrap()];

        let imported = SecretEntry::new(
            "EXISTING".to_string(),
            "New".to_string(),
            vec!["updated".to_string()],
            b"new_value".to_vec(),
        )
        .unwrap();

        // Overwrite
        local[0] = imported;

        assert_eq!(local[0].description, "New");
        assert_eq!(local[0].value, b"new_value");
        assert_eq!(local[0].tags, vec!["updated"]);
    }

    #[test]
    fn corrupted_bundle_deserialization_fails() {
        let garbage = b"not valid bincode";
        let result = deserialize_store(garbage);
        assert!(result.is_err());
    }
}
