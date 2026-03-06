// opaq: encrypted store operations (read, write, atomic save)

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::crypto::key_to_passphrase;
use crate::error::{OpaqError, Result};
use crate::model::{Scope, SecretEntry};

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
struct SecretEntryV0 {
    name: String,
    description: String,
    tags: Vec<String>,
    value: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<SecretEntryV0> for SecretEntry {
    fn from(old: SecretEntryV0) -> Self {
        SecretEntry {
            name: old.name,
            description: old.description,
            tags: old.tags,
            value: old.value,
            created_at: old.created_at,
            updated_at: old.updated_at,
            sensitive: true,
            scope: Scope::Global,
        }
    }
}

pub fn serialize_store(entries: &[SecretEntry]) -> Result<Vec<u8>> {
    let mut out = vec![0x01u8];
    let payload =
        bincode::serialize(entries).map_err(|e| OpaqError::Serialization(e.to_string()))?;
    out.extend(payload);
    Ok(out)
}

pub fn deserialize_store(data: &[u8]) -> Result<Vec<SecretEntry>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] == 0x01 {
        bincode::deserialize(&data[1..]).map_err(|e| OpaqError::Serialization(e.to_string()))
    } else {
        let old_entries: Vec<SecretEntryV0> =
            bincode::deserialize(data).map_err(|e| OpaqError::Serialization(e.to_string()))?;
        Ok(old_entries.into_iter().map(SecretEntry::from).collect())
    }
}

pub fn store_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OPAQ_STORE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}/.config",
                std::env::var("HOME").unwrap_or_else(|_| String::from("~"))
            ))
        })
        .join("opaq")
}

pub fn store_path() -> PathBuf {
    store_dir().join("store")
}

pub fn metadata_path() -> PathBuf {
    store_dir().join("metadata")
}

pub fn read_store(passphrase: &str) -> Result<Vec<SecretEntry>> {
    read_store_from(&store_path(), passphrase)
}

fn read_store_from(path: &std::path::Path, passphrase: &str) -> Result<Vec<SecretEntry>> {
    if !path.exists() {
        return Err(OpaqError::StoreNotFound);
    }
    let ciphertext = fs::read(path)?;
    let plaintext = crate::crypto::decrypt_blob(&ciphertext, passphrase)?;
    deserialize_store(&plaintext)
}

pub fn write_store(entries: &[SecretEntry], passphrase: &str) -> Result<()> {
    write_store_to(&store_dir(), &store_path(), entries, passphrase)
}

fn write_store_to(
    dir: &std::path::Path,
    path: &std::path::Path,
    entries: &[SecretEntry],
    passphrase: &str,
) -> Result<()> {
    fs::create_dir_all(dir)?;

    // Set directory permissions to 0700
    let dir_perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(dir, dir_perms)?;

    let plaintext = serialize_store(entries)?;
    let ciphertext = crate::crypto::encrypt_blob(&plaintext, passphrase)?;

    // Write to a tempfile in the same directory (required for atomic rename)
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(&ciphertext)?;

    // fsync to ensure data is flushed to disk
    temp.as_file().sync_all()?;

    // Atomically rename temp file to store path
    temp.persist(path).map_err(std::io::Error::from)?;

    // Set permissions to 0600
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;

    Ok(())
}

/// Load the store using the master key from the OS keychain.
pub fn load_store() -> Result<Vec<SecretEntry>> {
    let keychain = crate::keychain::get_keychain();
    let key = keychain.retrieve_key()?;
    let passphrase = key_to_passphrase(&key);
    read_store(&passphrase)
}

/// Save the store using the master key from the OS keychain.
pub fn save_store(entries: &[SecretEntry]) -> Result<()> {
    let keychain = crate::keychain::get_keychain();
    let key = keychain.retrieve_key()?;
    let passphrase = key_to_passphrase(&key);
    write_store(entries, &passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_multiple_entries() {
        let entries = vec![
            SecretEntry::new(
                "TOKEN_A".to_string(),
                "First token".to_string(),
                vec!["ci".to_string(), "api".to_string()],
                b"secret_value_a".to_vec(),
                true,
                crate::model::Scope::Global,
            )
            .unwrap(),
            SecretEntry::new(
                "TOKEN_B".to_string(),
                "Second token".to_string(),
                vec!["registry".to_string()],
                vec![0x00, 0x01, 0xFF, 0xFE],
                true,
                crate::model::Scope::Global,
            )
            .unwrap(),
        ];

        let serialized = serialize_store(&entries).unwrap();
        let deserialized = deserialize_store(&serialized).unwrap();

        assert_eq!(deserialized.len(), 2);

        assert_eq!(deserialized[0].name, "TOKEN_A");
        assert_eq!(deserialized[0].description, "First token");
        assert_eq!(deserialized[0].tags, vec!["api", "ci"]);
        assert_eq!(deserialized[0].value, b"secret_value_a");
        assert_eq!(deserialized[0].created_at, entries[0].created_at);
        assert_eq!(deserialized[0].updated_at, entries[0].updated_at);

        assert_eq!(deserialized[1].name, "TOKEN_B");
        assert_eq!(deserialized[1].description, "Second token");
        assert_eq!(deserialized[1].tags, vec!["registry"]);
        assert_eq!(deserialized[1].value, vec![0x00, 0x01, 0xFF, 0xFE]);
        assert_eq!(deserialized[1].created_at, entries[1].created_at);
        assert_eq!(deserialized[1].updated_at, entries[1].updated_at);
    }

    #[test]
    fn round_trip_empty_store() {
        let entries: Vec<SecretEntry> = vec![];
        let serialized = serialize_store(&entries).unwrap();
        let deserialized = deserialize_store(&serialized).unwrap();
        assert!(deserialized.is_empty());
    }

    #[test]
    fn deserialize_empty_bytes_returns_empty_vec() {
        let deserialized = deserialize_store(&[]).unwrap();
        assert!(deserialized.is_empty());
    }

    #[test]
    fn deserialize_garbage_returns_error() {
        let garbage = b"this is not valid bincode data at all";
        let result = deserialize_store(garbage);
        assert!(result.is_err());
        match result.unwrap_err() {
            OpaqError::Serialization(_) => {}
            other => panic!("Expected Serialization error, got: {:?}", other),
        }
    }

    #[test]
    fn v0_to_v1_migration() {
        // Serialize entries in V0 format (raw bincode, no version prefix)
        // Use 2 entries so the bincode length prefix byte is 0x02, not 0x01
        let now = chrono::Utc::now();
        let v0_entries = vec![
            SecretEntryV0 {
                name: "OLD_TOKEN_A".to_string(),
                description: "A legacy token".to_string(),
                tags: vec!["ci".to_string()],
                value: b"old_secret_a".to_vec(),
                created_at: now,
                updated_at: now,
            },
            SecretEntryV0 {
                name: "OLD_TOKEN_B".to_string(),
                description: "Another legacy token".to_string(),
                tags: vec![],
                value: b"old_secret_b".to_vec(),
                created_at: now,
                updated_at: now,
            },
        ];
        let v0_bytes = bincode::serialize(&v0_entries).unwrap();

        // First byte should not be 0x01 (V0 format uses bincode length prefix)
        assert_ne!(v0_bytes[0], 0x01);

        // Deserialize should migrate to V1
        let migrated = deserialize_store(&v0_bytes).unwrap();
        assert_eq!(migrated.len(), 2);
        assert_eq!(migrated[0].name, "OLD_TOKEN_A");
        assert_eq!(migrated[0].description, "A legacy token");
        assert_eq!(migrated[0].tags, vec!["ci"]);
        assert_eq!(migrated[0].value, b"old_secret_a");
        assert!(migrated[0].sensitive);
        assert_eq!(migrated[0].scope, crate::model::Scope::Global);
        assert_eq!(migrated[1].name, "OLD_TOKEN_B");
        assert!(migrated[1].sensitive);
        assert_eq!(migrated[1].scope, crate::model::Scope::Global);
    }

    #[test]
    fn v1_version_byte_routing() {
        // Serialize with V1 format
        let entries = vec![
            SecretEntry::new(
                "V1_TOKEN".to_string(),
                "A V1 token".to_string(),
                vec![],
                b"v1_value".to_vec(),
                false,
                crate::model::Scope::Global,
            )
            .unwrap(),
        ];
        let serialized = serialize_store(&entries).unwrap();

        // First byte should be 0x01
        assert_eq!(serialized[0], 0x01);

        // Deserialize should preserve V1 fields
        let deserialized = deserialize_store(&serialized).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized[0].name, "V1_TOKEN");
        assert!(!deserialized[0].sensitive);
    }

    #[test]
    fn write_then_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let path = dir.join("store");
        let passphrase = "test-passphrase";

        let entries = vec![
            SecretEntry::new(
                "MY_SECRET".to_string(),
                "A test secret".to_string(),
                vec!["test".to_string()],
                b"supersecretvalue".to_vec(),
                true,
                crate::model::Scope::Global,
            )
            .unwrap(),
            SecretEntry::new(
                "OTHER_TOKEN".to_string(),
                "Another token".to_string(),
                vec!["api".to_string(), "ci".to_string()],
                b"token123".to_vec(),
                true,
                crate::model::Scope::Global,
            )
            .unwrap(),
        ];

        write_store_to(&dir, &path, &entries, passphrase).unwrap();

        // Verify file exists with correct permissions
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        // Read back and verify
        let loaded = read_store_from(&path, passphrase).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "MY_SECRET");
        assert_eq!(loaded[0].description, "A test secret");
        assert_eq!(loaded[0].tags, vec!["test"]);
        assert_eq!(loaded[0].value, b"supersecretvalue");
        assert_eq!(loaded[1].name, "OTHER_TOKEN");
        assert_eq!(loaded[1].value, b"token123");
    }

    #[test]
    fn read_nonexistent_store_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent");
        let result = read_store_from(&path, "passphrase");
        assert!(matches!(result, Err(OpaqError::StoreNotFound)));
    }

    #[test]
    fn write_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested").join("opaq");
        let path = dir.join("store");
        let passphrase = "test";

        let entries = vec![];
        write_store_to(&dir, &path, &entries, passphrase).unwrap();
        assert!(path.exists());
    }
}
