// opaq: encrypted store operations (read, write, atomic save)

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use crate::crypto::key_to_passphrase;
use crate::error::{OpaqError, Result};
use crate::model::SecretEntry;

pub fn serialize_store(entries: &[SecretEntry]) -> Result<Vec<u8>> {
    bincode::serialize(entries).map_err(|e| OpaqError::Serialization(e.to_string()))
}

pub fn deserialize_store(data: &[u8]) -> Result<Vec<SecretEntry>> {
    bincode::deserialize(data).map_err(|e| OpaqError::Serialization(e.to_string()))
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
            )
            .unwrap(),
            SecretEntry::new(
                "TOKEN_B".to_string(),
                "Second token".to_string(),
                vec!["registry".to_string()],
                vec![0x00, 0x01, 0xFF, 0xFE],
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
            )
            .unwrap(),
            SecretEntry::new(
                "OTHER_TOKEN".to_string(),
                "Another token".to_string(),
                vec!["api".to_string(), "ci".to_string()],
                b"token123".to_vec(),
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
