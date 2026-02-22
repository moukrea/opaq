// opaq: OS keychain integration (platform-specific master key storage)

pub trait Keychain {
    /// Store the 32-byte master key in the OS keychain.
    fn store_key(&self, key: &[u8; 32]) -> crate::error::Result<()>;

    /// Retrieve the master key from the OS keychain.
    /// Returns OpaqError::StoreLocked if no key is found.
    fn retrieve_key(&self) -> crate::error::Result<[u8; 32]>;

    /// Delete the master key from the OS keychain (used by `opaq lock`).
    fn delete_key(&self) -> crate::error::Result<()>;
}

#[cfg(all(target_os = "linux", feature = "linux-keychain"))]
mod linux {
    use std::collections::HashMap;

    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;

    use crate::error::OpaqError;

    pub struct LinuxKeychain;

    impl super::Keychain for LinuxKeychain {
        fn store_key(&self, key: &[u8; 32]) -> crate::error::Result<()> {
            let ss = SecretService::connect(EncryptionType::Dh)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            let collection = ss
                .get_default_collection()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            if collection
                .is_locked()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?
            {
                collection
                    .unlock()
                    .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            }
            let mut attributes = HashMap::new();
            attributes.insert("service", "opaq");
            attributes.insert("account", "master-key");
            collection
                .create_item(
                    "opaq master key",
                    attributes,
                    key,
                    true,
                    "application/octet-stream",
                )
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            Ok(())
        }

        fn retrieve_key(&self) -> crate::error::Result<[u8; 32]> {
            let ss = SecretService::connect(EncryptionType::Dh)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            let collection = ss
                .get_default_collection()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            if collection
                .is_locked()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?
            {
                collection
                    .unlock()
                    .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            }
            let mut attributes = HashMap::new();
            attributes.insert("service", "opaq");
            attributes.insert("account", "master-key");
            let items = collection
                .search_items(attributes)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            match items.first() {
                Some(item) => {
                    let secret = item
                        .get_secret()
                        .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
                    let key: [u8; 32] = secret.try_into().map_err(|_| {
                        OpaqError::KeychainError("Invalid key length in keychain".into())
                    })?;
                    Ok(key)
                }
                None => Err(OpaqError::StoreLocked),
            }
        }

        fn delete_key(&self) -> crate::error::Result<()> {
            let ss = SecretService::connect(EncryptionType::Dh)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            let collection = ss
                .get_default_collection()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            if collection
                .is_locked()
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?
            {
                collection
                    .unlock()
                    .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            }
            let mut attributes = HashMap::new();
            attributes.insert("service", "opaq");
            attributes.insert("account", "master-key");
            let items = collection
                .search_items(attributes)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            for item in items {
                item.delete()
                    .map_err(|e| OpaqError::KeychainError(e.to_string()))?;
            }
            Ok(())
        }
    }
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
mod macos {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    use crate::error::OpaqError;

    pub struct MacosKeychain;

    impl super::Keychain for MacosKeychain {
        fn store_key(&self, key: &[u8; 32]) -> crate::error::Result<()> {
            set_generic_password("opaq", "master-key", key)
                .map_err(|e| OpaqError::KeychainError(e.to_string()))
        }

        fn retrieve_key(&self) -> crate::error::Result<[u8; 32]> {
            match get_generic_password("opaq", "master-key") {
                Ok(data) => {
                    let key: [u8; 32] = data.try_into().map_err(|_| {
                        OpaqError::KeychainError("Invalid key length in keychain".into())
                    })?;
                    Ok(key)
                }
                Err(e) if e.code() == -25300 => Err(OpaqError::StoreLocked),
                Err(e) => Err(OpaqError::KeychainError(e.to_string())),
            }
        }

        fn delete_key(&self) -> crate::error::Result<()> {
            delete_generic_password("opaq", "master-key")
                .map_err(|e| OpaqError::KeychainError(e.to_string()))
        }
    }
}

/// File-based keychain for testing. Stores the master key in a file
/// alongside the store, avoiding OS keychain dependencies in tests.
struct FileKeychain {
    key_path: std::path::PathBuf,
}

impl Keychain for FileKeychain {
    fn store_key(&self, key: &[u8; 32]) -> crate::error::Result<()> {
        if let Some(parent) = self.key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.key_path, key)?;
        Ok(())
    }

    fn retrieve_key(&self) -> crate::error::Result<[u8; 32]> {
        let data = std::fs::read(&self.key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                crate::error::OpaqError::StoreLocked
            } else {
                crate::error::OpaqError::Io(e)
            }
        })?;
        let key: [u8; 32] = data.try_into().map_err(|_| {
            crate::error::OpaqError::KeychainError("Invalid key length in file keychain".into())
        })?;
        Ok(key)
    }

    fn delete_key(&self) -> crate::error::Result<()> {
        match std::fs::remove_file(&self.key_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(crate::error::OpaqError::Io(e)),
        }
    }
}

pub fn get_keychain() -> Box<dyn Keychain> {
    // Test mode: use file-based keychain to avoid OS keychain dependencies
    if std::env::var("OPAQ_TEST_MODE").is_ok() {
        let key_path = crate::store::store_dir().join("master.key");
        return Box::new(FileKeychain { key_path });
    }

    #[cfg(all(target_os = "linux", feature = "linux-keychain"))]
    {
        return Box::new(linux::LinuxKeychain);
    }

    #[cfg(all(target_os = "macos", feature = "macos-keychain"))]
    {
        return Box::new(macos::MacosKeychain);
    }

    #[cfg(not(any(
        all(target_os = "linux", feature = "linux-keychain"),
        all(target_os = "macos", feature = "macos-keychain")
    )))]
    {
        panic!("No keychain backend available. Build with --features linux-keychain or macos-keychain.");
    }
}
