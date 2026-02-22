// opaq: encryption and key management (age, argon2)

use std::io::{Read, Write};

use age::secrecy::SecretString;
use base64::Engine;
use rand::RngCore;

use crate::error::OpaqError;

pub fn generate_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn key_to_passphrase(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

pub fn encrypt_blob(plaintext: &[u8], passphrase: &str) -> crate::error::Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| OpaqError::EncryptionFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| OpaqError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| OpaqError::EncryptionFailed(e.to_string()))?;
    Ok(encrypted)
}

pub fn decrypt_blob(ciphertext: &[u8], passphrase: &str) -> crate::error::Result<Vec<u8>> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| OpaqError::DecryptionFailed(e.to_string()))?;
    match decryptor {
        age::Decryptor::Passphrase(d) => {
            let mut decrypted = vec![];
            let mut reader = d
                .decrypt(&SecretString::from(passphrase.to_string()), None)
                .map_err(|e| OpaqError::DecryptionFailed(e.to_string()))?;
            reader
                .read_to_end(&mut decrypted)
                .map_err(|e| OpaqError::DecryptionFailed(e.to_string()))?;
            Ok(decrypted)
        }
        _ => Err(OpaqError::DecryptionFailed(
            "Expected passphrase-encrypted data".to_string(),
        )),
    }
}

pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> crate::error::Result<[u8; 32]> {
    let mut output = [0u8; 32];
    let argon2 = argon2::Argon2::default();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| OpaqError::EncryptionFailed(format!("Key derivation failed: {e}")))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let plaintext = b"hello, this is a secret message";
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt_blob(plaintext, passphrase).unwrap();
        let decrypted = decrypt_blob(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_passphrase_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt_blob(plaintext, "correct-passphrase").unwrap();
        let result = decrypt_blob(&encrypted, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let plaintext = b"";
        let passphrase = "passphrase";

        let encrypted = encrypt_blob(plaintext, passphrase).unwrap();
        let decrypted = decrypt_blob(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_with_master_key() {
        let key = generate_master_key();
        let passphrase = key_to_passphrase(&key);
        let plaintext = b"encrypted with master key";

        let encrypted = encrypt_blob(plaintext, &passphrase).unwrap();
        let decrypted = decrypt_blob(&encrypted, &passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn master_key_is_32_bytes() {
        let key = generate_master_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn master_keys_are_unique() {
        let key1 = generate_master_key();
        let key2 = generate_master_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_from_passphrase_produces_32_bytes() {
        let salt = b"0123456789abcdef"; // 16 bytes minimum for argon2
        let key = derive_key_from_passphrase("my passphrase", salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = b"0123456789abcdef";
        let key1 = derive_key_from_passphrase("same passphrase", salt).unwrap();
        let key2 = derive_key_from_passphrase("same passphrase", salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_different_passphrases() {
        let salt = b"0123456789abcdef";
        let key1 = derive_key_from_passphrase("passphrase one", salt).unwrap();
        let key2 = derive_key_from_passphrase("passphrase two", salt).unwrap();
        assert_ne!(key1, key2);
    }
}
