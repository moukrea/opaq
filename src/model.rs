// opaq: data model (SecretEntry and related types)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::OpaqError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub value: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub fn validate_name(name: &str) -> crate::error::Result<()> {
    if name.is_empty() {
        return Err(OpaqError::InvalidName(name.to_string()));
    }
    let mut chars = name.chars();
    // First char must be A-Z
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return Err(OpaqError::InvalidName(name.to_string())),
    }
    // Remaining chars must be A-Z, 0-9, or _
    for c in chars {
        if !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != '_' {
            return Err(OpaqError::InvalidName(name.to_string()));
        }
    }
    Ok(())
}

pub fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = tags
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

impl SecretEntry {
    pub fn new(
        name: String,
        description: String,
        tags: Vec<String>,
        value: Vec<u8>,
    ) -> crate::error::Result<Self> {
        validate_name(&name)?;
        let now = Utc::now();
        Ok(Self {
            name,
            description,
            tags: normalize_tags(&tags),
            value,
            created_at: now,
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(validate_name("A").is_ok());
        assert!(validate_name("MY_TOKEN").is_ok());
        assert!(validate_name("SONARQUBE_TOKEN").is_ok());
        assert!(validate_name("A1").is_ok());
        assert!(validate_name("ABC_123_DEF").is_ok());
    }

    #[test]
    fn invalid_name_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn invalid_name_lowercase() {
        assert!(validate_name("lowercase").is_err());
        assert!(validate_name("myToken").is_err());
        assert!(validate_name("a").is_err());
    }

    #[test]
    fn invalid_name_leading_digit() {
        assert!(validate_name("1ABC").is_err());
    }

    #[test]
    fn invalid_name_leading_underscore() {
        assert!(validate_name("_ABC").is_err());
    }

    #[test]
    fn invalid_name_hyphens() {
        assert!(validate_name("A-B").is_err());
        assert!(validate_name("ABC-DEF").is_err());
    }

    #[test]
    fn invalid_name_spaces() {
        assert!(validate_name("A B").is_err());
    }

    #[test]
    fn tag_normalization_case() {
        let tags = vec!["CI".to_string(), "Api".to_string(), "REGISTRY".to_string()];
        assert_eq!(normalize_tags(&tags), vec!["api", "ci", "registry"]);
    }

    #[test]
    fn tag_normalization_dedup() {
        let tags = vec![
            "sonar".to_string(),
            "SONAR".to_string(),
            "Sonar".to_string(),
        ];
        assert_eq!(normalize_tags(&tags), vec!["sonar"]);
    }

    #[test]
    fn tag_normalization_whitespace() {
        let tags = vec!["  spaced  ".to_string(), "trimmed".to_string()];
        assert_eq!(normalize_tags(&tags), vec!["spaced", "trimmed"]);
    }

    #[test]
    fn tag_normalization_empty_filtered() {
        let tags = vec!["".to_string(), "  ".to_string(), "valid".to_string()];
        assert_eq!(normalize_tags(&tags), vec!["valid"]);
    }

    #[test]
    fn secret_entry_new_valid() {
        let entry = SecretEntry::new(
            "MY_TOKEN".to_string(),
            "A test token".to_string(),
            vec!["CI".to_string(), "Api".to_string()],
            b"secret_value".to_vec(),
        )
        .unwrap();
        assert_eq!(entry.name, "MY_TOKEN");
        assert_eq!(entry.tags, vec!["api", "ci"]);
        assert_eq!(entry.value, b"secret_value");
    }

    #[test]
    fn secret_entry_new_invalid_name() {
        let result = SecretEntry::new("invalid".to_string(), "desc".to_string(), vec![], vec![]);
        assert!(result.is_err());
    }
}
