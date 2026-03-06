// opaq: data model (SecretEntry and related types)

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::OpaqError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Global,
    Path(PathBuf),
}

impl Scope {
    pub fn contains(&self, dir: &Path) -> bool {
        match self {
            Scope::Global => true,
            Scope::Path(scope_path) => dir.starts_with(scope_path),
        }
    }

    pub fn specificity(&self) -> usize {
        match self {
            Scope::Global => 0,
            Scope::Path(p) => p.components().count(),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Global => write!(f, "global"),
            Scope::Path(p) => {
                let path_str = p.to_string_lossy();
                if let Ok(home) = std::env::var("HOME") {
                    if path_str == home {
                        return write!(f, "~/");
                    }
                    let home_prefix = format!("{}/", home);
                    if path_str.starts_with(&home_prefix) {
                        let relative = &path_str[home.len()..];
                        return write!(f, "~{}/", relative.trim_end_matches('/'));
                    }
                }
                write!(f, "{}/", path_str.trim_end_matches('/'))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub value: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sensitive: bool,
    pub scope: Scope,
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
        sensitive: bool,
        scope: Scope,
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
            sensitive,
            scope,
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
            true,
            Scope::Global,
        )
        .unwrap();
        assert_eq!(entry.name, "MY_TOKEN");
        assert_eq!(entry.tags, vec!["api", "ci"]);
        assert_eq!(entry.value, b"secret_value");
        assert!(entry.sensitive);
        assert_eq!(entry.scope, Scope::Global);
    }

    #[test]
    fn secret_entry_new_invalid_name() {
        let result = SecretEntry::new(
            "invalid".to_string(),
            "desc".to_string(),
            vec![],
            vec![],
            true,
            Scope::Global,
        );
        assert!(result.is_err());
    }

    #[test]
    fn scope_contains_global() {
        let scope = Scope::Global;
        assert!(scope.contains(Path::new("/any/path")));
        assert!(scope.contains(Path::new("/home/user/project")));
        assert!(scope.contains(Path::new("/")));
    }

    #[test]
    fn scope_contains_path_descendants() {
        let scope = Scope::Path(PathBuf::from("/home/eco/code"));
        assert!(scope.contains(Path::new("/home/eco/code")));
        assert!(scope.contains(Path::new("/home/eco/code/project")));
        assert!(scope.contains(Path::new("/home/eco/code/project/src")));
    }

    #[test]
    fn scope_contains_path_rejects_non_descendants() {
        let scope = Scope::Path(PathBuf::from("/home/eco/code"));
        assert!(!scope.contains(Path::new("/home/eco/other")));
        assert!(!scope.contains(Path::new("/home/eco")));
        assert!(!scope.contains(Path::new("/opt/services")));
    }

    #[test]
    fn scope_specificity_ordering() {
        let global = Scope::Global;
        let short = Scope::Path(PathBuf::from("/home/eco"));
        let deep = Scope::Path(PathBuf::from("/home/eco/code/project"));

        assert_eq!(global.specificity(), 0);
        assert!(global.specificity() < short.specificity());
        assert!(short.specificity() < deep.specificity());
    }

    #[test]
    fn scope_display_global() {
        assert_eq!(format!("{}", Scope::Global), "global");
    }

    #[test]
    fn scope_display_home_path() {
        if let Ok(home) = std::env::var("HOME") {
            let scope = Scope::Path(PathBuf::from(&home));
            assert_eq!(format!("{}", scope), "~/");
        }
    }

    #[test]
    fn scope_display_home_subpath() {
        if let Ok(home) = std::env::var("HOME") {
            let scope = Scope::Path(PathBuf::from(format!("{}/code/project", home)));
            assert_eq!(format!("{}", scope), "~/code/project/");
        }
    }

    #[test]
    fn scope_display_absolute_path() {
        let scope = Scope::Path(PathBuf::from("/opt/services"));
        assert_eq!(format!("{}", scope), "/opt/services/");
    }
}
