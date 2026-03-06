// opaq: run subcommand (placeholder injection, child process execution, output filtering)

use std::collections::HashSet;
use std::path::Path;

use regex::Regex;

use crate::model::SecretEntry;

pub struct ResolvedCommand {
    pub args: Vec<String>,
    pub sensitive_secrets: Vec<Vec<u8>>,
    pub plain_values: Vec<Vec<u8>>,
}

/// Resolve `{{SECRET_NAME}}` placeholders in command arguments using the
/// decrypted store. Performs scope-aware resolution (nearest-ancestor-wins from
/// `cwd`) and classifies resolved values into sensitive secrets vs plain values.
pub fn resolve_placeholders(args: &[String], store: &[SecretEntry], cwd: &Path) -> ResolvedCommand {
    let re = Regex::new(r"\{\{([A-Z][A-Z0-9_]*)\}\}").expect("placeholder regex is valid");

    let mut seen_sensitive: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_plain: HashSet<Vec<u8>> = HashSet::new();
    let mut sensitive_secrets: Vec<Vec<u8>> = Vec::new();
    let mut plain_values: Vec<Vec<u8>> = Vec::new();

    let resolved_args: Vec<String> = args
        .iter()
        .map(|arg| {
            let result = re.replace_all(arg, |caps: &regex::Captures| {
                let name = &caps[1];

                // Find the winning entry via scope resolution
                let mut best: Option<&SecretEntry> = None;
                let mut best_specificity: usize = 0;

                for entry in store.iter().filter(|e| e.name == name) {
                    if !entry.scope.contains(cwd) {
                        continue;
                    }
                    let spec = entry.scope.specificity();
                    if best.is_none() || spec > best_specificity {
                        best = Some(entry);
                        best_specificity = spec;
                    }
                }

                match best {
                    Some(winner) => {
                        let value = &winner.value;
                        if winner.sensitive {
                            if seen_sensitive.insert(value.clone()) {
                                sensitive_secrets.push(value.clone());
                            }
                        } else if seen_plain.insert(value.clone()) {
                            plain_values.push(value.clone());
                        }
                        String::from_utf8_lossy(value).into_owned()
                    }
                    None => {
                        eprintln!(
                            "Warning: '{{{{{}}}}}' is not a known opaq secret \u{2014} it will not be interpolated. This may be intentional.",
                            name
                        );
                        caps[0].to_string()
                    }
                }
            });
            result.into_owned()
        })
        .collect();

    ResolvedCommand {
        args: resolved_args,
        sensitive_secrets,
        plain_values,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::model::Scope;

    fn make_entry(name: &str, value: &[u8]) -> SecretEntry {
        SecretEntry::new(
            name.to_string(),
            format!("Description for {}", name),
            vec![],
            value.to_vec(),
            true,
            Scope::Global,
        )
        .unwrap()
    }

    fn make_entry_with_scope(
        name: &str,
        value: &[u8],
        sensitive: bool,
        scope: Scope,
    ) -> SecretEntry {
        SecretEntry::new(
            name.to_string(),
            format!("Description for {}", name),
            vec![],
            value.to_vec(),
            sensitive,
            scope,
        )
        .unwrap()
    }

    fn default_cwd() -> PathBuf {
        PathBuf::from("/tmp")
    }

    #[test]
    fn single_placeholder() {
        let store = vec![make_entry("API_TOKEN", b"secret123")];
        let args = vec!["curl".into(), "-H".into(), "Bearer {{API_TOKEN}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["curl", "-H", "Bearer secret123"]);
        assert_eq!(result.sensitive_secrets, vec![b"secret123".to_vec()]);
        assert!(result.plain_values.is_empty());
    }

    #[test]
    fn multiple_placeholders_in_one_arg() {
        let store = vec![make_entry("USER", b"admin"), make_entry("PASS", b"hunter2")];
        let args = vec!["{{USER}}:{{PASS}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["admin:hunter2"]);
        assert_eq!(result.sensitive_secrets.len(), 2);
        assert!(result.sensitive_secrets.contains(&b"admin".to_vec()));
        assert!(result.sensitive_secrets.contains(&b"hunter2".to_vec()));
    }

    #[test]
    fn unknown_placeholder_left_asis() {
        let store = vec![make_entry("KNOWN", b"value")];
        let args = vec!["{{UNKNOWN}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["{{UNKNOWN}}"]);
        assert!(result.sensitive_secrets.is_empty());
        assert!(result.plain_values.is_empty());
    }

    #[test]
    fn mixed_known_and_unknown() {
        let store = vec![make_entry("TOKEN", b"abc")];
        let args = vec!["{{TOKEN}} and {{MISSING}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["abc and {{MISSING}}"]);
        assert_eq!(result.sensitive_secrets, vec![b"abc".to_vec()]);
    }

    #[test]
    fn no_placeholders_passthrough() {
        let store = vec![make_entry("TOKEN", b"abc")];
        let args = vec!["curl".into(), "https://example.com".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["curl", "https://example.com"]);
        assert!(result.sensitive_secrets.is_empty());
        assert!(result.plain_values.is_empty());
    }

    #[test]
    fn non_matching_curly_patterns_pass_through() {
        let store = vec![make_entry("TOKEN", b"abc")];
        let args = vec![
            "{{ .Values.x }}".into(),
            "{{.}}".into(),
            "{{lowercase}}".into(),
            "{{my_token}}".into(),
        ];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(
            result.args,
            vec!["{{ .Values.x }}", "{{.}}", "{{lowercase}}", "{{my_token}}"]
        );
        assert!(result.sensitive_secrets.is_empty());
    }

    #[test]
    fn duplicate_secret_deduplicated() {
        let store = vec![make_entry("TOKEN", b"secret")];
        let args = vec!["{{TOKEN}}".into(), "{{TOKEN}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["secret", "secret"]);
        assert_eq!(result.sensitive_secrets.len(), 1);
        assert_eq!(result.sensitive_secrets[0], b"secret");
    }

    #[test]
    fn non_utf8_value_uses_lossy() {
        let store = vec![make_entry("BINARY_VAL", &[0xFF, 0xFE, 0x41])];
        let args = vec!["prefix-{{BINARY_VAL}}-suffix".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert!(result.args[0].contains('\u{FFFD}'));
        assert!(result.args[0].starts_with("prefix-"));
        assert!(result.args[0].ends_with("-suffix"));
        assert_eq!(result.sensitive_secrets.len(), 1);
    }

    #[test]
    fn placeholder_at_boundaries() {
        let store = vec![make_entry("A", b"x")];
        let args = vec!["{{A}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["x"]);
    }

    #[test]
    fn multiple_args_with_placeholders() {
        let store = vec![
            make_entry("HOST", b"example.com"),
            make_entry("TOKEN", b"tk_123"),
        ];
        let args = vec![
            "curl".into(),
            "-H".into(),
            "Authorization: Bearer {{TOKEN}}".into(),
            "https://{{HOST}}/api".into(),
        ];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(
            result.args,
            vec![
                "curl",
                "-H",
                "Authorization: Bearer tk_123",
                "https://example.com/api"
            ]
        );
        assert_eq!(result.sensitive_secrets.len(), 2);
    }

    #[test]
    fn scope_resolution_nearest_ancestor_wins() {
        let store = vec![
            make_entry_with_scope("TOKEN", b"global_val", true, Scope::Global),
            make_entry_with_scope(
                "TOKEN",
                b"project_val",
                true,
                Scope::Path(PathBuf::from("/home/eco/code")),
            ),
        ];
        let args = vec!["{{TOKEN}}".into()];
        let cwd = PathBuf::from("/home/eco/code/project");

        let result = resolve_placeholders(&args, &store, &cwd);
        assert_eq!(result.args, vec!["project_val"]);
        assert_eq!(result.sensitive_secrets, vec![b"project_val".to_vec()]);
    }

    #[test]
    fn sensitivity_classification() {
        let store = vec![
            make_entry_with_scope("SECRET_TOKEN", b"secret_val", true, Scope::Global),
            make_entry_with_scope("PLAIN_URL", b"https://example.com", false, Scope::Global),
        ];
        let args = vec!["{{SECRET_TOKEN}}".into(), "{{PLAIN_URL}}".into()];

        let result = resolve_placeholders(&args, &store, &default_cwd());
        assert_eq!(result.args, vec!["secret_val", "https://example.com"]);
        assert_eq!(result.sensitive_secrets, vec![b"secret_val".to_vec()]);
        assert_eq!(
            result.plain_values,
            vec![b"https://example.com".to_vec()]
        );
    }

    #[test]
    fn scope_resolution_global_fallback() {
        let store = vec![make_entry_with_scope(
            "TOKEN",
            b"global_val",
            true,
            Scope::Global,
        )];
        let args = vec!["{{TOKEN}}".into()];
        let cwd = PathBuf::from("/some/random/dir");

        let result = resolve_placeholders(&args, &store, &cwd);
        assert_eq!(result.args, vec!["global_val"]);
        assert_eq!(result.sensitive_secrets, vec![b"global_val".to_vec()]);
    }

    #[test]
    fn out_of_scope_entry_treated_as_unknown() {
        let store = vec![make_entry_with_scope(
            "TOKEN",
            b"scoped_val",
            true,
            Scope::Path(PathBuf::from("/home/eco/code")),
        )];
        let args = vec!["{{TOKEN}}".into()];
        let cwd = PathBuf::from("/opt/other");

        let result = resolve_placeholders(&args, &store, &cwd);
        assert_eq!(result.args, vec!["{{TOKEN}}"]);
        assert!(result.sensitive_secrets.is_empty());
        assert!(result.plain_values.is_empty());
    }
}
