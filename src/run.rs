// opaq: run subcommand (placeholder injection, child process execution, output filtering)

use std::collections::{HashMap, HashSet};

use regex::Regex;

use crate::model::SecretEntry;

pub struct ResolvedCommand {
    pub args: Vec<String>,
    pub injected_secrets: Vec<Vec<u8>>,
}

/// Resolve `{{SECRET_NAME}}` placeholders in command arguments using the
/// decrypted store. Returns the resolved args and the set of injected secret
/// values (for use by the output filter and file scrubber).
pub fn resolve_placeholders(args: &[String], store: &[SecretEntry]) -> ResolvedCommand {
    let re = Regex::new(r"\{\{([A-Z][A-Z0-9_]*)\}\}").expect("placeholder regex is valid");

    // Build a lookup map: name -> value
    let lookup: HashMap<&str, &[u8]> = store
        .iter()
        .map(|e| (e.name.as_str(), e.value.as_slice()))
        .collect();

    let mut seen_secrets: HashSet<Vec<u8>> = HashSet::new();
    let mut injected_secrets: Vec<Vec<u8>> = Vec::new();

    let resolved_args: Vec<String> = args
        .iter()
        .map(|arg| {
            let result = re.replace_all(arg, |caps: &regex::Captures| {
                let name = &caps[1];
                match lookup.get(name) {
                    Some(value) => {
                        if seen_secrets.insert(value.to_vec()) {
                            injected_secrets.push(value.to_vec());
                        }
                        String::from_utf8_lossy(value).into_owned()
                    }
                    None => {
                        eprintln!(
                            "Warning: '{{{{{}}}}}' is not a known opaq secret \u{2014} it will not be interpolated. This may be intentional.",
                            name
                        );
                        // Leave the placeholder as-is
                        caps[0].to_string()
                    }
                }
            });
            result.into_owned()
        })
        .collect();

    ResolvedCommand {
        args: resolved_args,
        injected_secrets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, value: &[u8]) -> SecretEntry {
        SecretEntry::new(
            name.to_string(),
            format!("Description for {}", name),
            vec![],
            value.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn single_placeholder() {
        let store = vec![make_entry("API_TOKEN", b"secret123")];
        let args = vec!["curl".into(), "-H".into(), "Bearer {{API_TOKEN}}".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["curl", "-H", "Bearer secret123"]);
        assert_eq!(result.injected_secrets, vec![b"secret123".to_vec()]);
    }

    #[test]
    fn multiple_placeholders_in_one_arg() {
        let store = vec![make_entry("USER", b"admin"), make_entry("PASS", b"hunter2")];
        let args = vec!["{{USER}}:{{PASS}}".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["admin:hunter2"]);
        assert_eq!(result.injected_secrets.len(), 2);
        assert!(result.injected_secrets.contains(&b"admin".to_vec()));
        assert!(result.injected_secrets.contains(&b"hunter2".to_vec()));
    }

    #[test]
    fn unknown_placeholder_left_asis() {
        let store = vec![make_entry("KNOWN", b"value")];
        let args = vec!["{{UNKNOWN}}".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["{{UNKNOWN}}"]);
        assert!(result.injected_secrets.is_empty());
    }

    #[test]
    fn mixed_known_and_unknown() {
        let store = vec![make_entry("TOKEN", b"abc")];
        let args = vec!["{{TOKEN}} and {{MISSING}}".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["abc and {{MISSING}}"]);
        assert_eq!(result.injected_secrets, vec![b"abc".to_vec()]);
    }

    #[test]
    fn no_placeholders_passthrough() {
        let store = vec![make_entry("TOKEN", b"abc")];
        let args = vec!["curl".into(), "https://example.com".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["curl", "https://example.com"]);
        assert!(result.injected_secrets.is_empty());
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

        let result = resolve_placeholders(&args, &store);
        assert_eq!(
            result.args,
            vec!["{{ .Values.x }}", "{{.}}", "{{lowercase}}", "{{my_token}}"]
        );
        assert!(result.injected_secrets.is_empty());
    }

    #[test]
    fn duplicate_secret_deduplicated() {
        let store = vec![make_entry("TOKEN", b"secret")];
        let args = vec!["{{TOKEN}}".into(), "{{TOKEN}}".into()];

        let result = resolve_placeholders(&args, &store);
        assert_eq!(result.args, vec!["secret", "secret"]);
        assert_eq!(result.injected_secrets.len(), 1);
        assert_eq!(result.injected_secrets[0], b"secret");
    }

    #[test]
    fn non_utf8_value_uses_lossy() {
        let store = vec![make_entry("BINARY_VAL", &[0xFF, 0xFE, 0x41])];
        let args = vec!["prefix-{{BINARY_VAL}}-suffix".into()];

        let result = resolve_placeholders(&args, &store);
        // from_utf8_lossy replaces invalid bytes with the replacement character
        assert!(result.args[0].contains('\u{FFFD}'));
        assert!(result.args[0].starts_with("prefix-"));
        assert!(result.args[0].ends_with("-suffix"));
        assert_eq!(result.injected_secrets.len(), 1);
    }

    #[test]
    fn placeholder_at_boundaries() {
        let store = vec![make_entry("A", b"x")];
        let args = vec!["{{A}}".into()];

        let result = resolve_placeholders(&args, &store);
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

        let result = resolve_placeholders(&args, &store);
        assert_eq!(
            result.args,
            vec![
                "curl",
                "-H",
                "Authorization: Bearer tk_123",
                "https://example.com/api"
            ]
        );
        assert_eq!(result.injected_secrets.len(), 2);
    }
}
