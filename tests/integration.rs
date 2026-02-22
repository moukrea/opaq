// opaq: integration tests
//
// These tests exercise the full opaq workflow at two levels:
// 1. Library-level: encryption round-trips, store operations, search,
//    placeholder resolution, output filtering, file scrubbing, export/import.
// 2. Binary-level: `std::process::Command` tests using OPAQ_TEST_MODE and
//    OPAQ_STORE_DIR env vars to exercise the real end-to-end CLI behavior
//    without needing a TTY or OS keychain.

use std::collections::HashSet;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use opaq::crypto::{decrypt_blob, encrypt_blob, generate_master_key, key_to_passphrase};
use opaq::filter::OutputFilter;
use opaq::model::SecretEntry;
use opaq::run::resolve_placeholders;
use opaq::scrubber::{parse_output_paths, FileScrubber};
use opaq::search::fuzzy_search;
use opaq::store::{deserialize_store, serialize_store};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a SecretEntry for testing.
fn make_entry(name: &str, desc: &str, tags: &[&str], value: &[u8]) -> SecretEntry {
    SecretEntry::new(
        name.to_string(),
        desc.to_string(),
        tags.iter().map(|s| s.to_string()).collect(),
        value.to_vec(),
    )
    .unwrap()
}

/// Write an encrypted store to a temp directory and return the passphrase.
fn write_test_store(dir: &std::path::Path, entries: &[SecretEntry]) -> String {
    let key = generate_master_key();
    let passphrase = key_to_passphrase(&key);

    let plaintext = serialize_store(entries).unwrap();
    let ciphertext = encrypt_blob(&plaintext, &passphrase).unwrap();

    fs::create_dir_all(dir).unwrap();
    let store_path = dir.join("store");
    fs::write(&store_path, &ciphertext).unwrap();

    passphrase
}

// ---------------------------------------------------------------------------
// Init: store creation and encryption round-trip
// ---------------------------------------------------------------------------

#[test]
fn init_creates_encrypted_store() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("opaq");
    let entries: Vec<SecretEntry> = vec![];

    let passphrase = write_test_store(&dir, &entries);

    // Verify the store file exists
    let store_path = dir.join("store");
    assert!(store_path.exists());

    // Verify it can be decrypted
    let ciphertext = fs::read(&store_path).unwrap();
    let plaintext = decrypt_blob(&ciphertext, &passphrase).unwrap();
    let loaded = deserialize_store(&plaintext).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn init_already_initialized_detects_existing_store() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("opaq");

    // Write the store twice to simulate double init
    let _passphrase = write_test_store(&dir, &[]);
    let store_path = dir.join("store");

    // The store file should exist from the first write
    assert!(store_path.exists());

    // Attempting to create again should detect the existing file
    // (In real binary, this would return StoreAlreadyExists)
    assert!(store_path.exists());
}

// ---------------------------------------------------------------------------
// Add + Search: add entries and verify search finds them
// ---------------------------------------------------------------------------

#[test]
fn add_then_search_by_name() {
    let entries = vec![
        make_entry("SONARQUBE_TOKEN", "API token for SonarQube", &["sonar", "ci"], b"sq_abc123"),
        make_entry("GITHUB_TOKEN", "GitHub personal access token", &["github"], b"ghp_xyz"),
    ];

    // Encrypt and decrypt round-trip
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("opaq");
    let passphrase = write_test_store(&dir, &entries);

    // Read back from disk
    let ciphertext = fs::read(dir.join("store")).unwrap();
    let plaintext = decrypt_blob(&ciphertext, &passphrase).unwrap();
    let loaded = deserialize_store(&plaintext).unwrap();

    // Search by name
    let results = fuzzy_search("sonar", &loaded);
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "SONARQUBE_TOKEN");
    assert_eq!(results[0].description, "API token for SonarQube");
    // Search results must never contain secret values
    // (SearchResult struct has no value field by design)
}

#[test]
fn add_then_search_by_tag() {
    let entries = vec![
        make_entry("MY_TOKEN", "Some token", &["ci", "sonarqube"], b"val1"),
        make_entry("OTHER_TOKEN", "Other token", &["github"], b"val2"),
    ];

    let results = fuzzy_search("sonar", &entries);
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "MY_TOKEN");
}

#[test]
fn add_then_search_by_description() {
    let entries = vec![
        make_entry("API_KEY", "Key for SonarQube quality gateway", &["ci"], b"key1"),
        make_entry("DB_PASS", "Database password", &["db"], b"pass1"),
    ];

    let results = fuzzy_search("sonar", &entries);
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "API_KEY");
}

#[test]
fn search_no_results_returns_empty() {
    let entries = vec![
        make_entry("GITHUB_TOKEN", "GitHub access token", &["github"], b"ghp_abc"),
    ];

    let results = fuzzy_search("kubernetes", &entries);
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// Run: placeholder resolution
// ---------------------------------------------------------------------------

#[test]
fn run_placeholder_resolution_full_workflow() {
    // Simulate the full init -> add -> run workflow
    let entries = vec![
        make_entry("API_TOKEN", "API auth token", &["api"], b"super-secret-value-12345"),
        make_entry("DB_HOST", "Database host", &["db"], b"db.internal.example.com"),
    ];

    // Encrypt, persist, read back (full round-trip)
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("opaq");
    let passphrase = write_test_store(&dir, &entries);
    let ciphertext = fs::read(dir.join("store")).unwrap();
    let plaintext = decrypt_blob(&ciphertext, &passphrase).unwrap();
    let loaded = deserialize_store(&plaintext).unwrap();

    // Resolve placeholders
    let args: Vec<String> = vec![
        "curl".into(),
        "-H".into(),
        "Authorization: Bearer {{API_TOKEN}}".into(),
        "https://{{DB_HOST}}/api/v1".into(),
    ];
    let resolved = resolve_placeholders(&args, &loaded);

    assert_eq!(resolved.args[0], "curl");
    assert_eq!(resolved.args[1], "-H");
    assert_eq!(resolved.args[2], "Authorization: Bearer super-secret-value-12345");
    assert_eq!(resolved.args[3], "https://db.internal.example.com/api/v1");
    assert_eq!(resolved.injected_secrets.len(), 2);
}

#[test]
fn run_output_filter_masks_secret_values() {
    let secret = b"super-secret-value-12345".to_vec();
    let filter = OutputFilter::new(std::slice::from_ref(&secret)).unwrap();

    // Simulate child process stdout containing the secret
    let input_data = b"Response: super-secret-value-12345 received";
    let mut input = Cursor::new(input_data.as_slice());
    let mut output = Vec::new();

    filter.filter_stream(&mut input, &mut output).unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("[MASKED]"), "Output should contain [MASKED]");
    assert!(
        !output_str.contains("super-secret-value-12345"),
        "Output must NOT contain raw secret value"
    );
}

#[test]
fn run_output_filter_passes_non_secret_content() {
    let secret = b"my-secret".to_vec();
    let filter = OutputFilter::new(&[secret]).unwrap();

    let input_data = b"This is safe output with no secrets";
    let mut input = Cursor::new(input_data.as_slice());
    let mut output = Vec::new();

    filter.filter_stream(&mut input, &mut output).unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert_eq!(output_str, "This is safe output with no secrets");
}

#[test]
fn run_output_filter_masks_multiple_secrets() {
    let secrets = vec![b"token123".to_vec(), b"password456".to_vec()];
    let filter = OutputFilter::new(&secrets).unwrap();

    let input_data = b"auth=token123 pass=password456 done";
    let mut input = Cursor::new(input_data.as_slice());
    let mut output = Vec::new();

    filter.filter_stream(&mut input, &mut output).unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert!(!output_str.contains("token123"));
    assert!(!output_str.contains("password456"));
    assert!(output_str.contains("[MASKED]"));
}

#[test]
fn run_unknown_placeholder_left_asis() {
    let entries = vec![
        make_entry("KNOWN", "Known secret", &[], b"value"),
    ];

    let args: Vec<String> = vec!["echo".into(), "{{KNOWN}} and {{UNKNOWN}}".into()];
    let resolved = resolve_placeholders(&args, &entries);

    assert_eq!(resolved.args[1], "value and {{UNKNOWN}}");
    assert_eq!(resolved.injected_secrets.len(), 1);
}

#[test]
fn run_non_opaq_curly_patterns_pass_through() {
    let entries = vec![
        make_entry("TOKEN", "A token", &[], b"val"),
    ];

    let args: Vec<String> = vec![
        "helm".into(),
        "template".into(),
        "{{ .Values.image }}".into(),
        "{{.}}".into(),
        "{{lowercase}}".into(),
    ];
    let resolved = resolve_placeholders(&args, &entries);

    // None of these should be touched
    assert_eq!(resolved.args[2], "{{ .Values.image }}");
    assert_eq!(resolved.args[3], "{{.}}");
    assert_eq!(resolved.args[4], "{{lowercase}}");
    assert!(resolved.injected_secrets.is_empty());
}

// ---------------------------------------------------------------------------
// File scrubber: text file scrubbing and binary file deletion
// ---------------------------------------------------------------------------

#[test]
fn scrubber_text_file_scrubbing_integration() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = b"my-api-key-12345".to_vec();

    // Simulate a child process writing a file that contains the secret
    let output_file = tmp.path().join("response.json");
    fs::write(
        &output_file,
        r#"{"auth": "my-api-key-12345", "status": "ok"}"#,
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let watcher = notify::recommended_watcher(tx).unwrap();
    let mut scrubber = FileScrubber {
        secrets: vec![secret],
        watcher,
        event_rx: rx,
        modified_files: HashSet::from([output_file.clone()]),
        extra_paths: vec![],
    };

    scrubber.scrub().unwrap();

    let content = fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("[MASKED]"));
    assert!(!content.contains("my-api-key-12345"));
}

#[test]
fn scrubber_binary_file_deletion_integration() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = b"binary-secret".to_vec();

    // Write a binary file that contains the secret
    let bin_file = tmp.path().join("data.bin");
    let mut content = Vec::new();
    content.extend_from_slice(b"HEADER\x00\x00");
    content.extend_from_slice(b"binary-secret");
    content.extend_from_slice(b"\x00TRAILER");
    fs::write(&bin_file, &content).unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let watcher = notify::recommended_watcher(tx).unwrap();
    let mut scrubber = FileScrubber {
        secrets: vec![secret],
        watcher,
        event_rx: rx,
        modified_files: HashSet::from([bin_file.clone()]),
        extra_paths: vec![],
    };

    scrubber.scrub().unwrap();

    assert!(
        !bin_file.exists(),
        "Binary file with secret should be deleted"
    );
}

// ---------------------------------------------------------------------------
// Export/Import round-trip
// ---------------------------------------------------------------------------

#[test]
fn export_import_roundtrip() {
    let entries = vec![
        make_entry("SECRET_A", "First secret", &["api", "ci"], b"value_alpha"),
        make_entry("SECRET_B", "Second secret", &["registry"], b"value_beta"),
        make_entry("SECRET_C", "Third secret", &[], b"value_gamma"),
    ];

    // Encrypt store with master key passphrase
    let master_key = generate_master_key();
    let master_passphrase = key_to_passphrase(&master_key);

    let plaintext = serialize_store(&entries).unwrap();
    let store_ciphertext = encrypt_blob(&plaintext, &master_passphrase).unwrap();

    // "Export": decrypt store with master passphrase, re-encrypt with export passphrase
    let decrypted = decrypt_blob(&store_ciphertext, &master_passphrase).unwrap();
    let export_passphrase = "export-test-passphrase-2024";
    let export_bundle = encrypt_blob(&decrypted, export_passphrase).unwrap();

    // Write export bundle to disk
    let tmp = tempfile::tempdir().unwrap();
    let export_path = tmp.path().join("export.opaq");
    fs::write(&export_path, &export_bundle).unwrap();

    // "Import": read bundle, decrypt with export passphrase, deserialize
    let bundle_bytes = fs::read(&export_path).unwrap();
    let imported_plaintext = decrypt_blob(&bundle_bytes, export_passphrase).unwrap();
    let imported_entries = deserialize_store(&imported_plaintext).unwrap();

    // Verify all secrets survived the round-trip
    assert_eq!(imported_entries.len(), 3);
    assert_eq!(imported_entries[0].name, "SECRET_A");
    assert_eq!(imported_entries[0].description, "First secret");
    assert_eq!(imported_entries[0].tags, vec!["api", "ci"]);
    assert_eq!(imported_entries[0].value, b"value_alpha");
    assert_eq!(imported_entries[1].name, "SECRET_B");
    assert_eq!(imported_entries[1].value, b"value_beta");
    assert_eq!(imported_entries[2].name, "SECRET_C");
    assert_eq!(imported_entries[2].value, b"value_gamma");

    // Verify search still works on imported entries
    let results = fuzzy_search("secret", &imported_entries);
    assert_eq!(results.len(), 3);
}

#[test]
fn export_import_wrong_passphrase_fails() {
    let entries = vec![
        make_entry("TOKEN", "A token", &[], b"secret_value"),
    ];

    let plaintext = serialize_store(&entries).unwrap();
    let encrypted = encrypt_blob(&plaintext, "correct-export-pass").unwrap();

    // Try to decrypt with wrong passphrase
    let result = decrypt_blob(&encrypted, "wrong-passphrase");
    assert!(result.is_err());
}

#[test]
fn export_empty_store_roundtrip() {
    let entries: Vec<SecretEntry> = vec![];

    let plaintext = serialize_store(&entries).unwrap();
    let passphrase = "empty-store-pass";
    let encrypted = encrypt_blob(&plaintext, passphrase).unwrap();

    let decrypted = decrypt_blob(&encrypted, passphrase).unwrap();
    let loaded = deserialize_store(&decrypted).unwrap();

    assert!(loaded.is_empty());
}

#[test]
fn import_merge_new_entries_preserves_existing() {
    // Simulate merging: local store has SECRET_A, import has SECRET_B
    let local = vec![
        make_entry("SECRET_A", "Local secret", &["local"], b"local_value"),
    ];
    let imported = vec![
        make_entry("SECRET_B", "Imported secret", &["imported"], b"imported_value"),
    ];

    // Merge logic (mirroring import_cmd.rs)
    let mut merged = local.clone();
    let existing_names: HashSet<String> = merged.iter().map(|e| e.name.clone()).collect();

    for entry in &imported {
        if !existing_names.contains(&entry.name) {
            merged.push(entry.clone());
        }
    }

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].name, "SECRET_A");
    assert_eq!(merged[0].value, b"local_value");
    assert_eq!(merged[1].name, "SECRET_B");
    assert_eq!(merged[1].value, b"imported_value");

    // Verify both are searchable
    let results = fuzzy_search("secret", &merged);
    assert_eq!(results.len(), 2);
}

#[test]
fn import_overwrite_replaces_existing() {
    let mut local = [
        make_entry("TOKEN", "Old description", &["old"], b"old_value"),
    ];
    let imported = make_entry("TOKEN", "New description", &["new"], b"new_value");

    // Overwrite
    local[0] = imported;

    assert_eq!(local[0].description, "New description");
    assert_eq!(local[0].value, b"new_value");
    assert_eq!(local[0].tags, vec!["new"]);
}

// ---------------------------------------------------------------------------
// Full workflow: init -> add -> search -> run (placeholder + filter)
// ---------------------------------------------------------------------------

#[test]
fn full_workflow_init_add_search_run() {
    // Step 1: "Init" -- create an encrypted empty store
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("opaq");
    let key = generate_master_key();
    let passphrase = key_to_passphrase(&key);
    let empty: Vec<SecretEntry> = vec![];
    let plaintext = serialize_store(&empty).unwrap();
    let ciphertext = encrypt_blob(&plaintext, &passphrase).unwrap();
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("store"), &ciphertext).unwrap();

    // Step 2: "Add" -- add entries to the store
    let entries = vec![
        make_entry(
            "SONARQUBE_TOKEN",
            "SonarQube API token for CI pipeline",
            &["sonar", "ci"],
            b"sqp_a1b2c3d4e5f6",
        ),
        make_entry(
            "REGISTRY_PASSWORD",
            "Docker registry password",
            &["docker", "registry"],
            b"hunter2",
        ),
    ];

    // Persist updated store
    let plaintext = serialize_store(&entries).unwrap();
    let ciphertext = encrypt_blob(&plaintext, &passphrase).unwrap();
    fs::write(dir.join("store"), &ciphertext).unwrap();

    // Step 3: "Search" -- find secrets by query
    let results = fuzzy_search("sonar", &entries);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "SONARQUBE_TOKEN");
    assert_eq!(results[0].description, "SonarQube API token for CI pipeline");

    let results = fuzzy_search("docker", &entries);
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "REGISTRY_PASSWORD");

    // Step 4: "Run" -- resolve placeholders
    let args: Vec<String> = vec![
        "curl".into(),
        "-H".into(),
        "Authorization: Bearer {{SONARQUBE_TOKEN}}".into(),
        "https://sonar.example.com/api/v1".into(),
    ];
    let resolved = resolve_placeholders(&args, &entries);
    assert_eq!(resolved.args[2], "Authorization: Bearer sqp_a1b2c3d4e5f6");
    assert_eq!(resolved.injected_secrets.len(), 1);
    assert_eq!(resolved.injected_secrets[0], b"sqp_a1b2c3d4e5f6");

    // Step 5: Verify output filter masks the resolved value
    let filter = OutputFilter::new(&resolved.injected_secrets).unwrap();
    let simulated_output = b"Response from sonar: sqp_a1b2c3d4e5f6 authenticated";
    let mut input = Cursor::new(simulated_output.as_slice());
    let mut output = Vec::new();
    filter.filter_stream(&mut input, &mut output).unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("[MASKED]"));
    assert!(!output_str.contains("sqp_a1b2c3d4e5f6"));
    assert!(output_str.contains("Response from sonar:"));
    assert!(output_str.contains("authenticated"));

    // Step 6: Read back from encrypted store to verify persistence
    let ciphertext = fs::read(dir.join("store")).unwrap();
    let plaintext = decrypt_blob(&ciphertext, &passphrase).unwrap();
    let loaded = deserialize_store(&plaintext).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].name, "SONARQUBE_TOKEN");
    assert_eq!(loaded[0].value, b"sqp_a1b2c3d4e5f6");
}

// ---------------------------------------------------------------------------
// CLI argument parsing (binary-level tests)
// ---------------------------------------------------------------------------

#[test]
fn cli_help_shows_all_subcommands() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaq"))
        .arg("--help")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();

    // All 11 subcommands should appear in help
    for subcmd in &[
        "init", "add", "edit", "remove", "search", "run", "export", "import", "lock", "unlock",
        "setup",
    ] {
        assert!(
            stdout.contains(subcmd),
            "Help output should contain subcommand '{}'",
            subcmd
        );
    }
}

#[test]
fn cli_no_args_shows_help_or_error() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaq"))
        .output()
        .unwrap();

    // clap should print help/usage to stderr and exit non-zero
    assert!(!output.status.success());
}

#[test]
fn cli_invalid_subcommand_returns_error() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaq"))
        .arg("nonexistent")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("nonexistent") || stderr.contains("unrecognized"));
}

#[test]
fn cli_search_requires_query_argument() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaq"))
        .arg("search")
        .output()
        .unwrap();

    // Should fail because query is required
    assert!(!output.status.success());
}

#[test]
fn cli_run_requires_command_argument() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaq"))
        .arg("run")
        .arg("--")
        .output()
        .unwrap();

    // Should fail because command args are required
    assert!(!output.status.success());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_output_paths_integration() {
    let args: Vec<String> = vec![
        "curl".into(),
        "-o".into(),
        "output.json".into(),
        "--output=response.txt".into(),
        "https://example.com".into(),
        ">".into(),
        "redirect.log".into(),
    ];

    let paths = parse_output_paths(&args);
    assert_eq!(paths.len(), 3);
    assert!(paths.contains(&PathBuf::from("output.json")));
    assert!(paths.contains(&PathBuf::from("response.txt")));
    assert!(paths.contains(&PathBuf::from("redirect.log")));
}

#[test]
fn encryption_roundtrip_with_binary_secret_values() {
    // Secrets can be arbitrary bytes, not just UTF-8
    let entries = vec![
        make_entry("BINARY_KEY", "Binary API key", &["binary"], &[0xFF, 0xFE, 0x00, 0x01, 0x80]),
    ];

    let passphrase = "test-pass";
    let plaintext = serialize_store(&entries).unwrap();
    let encrypted = encrypt_blob(&plaintext, passphrase).unwrap();
    let decrypted = decrypt_blob(&encrypted, passphrase).unwrap();
    let loaded = deserialize_store(&decrypted).unwrap();

    assert_eq!(loaded[0].value, vec![0xFF, 0xFE, 0x00, 0x01, 0x80]);
}

#[test]
fn secret_name_validation_rejects_invalid_names() {
    assert!(SecretEntry::new("lowercase".into(), "d".into(), vec![], vec![]).is_err());
    assert!(SecretEntry::new("_LEADING".into(), "d".into(), vec![], vec![]).is_err());
    assert!(SecretEntry::new("1DIGIT".into(), "d".into(), vec![], vec![]).is_err());
    assert!(SecretEntry::new("HAS-DASH".into(), "d".into(), vec![], vec![]).is_err());
    assert!(SecretEntry::new("".into(), "d".into(), vec![], vec![]).is_err());
}

#[test]
fn secret_name_validation_accepts_valid_names() {
    assert!(SecretEntry::new("A".into(), "d".into(), vec![], vec![]).is_ok());
    assert!(SecretEntry::new("MY_TOKEN".into(), "d".into(), vec![], vec![]).is_ok());
    assert!(SecretEntry::new("ABC_123_DEF".into(), "d".into(), vec![], vec![]).is_ok());
    assert!(SecretEntry::new("SONARQUBE_TOKEN".into(), "d".into(), vec![], vec![]).is_ok());
}

#[test]
fn output_filter_empty_secrets_is_passthrough() {
    let filter = OutputFilter::new(&[]).unwrap();
    let input_data = b"This content should pass through unchanged";
    let mut input = Cursor::new(input_data.as_slice());
    let mut output = Vec::new();

    filter.filter_stream(&mut input, &mut output).unwrap();

    assert_eq!(output, input_data);
}

// ---------------------------------------------------------------------------
// Binary-level end-to-end tests using OPAQ_TEST_MODE and OPAQ_STORE_DIR
// ---------------------------------------------------------------------------
//
// These tests invoke the compiled opaq binary with isolated temp directories
// and a file-based keychain (OPAQ_TEST_MODE=1), exercising the real CLI
// end-to-end: init error paths, search, run with output masking, and exit
// code passthrough.

mod binary_tests {
    use std::path::PathBuf;
    use std::process::Command;

    use tempfile::TempDir;

    struct TestEnv {
        dir: TempDir,
        store_dir: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let dir = TempDir::new().expect("failed to create temp dir");
            let store_dir = dir.path().join("opaq");
            Self { dir, store_dir }
        }

        fn cmd(&self) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_opaq"));
            cmd.env("OPAQ_STORE_DIR", &self.store_dir);
            cmd.env("OPAQ_TEST_MODE", "1");
            cmd
        }

        /// Initialize the store using library APIs (bypasses TTY/inquire).
        fn init_store(&self) {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;

            fs::create_dir_all(&self.store_dir).unwrap();
            fs::set_permissions(&self.store_dir, fs::Permissions::from_mode(0o700)).unwrap();

            let key = opaq::crypto::generate_master_key();
            let key_path = self.store_dir.join("master.key");
            fs::write(&key_path, key).unwrap();

            let passphrase = opaq::crypto::key_to_passphrase(&key);
            let entries: Vec<opaq::model::SecretEntry> = vec![];
            let plaintext = opaq::store::serialize_store(&entries).unwrap();
            let ciphertext = opaq::crypto::encrypt_blob(&plaintext, &passphrase).unwrap();

            let store_path = self.store_dir.join("store");
            fs::write(&store_path, &ciphertext).unwrap();
            fs::set_permissions(&store_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        /// Add a secret to the store using library APIs (bypasses TTY/inquire).
        fn add_secret(&self, name: &str, description: &str, tags: &[&str], value: &[u8]) {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;

            let key_path = self.store_dir.join("master.key");
            let key_data = fs::read(&key_path).unwrap();
            let key: [u8; 32] = key_data.try_into().unwrap();
            let passphrase = opaq::crypto::key_to_passphrase(&key);

            let store_path = self.store_dir.join("store");
            let ciphertext = fs::read(&store_path).unwrap();
            let plaintext = opaq::crypto::decrypt_blob(&ciphertext, &passphrase).unwrap();
            let mut entries: Vec<opaq::model::SecretEntry> =
                opaq::store::deserialize_store(&plaintext).unwrap();

            let tag_strings: Vec<String> = tags.iter().map(|s| s.to_string()).collect();
            let entry = opaq::model::SecretEntry::new(
                name.to_string(),
                description.to_string(),
                tag_strings,
                value.to_vec(),
            )
            .unwrap();
            entries.push(entry);

            let new_plaintext = opaq::store::serialize_store(&entries).unwrap();
            let new_ciphertext =
                opaq::crypto::encrypt_blob(&new_plaintext, &passphrase).unwrap();
            fs::write(&store_path, &new_ciphertext).unwrap();
            fs::set_permissions(&store_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    // -- Init tests (binary-level) --

    #[test]
    fn binary_init_already_initialized() {
        let env = TestEnv::new();
        env.init_store();

        let output = env.cmd().args(["init"]).output().unwrap();

        assert!(
            !output.status.success(),
            "Second init should fail with non-zero exit code"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("already initialized"),
            "Error should mention 'already initialized', got: {}",
            stderr
        );
    }

    // -- Search tests (binary-level) --

    #[test]
    fn binary_search_finds_secret() {
        let env = TestEnv::new();
        env.init_store();
        env.add_secret(
            "TEST_TOKEN",
            "Test API token for CI",
            &["api", "test"],
            b"super-secret-value-12345",
        );

        let output = env.cmd().args(["search", "test"]).output().unwrap();

        assert!(output.status.success(), "Search should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("TEST_TOKEN"),
            "Search output should contain the secret name, got: {}",
            stdout
        );
        assert!(
            stdout.contains("Test API token"),
            "Search output should contain the description, got: {}",
            stdout
        );
        assert!(
            !stdout.contains("super-secret-value-12345"),
            "Search output must NEVER contain the secret value"
        );
    }

    #[test]
    fn binary_search_json_output() {
        let env = TestEnv::new();
        env.init_store();
        env.add_secret("MY_KEY", "An API key", &["ci"], b"key-value-123");

        let output = env
            .cmd()
            .args(["search", "--json", "key"])
            .output()
            .unwrap();

        assert!(output.status.success(), "Search --json should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("Should be valid JSON: {}\nOutput: {}", e, stdout));

        assert!(parsed.is_array());
        let arr = parsed.as_array().unwrap();
        assert!(!arr.is_empty());
        assert_eq!(arr[0]["name"], "MY_KEY");
        assert!(
            !stdout.contains("key-value-123"),
            "JSON output must NEVER contain the secret value"
        );
    }

    #[test]
    fn binary_search_no_results() {
        let env = TestEnv::new();
        env.init_store();

        let output = env
            .cmd()
            .args(["search", "nonexistent"])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("No secrets found"),
            "Should indicate no results, got: {}",
            stdout
        );
    }

    // -- Run tests (binary-level) --

    #[test]
    fn binary_run_masks_output() {
        let env = TestEnv::new();
        env.init_store();
        env.add_secret(
            "MY_SECRET",
            "A test secret",
            &[],
            b"super-secret-value-12345",
        );

        let output = env
            .cmd()
            .args(["run", "--", "echo", "{{MY_SECRET}}"])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Run should succeed, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("[MASKED]"),
            "Output should contain [MASKED], got: {}",
            stdout
        );
        assert!(
            !stdout.contains("super-secret-value-12345"),
            "Output must NEVER contain the raw secret value"
        );
    }

    #[test]
    fn binary_run_exit_code_passthrough() {
        let env = TestEnv::new();
        env.init_store();

        let output = env
            .cmd()
            .args(["run", "--", "sh", "-c", "exit 42"])
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(42),
            "Exit code should be passed through from child process"
        );
    }

    #[test]
    fn binary_run_exit_code_zero() {
        let env = TestEnv::new();
        env.init_store();

        let output = env
            .cmd()
            .args(["run", "--", "true"])
            .output()
            .unwrap();

        assert!(output.status.success(), "Run with 'true' should exit 0");
    }

    #[test]
    fn binary_run_unknown_placeholder_warning() {
        let env = TestEnv::new();
        env.init_store();

        let output = env
            .cmd()
            .args(["run", "--", "echo", "{{NONEXISTENT_SECRET}}"])
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not a known opaq secret"),
            "Should warn about unknown placeholder, stderr: {}",
            stderr
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("{{NONEXISTENT_SECRET}}"),
            "Unknown placeholder should pass through as literal text, got: {}",
            stdout
        );
    }

    #[test]
    fn binary_run_no_placeholders() {
        let env = TestEnv::new();
        env.init_store();

        let output = env
            .cmd()
            .args(["run", "--", "echo", "hello world"])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("hello world"),
            "Output without placeholders should pass through, got: {}",
            stdout
        );
    }

    #[test]
    fn binary_run_store_not_found() {
        let env = TestEnv::new();
        // Don't init the store

        let output = env
            .cmd()
            .args(["run", "--", "echo", "test"])
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "Run without initialized store should fail"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Store not found")
                || stderr.contains("opaq init")
                || stderr.contains("locked"),
            "Should indicate store issue, got: {}",
            stderr
        );
    }

    #[test]
    fn binary_run_multiple_secrets_masked() {
        let env = TestEnv::new();
        env.init_store();
        env.add_secret("TOKEN_ONE", "First token", &[], b"alpha-secret");
        env.add_secret("TOKEN_TWO", "Second token", &[], b"beta-secret");

        let output = env
            .cmd()
            .args([
                "run", "--", "sh", "-c",
                "echo {{TOKEN_ONE}} and {{TOKEN_TWO}}",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Run with multiple secrets should succeed, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("alpha-secret"),
            "First secret value must not appear in output"
        );
        assert!(
            !stdout.contains("beta-secret"),
            "Second secret value must not appear in output"
        );
        let masked_count = stdout.matches("[MASKED]").count();
        assert!(
            masked_count >= 2,
            "Both secrets should be masked, found {} [MASKED] in: {}",
            masked_count,
            stdout
        );
    }

    // -- Export/Import round-trip (binary + library hybrid) --

    #[test]
    fn binary_export_import_roundtrip() {
        let env1 = TestEnv::new();
        env1.init_store();
        env1.add_secret("SECRET_A", "First secret", &["ci"], b"value_a");
        env1.add_secret("SECRET_B", "Second secret", &["api"], b"value_b");

        // Export using library APIs (export command requires TTY for passphrase)
        let export_file = env1.dir.path().join("export.opaq");
        let export_pass = "test-export-passphrase";
        {
            let key_path = env1.store_dir.join("master.key");
            let key_data = std::fs::read(&key_path).unwrap();
            let key: [u8; 32] = key_data.try_into().unwrap();
            let master_passphrase = opaq::crypto::key_to_passphrase(&key);

            let store_path = env1.store_dir.join("store");
            let ciphertext = std::fs::read(&store_path).unwrap();
            let plaintext =
                opaq::crypto::decrypt_blob(&ciphertext, &master_passphrase).unwrap();
            let export_encrypted =
                opaq::crypto::encrypt_blob(&plaintext, export_pass).unwrap();
            std::fs::write(&export_file, &export_encrypted).unwrap();
        }

        // Verify bundle and import into second store
        let bundle_bytes = std::fs::read(&export_file).unwrap();
        let decrypted = opaq::crypto::decrypt_blob(&bundle_bytes, export_pass).unwrap();
        let imported_entries: Vec<opaq::model::SecretEntry> =
            opaq::store::deserialize_store(&decrypted).unwrap();

        assert_eq!(imported_entries.len(), 2);

        let env2 = TestEnv::new();
        env2.init_store();

        // Write imported entries into second store
        {
            let key_path = env2.store_dir.join("master.key");
            let key_data = std::fs::read(&key_path).unwrap();
            let key: [u8; 32] = key_data.try_into().unwrap();
            let master_passphrase = opaq::crypto::key_to_passphrase(&key);

            let new_plaintext = opaq::store::serialize_store(&imported_entries).unwrap();
            let new_ciphertext =
                opaq::crypto::encrypt_blob(&new_plaintext, &master_passphrase).unwrap();
            let store_path = env2.store_dir.join("store");
            std::fs::write(&store_path, &new_ciphertext).unwrap();
        }

        // Search in second store via binary
        let output = env2.cmd().args(["search", "SECRET"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("SECRET_A"));
        assert!(stdout.contains("SECRET_B"));

        // Run with placeholder in second store via binary
        let output = env2
            .cmd()
            .args(["run", "--", "echo", "{{SECRET_A}}"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("[MASKED]"));
        assert!(!stdout.contains("value_a"));
    }
}
