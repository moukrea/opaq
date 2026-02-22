# Contributing to opaq

Thank you for your interest in contributing to opaq. This guide covers the development workflow and conventions used in the project.

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain
- `jq` on your PATH
- An OS keychain service (GNOME Keyring on Linux, Keychain Services on macOS)
- [ShellCheck](https://www.shellcheck.net/) (for linting hook scripts)

## Building

```bash
cd opaq/

# Debug build
cargo build

# Release build (Linux)
cargo build --release --features linux-keychain

# Release build (macOS)
cargo build --release --features macos-keychain
```

## Testing

```bash
# Run all tests
cargo test

# Run a specific test
cargo test <test_name>

# Run tests with stdout visible
cargo test -- --nocapture
```

## Code Quality

```bash
# Lint (warnings treated as errors)
cargo clippy -- -D warnings

# Check formatting
cargo fmt --check

# Auto-format
cargo fmt
```

All three checks must pass before a PR will be merged.

## Project Structure

```
opaq/
├── src/
│   ├── main.rs              # Binary entry point
│   ├── cli.rs               # Clap command definitions
│   ├── lib.rs               # Library root
│   ├── model.rs             # SecretEntry data model
│   ├── store.rs             # Encrypted store (age + bincode)
│   ├── crypto.rs            # Encryption/decryption
│   ├── keychain.rs          # OS keychain integration
│   ├── filter.rs            # Streaming output filter (aho-corasick)
│   ├── scrubber.rs          # Post-execution file scrubber (notify)
│   ├── search.rs            # Fuzzy search (nucleo)
│   ├── run.rs               # Run subsystem
│   ├── error.rs             # Error types
│   └── commands/            # One file per CLI subcommand
│       ├── init.rs
│       ├── add.rs
│       ├── edit.rs
│       ├── remove.rs
│       ├── search.rs
│       ├── run.rs
│       ├── export_cmd.rs
│       ├── import_cmd.rs
│       ├── lock.rs
│       ├── unlock.rs
│       ├── setup.rs
│       └── setup_claude.rs
└── tests/
```

## Conventions

### Secret names

- Uppercase with underscores: `^[A-Z][A-Z0-9_]*$`
- Examples: `API_TOKEN`, `DB_PASSWORD`, `SSH_KEY_PATH`

### Placeholder syntax

- `{{SECRET_NAME}}` — shell-safe, visually distinctive, inert until resolved by `opaq run`

### Masked output

- `[MASKED]` — fixed string, no length leakage

### Error handling

- All errors go to stderr with actionable messages
- Exit codes: `0` success, `1` general error, `2` usage error
- `opaq run` passes through the child process exit code

### Platform-specific code

Keychain crates are feature-gated:

- `linux-keychain` enables `secret-service` (D-Bus Secret Service)
- `macos-keychain` enables `security-framework` (Keychain Services)

Use `#[cfg(feature = "...")]` guards for platform-specific code paths.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

Examples:

```
feat(search): add JSON output format
fix(filter): handle partial matches at buffer boundaries
docs(readme): add installation instructions
```

## Pull Requests

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Ensure `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` all pass
4. Write a clear PR description explaining what changed and why
5. Submit the PR

## Architecture Notes

The [TECHNICAL-SPEC.md](../TECHNICAL-SPEC.md) at the workspace root contains the full system specification. Consult it when working on any subsystem.

Key design constraints:

- **No code path may output raw secret values.** The output filter and file scrubber are safety nets, not primary controls.
- **Interactive commands must enforce TTY.** Commands like `add`, `edit`, and `remove` check for a terminal and refuse to run in non-interactive contexts.
- **Atomic file writes.** The store is written via tempfile + fsync + rename to prevent corruption.
- **Agent safety by default.** Only `search` and `run` are available to non-interactive callers.
