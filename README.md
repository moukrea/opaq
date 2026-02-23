<p align="center">
  <img src="opaq.png" alt="opaq" width="400">
</p>

<p align="center">
  <strong>Keep secrets out of terminals, context windows, shell histories, and command output.</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#ai-agent-integration">AI Agent Integration</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## What is opaq?

opaq is a credential manager and execution wrapper for developers and AI agents. Secrets are stored encrypted, referenced by name, injected at runtime, and scrubbed from all output.

```bash
# Find a secret by keyword
opaq search gitlab
#   {{GITLAB_TOKEN}}       GitLab API personal access token

# Use it in a command — the value is injected at runtime, never visible
opaq run -- curl -sS -H "Authorization: Bearer {{GITLAB_TOKEN}}" \
  "https://gitlab.example.com/api/v4/projects"
```

The secret value never appears in your terminal, shell history, log files, or AI agent context. Any accidental output is replaced with `[MASKED]`.

### Why opaq?

- **Shell history is a liability.** Every `export API_KEY=sk-...` is saved to disk in plaintext.
- **Clipboard mistakes happen.** One wrong paste and a credential lands in a chat window.
- **AI agents amplify the risk.** Secrets in context windows are vulnerable to prompt injection, exfiltration, and accidental persistence.

opaq eliminates these risks with a single workflow: search by name, run with placeholders, never see the value.

## Installation

### Homebrew (macOS & Linux)

```bash
brew tap moukrea/tap
brew install opaq
```

### Debian / Ubuntu

```bash
# Add GPG key
curl -fsSL https://moukrea.github.io/apt-repo/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/moukrea.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/moukrea.gpg] https://moukrea.github.io/apt-repo stable main" | \
  sudo tee /etc/apt/sources.list.d/moukrea.list

# Install
sudo apt update && sudo apt install opaq
```

### Fedora / RHEL

```bash
# Add repository
sudo tee /etc/yum.repos.d/moukrea.repo << 'EOF'
[moukrea]
name=moukrea Repository
baseurl=https://moukrea.github.io/rpm-repo/
gpgcheck=1
gpgkey=https://moukrea.github.io/rpm-repo/pubkey.gpg
enabled=1
EOF

# Install
sudo dnf install opaq
```

### Arch Linux

Download the `PKGBUILD` from the
[latest release](https://github.com/moukrea/opaq/releases/latest) and build:

```bash
makepkg -si
```

### Pre-built Binaries

Download the archive for your platform from the
[latest release](https://github.com/moukrea/opaq/releases/latest):

| Platform | Architecture | Archive |
|----------|-------------|---------|
| Linux | x86_64 | `opaq-<version>-linux-x86_64.tar.gz` |
| Linux | aarch64 | `opaq-<version>-linux-aarch64.tar.gz` |
| macOS | x86_64 | `opaq-<version>-macos-x86_64.tar.gz` |
| macOS | Apple Silicon | `opaq-<version>-macos-aarch64.tar.gz` |

Extract and copy the binary to your `PATH`:

```bash
tar xzf opaq-<version>-<os>-<arch>.tar.gz
sudo mv opaq /usr/local/bin/
```

### From Source

Requires the [Rust toolchain](https://rustup.rs/) (stable).

```bash
git clone https://github.com/moukrea/opaq.git
cd opaq/opaq

# Linux
cargo build --release --features linux-keychain

# macOS
cargo build --release --features macos-keychain
```

The binary is at `target/release/opaq`. Copy it somewhere on your `PATH`.

### Supported platforms

| Platform | Architecture | Keychain Backend |
|----------|-------------|-----------------|
| Linux | x86_64, aarch64 | GNOME Keyring (D-Bus Secret Service) |
| macOS | x86_64, Apple Silicon | Keychain Services |

### Requirements

- An OS keychain service (GNOME Keyring, macOS Keychain)
- `jq` on `PATH` (used by Claude Code hooks)

## Quick Start

```bash
# 1. Initialize the encrypted store and master key
opaq init

# 2. Add a secret (value is entered interactively, never as an argument)
opaq add GITHUB_TOKEN "GitHub personal access token" --tags github,ci

# 3. Search for secrets
opaq search github
#   {{GITHUB_TOKEN}}    GitHub personal access token

# 4. Use in commands
opaq run -- gh api /user -H "Authorization: Bearer {{GITHUB_TOKEN}}"
```

## Commands

### For everyone (interactive terminal required)

| Command | Description |
|---------|-------------|
| `opaq init` | Create the encrypted store and save the master key in your OS keychain |
| `opaq add <NAME> <DESC>` | Add a secret (value entered via secure prompt) |
| `opaq edit <NAME>` | Change a secret's description, tags, or value |
| `opaq remove <NAME>` | Delete a secret |
| `opaq export --to <FILE>` | Export an encrypted backup |
| `opaq import --from <FILE>` | Restore from a backup |
| `opaq lock` | Clear the master key from the keychain |
| `opaq unlock` | Reload the master key into the keychain |

### For humans and AI agents

| Command | Description |
|---------|-------------|
| `opaq search <QUERY>` | Find secrets by name, tags, or description (never shows values) |
| `opaq run -- <CMD>` | Execute a command with `{{SECRET}}` placeholders injected at runtime |

Secret names are always uppercase with underscores: `API_TOKEN`, `DB_PASSWORD`, `SSH_KEY_PATH`.

### Examples

```bash
# API calls
opaq run -- curl -sS \
  -H "Authorization: Bearer {{API_TOKEN}}" \
  "https://api.example.com/v1/issues"

# Docker registry login
opaq run -- sh -c \
  'echo {{REGISTRY_PASSWORD}} | docker login registry.example.com -u admin --password-stdin'

# SSH
opaq run -- ssh -i "{{SSH_KEY_PATH}}" deploy@server.example.com uptime

# Pipe through jq (output is already scrubbed)
opaq run -- sh -c \
  'curl -sS -H "PRIVATE-TOKEN: {{GITLAB_TOKEN}}" \
   "https://git.example.com/api/v4/projects" | jq .[].name'

# JSON output for scripting
opaq search ci --json
```

## How It Works

### Storage

Secrets are stored in a single encrypted file at `~/.config/opaq/store`, encrypted with [age](https://github.com/FiloSottile/age) (ChaCha20-Poly1305). The master key lives only in your OS keychain — never on the filesystem.

### Runtime injection

When you run `opaq run -- <command>`, opaq:

1. Decrypts secrets in memory
2. Replaces `{{PLACEHOLDER}}` tokens with actual values in the command arguments
3. Spawns the child process
4. Filters stdout and stderr in real time, replacing any secret value with `[MASKED]`
5. Scrubs files written during execution, replacing secret values in text files and deleting binary files that contain matches

The output filter uses an [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) multi-pattern automaton to catch secrets in all their forms: raw, URL-encoded, Base64-encoded, and shell-escaped.

### What `[MASKED]` means

If you see `[MASKED]` in output, the command ran successfully — you just can't see the credential value. This is a fixed-length token that doesn't leak the length of the original secret.

## AI Agent Integration

opaq is designed to work with AI coding agents like [Claude Code](https://claude.ai/code). The [claude-code-plugins](https://github.com/moukrea/claude-code-plugins) package provides:

- **A skill** that teaches agents the search-then-run workflow
- **Hook scripts** that block agents from accessing the store directly, prevent writing placeholders to files, and auto-wrap commands containing `{{SECRET}}` placeholders

### Three enforcement layers

1. **Instruction layer** — The skill file teaches agents the correct workflow
2. **Hook layer** — Shell scripts intercept tool calls, blocking unsafe patterns and auto-correcting commands
3. **Binary layer** — TTY enforcement prevents agents from running interactive commands; the output filter and file scrubber prevent value leakage regardless of agent behavior

### Setup

```bash
opaq setup          # Interactive wizard for Claude Code integration
opaq setup --check  # Verify installation
```

## Security Model

- Secret values are never passed as CLI arguments (entered via `/dev/tty`)
- The master key exists only in the OS keychain
- The store file is encrypted at rest with age (ChaCha20-Poly1305)
- Output filtering catches raw, URL-encoded, Base64, and shell-escaped variants
- File scrubbing watches for secrets written to disk during command execution
- Interactive commands (`add`, `edit`, `remove`, etc.) require a TTY — agents cannot run them

## License

[MIT](LICENSE)
