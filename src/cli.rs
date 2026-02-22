// opaq: CLI command definitions (clap derive)

use clap::{Parser, Subcommand};
use std::fs::OpenOptions;

#[derive(Parser)]
#[command(
    name = "opaq",
    about = "Credential manager that keeps secrets out of terminals, agent context windows, shell histories, and command output"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the secret store and master key
    Init {
        /// Derive key from passphrase (requires unlock each session)
        #[arg(long)]
        passphrase: bool,
        /// Re-initialize (destroys existing store after confirmation)
        #[arg(long)]
        force: bool,
    },

    /// Add a new secret (interactive TTY required)
    Add {
        /// Uppercase identifier (A-Z, 0-9, underscore)
        name: String,
        /// What the secret is for
        description: String,
        /// Optional comma-separated tags
        tags: Option<String>,
    },

    /// Modify an existing secret's metadata or value
    Edit {
        /// Secret name to edit
        name: String,
        /// Update description
        #[arg(long)]
        desc: Option<String>,
        /// Update tags (replaces all tags)
        #[arg(long)]
        tags: Option<String>,
        /// Prompt for new value (interactive)
        #[arg(long)]
        rotate: bool,
    },

    /// Delete a secret (interactive confirmation required)
    Remove {
        /// Secret name to remove
        name: String,
    },

    /// Fuzzy search secrets (returns names and descriptions only)
    Search {
        /// Search query
        query: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Execute command with {{SECRET}} placeholder injection
    Run {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Export all secrets as a passphrase-encrypted bundle
    Export {
        /// Output file path
        #[arg(long = "to")]
        file: String,
    },

    /// Import secrets from an encrypted bundle
    Import {
        /// Input file path
        #[arg(long = "from")]
        file: String,
        /// Overwrite existing secrets without prompting
        #[arg(long)]
        overwrite: bool,
    },

    /// Clear master key from OS keychain
    Lock,

    /// Re-load master key into OS keychain
    Unlock,

    /// Interactive wizard for agentic system integration
    Setup {
        /// Remove integration for selected system
        #[arg(long)]
        uninstall: bool,
        /// Verify integration health for selected system
        #[arg(long)]
        check: bool,
    },
}

pub fn require_tty(command_name: &str) -> crate::error::Result<()> {
    if std::env::var("OPAQ_TEST_MODE").is_ok() {
        return Ok(());
    }
    match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(_) => Ok(()),
        Err(_) => Err(crate::error::OpaqError::TtyRequired(
            command_name.to_string(),
        )),
    }
}

pub fn dispatch(cli: Cli) -> crate::error::Result<()> {
    match cli.command {
        Commands::Init { passphrase, force } => {
            require_tty("init")?;
            crate::commands::init::execute(passphrase, force)
        }
        Commands::Add {
            name,
            description,
            tags,
        } => {
            require_tty("add")?;
            crate::commands::add::execute(name, description, tags)
        }
        Commands::Edit {
            name,
            desc,
            tags,
            rotate,
        } => {
            require_tty("edit")?;
            crate::commands::edit::execute(name, desc, tags, rotate)
        }
        Commands::Remove { name } => {
            require_tty("remove")?;
            crate::commands::remove::execute(name)
        }
        Commands::Search { query, json } => {
            // No TTY check -- agent-safe
            crate::commands::search::execute(query, json)
        }
        Commands::Run { command } => {
            // No TTY check -- agent-safe
            crate::commands::run::execute(command)
        }
        Commands::Export { file } => {
            require_tty("export")?;
            crate::commands::export_cmd::execute(file)
        }
        Commands::Import { file, overwrite } => {
            require_tty("import")?;
            crate::commands::import_cmd::execute(file, overwrite)
        }
        Commands::Lock => {
            require_tty("lock")?;
            crate::commands::lock::execute()
        }
        Commands::Unlock => {
            require_tty("unlock")?;
            crate::commands::unlock::execute()
        }
        Commands::Setup { uninstall, check } => {
            require_tty("setup")?;
            crate::commands::setup::execute(uninstall, check)
        }
    }
}
