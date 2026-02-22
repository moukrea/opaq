// opaq: setup command implementation — system detection and interactive wizard

use std::process::Command;

use inquire::{Confirm, Select};

use crate::error::{OpaqError, Result};
use crate::keychain;
use crate::store::store_path;

/// Compiled-in marketplace repository. Override via OPAQ_MARKETPLACE_REPO env var.
pub const MARKETPLACE_REPO: &str = "moukrea/claude-code-plugins";

pub fn marketplace_repo() -> String {
    std::env::var("OPAQ_MARKETPLACE_REPO").unwrap_or_else(|_| MARKETPLACE_REPO.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupMode {
    Install,
    Uninstall,
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSystem {
    ClaudeCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallScope {
    Global,
    Project,
}

#[derive(Debug, Clone)]
pub struct SetupSelection {
    pub mode: SetupMode,
    pub system: AgentSystem,
    pub scope: Option<InstallScope>,
}

/// Check the universal precondition: opaq must be initialized.
fn check_initialized() -> Result<()> {
    // Check store file exists
    if !store_path().exists() {
        return Err(OpaqError::CommandExecution(
            "Run `opaq init` first.".to_string(),
        ));
    }

    // Check keychain entry is valid (retrievable)
    let kc = keychain::get_keychain();
    kc.retrieve_key().map_err(|_| {
        OpaqError::CommandExecution("Run `opaq init` first.".to_string())
    })?;

    Ok(())
}

/// Check that the claude CLI is available on the system.
fn check_claude_cli() -> Result<()> {
    let result = Command::new("sh")
        .args(["-c", "command -v claude"])
        .output();

    match result {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(OpaqError::CommandExecution(
            "Claude Code is not installed. Install it from https://docs.claude.com/en/docs/claude-code".to_string(),
        )),
    }
}

/// Check if we're inside a git repository (current dir or any parent has .git).
fn is_in_git_repo() -> bool {
    let mut dir = std::env::current_dir().ok();
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return true;
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }
    false
}

/// Present the system selection menu and return the selected system.
fn select_system() -> Result<AgentSystem> {
    let systems = vec![
        "Claude Code",
        "Cursor          (coming soon)",
        "Windsurf        (coming soon)",
        "OpenAI Codex    (coming soon)",
    ];

    let selected = Select::new("Select agentic system:", systems)
        .prompt()
        .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

    if selected == "Claude Code" {
        Ok(AgentSystem::ClaudeCode)
    } else {
        // Extract the system name before "(coming soon)"
        let name = selected.split('(').next().unwrap_or(selected).trim();
        eprintln!("Support for {} is not yet available.", name);
        std::process::exit(0);
    }
}

/// Present the scope selection menu and return the selected scope.
fn select_scope() -> Result<InstallScope> {
    let scopes = vec![
        "Global   (all projects, installs to user scope)",
        "Project  (current project only, installs to project scope)",
    ];

    let selected = Select::new("Install scope:", scopes)
        .prompt()
        .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

    if selected.starts_with("Project") {
        // Check for git repository
        if !is_in_git_repo() {
            let proceed = Confirm::new(
                "No git repository detected. Project-scoped plugins may not work correctly. Continue?",
            )
            .with_default(true)
            .prompt()
            .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

            if !proceed {
                std::process::exit(0);
            }
        }
        Ok(InstallScope::Project)
    } else {
        Ok(InstallScope::Global)
    }
}

/// Run the interactive wizard and return a SetupSelection for the execution layer.
pub fn run_wizard(mode: SetupMode) -> Result<SetupSelection> {
    // 1. Universal precondition
    check_initialized()?;

    // 2. System selection
    let system = select_system()?;

    // 3. Agent-specific precondition
    match &system {
        AgentSystem::ClaudeCode => check_claude_cli()?,
    }

    // 4. Scope selection (not needed for --check mode)
    let scope = match &mode {
        SetupMode::Check => None,
        _ => Some(select_scope()?),
    };

    Ok(SetupSelection {
        mode,
        system,
        scope,
    })
}

pub fn execute(uninstall: bool, check: bool) -> Result<()> {
    // Validate mutually exclusive flags
    if uninstall && check {
        eprintln!("Error: --uninstall and --check cannot be used together.");
        std::process::exit(2);
    }

    let mode = if uninstall {
        SetupMode::Uninstall
    } else if check {
        SetupMode::Check
    } else {
        SetupMode::Install
    };

    let selection = run_wizard(mode)?;

    // The actual execution (marketplace add, plugin install, etc.) is handled
    // by task 023. For now, we have the structured selection ready.
    match selection.mode {
        SetupMode::Install => {
            crate::commands::setup_claude::install(selection)?;
        }
        SetupMode::Uninstall => {
            crate::commands::setup_claude::uninstall(selection)?;
        }
        SetupMode::Check => {
            crate::commands::setup_claude::check(selection)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_mode_variants() {
        assert_eq!(SetupMode::Install, SetupMode::Install);
        assert_eq!(SetupMode::Uninstall, SetupMode::Uninstall);
        assert_eq!(SetupMode::Check, SetupMode::Check);
        assert_ne!(SetupMode::Install, SetupMode::Check);
    }

    #[test]
    fn agent_system_variant() {
        assert_eq!(AgentSystem::ClaudeCode, AgentSystem::ClaudeCode);
    }

    #[test]
    fn install_scope_variants() {
        assert_eq!(InstallScope::Global, InstallScope::Global);
        assert_eq!(InstallScope::Project, InstallScope::Project);
        assert_ne!(InstallScope::Global, InstallScope::Project);
    }

    #[test]
    fn setup_selection_construction() {
        let sel = SetupSelection {
            mode: SetupMode::Install,
            system: AgentSystem::ClaudeCode,
            scope: Some(InstallScope::Global),
        };
        assert_eq!(sel.mode, SetupMode::Install);
        assert_eq!(sel.system, AgentSystem::ClaudeCode);
        assert_eq!(sel.scope, Some(InstallScope::Global));
    }

    #[test]
    fn setup_selection_check_mode_no_scope() {
        let sel = SetupSelection {
            mode: SetupMode::Check,
            system: AgentSystem::ClaudeCode,
            scope: None,
        };
        assert_eq!(sel.mode, SetupMode::Check);
        assert!(sel.scope.is_none());
    }

    #[test]
    fn marketplace_repo_default() {
        // If OPAQ_MARKETPLACE_REPO is not set, returns the default
        std::env::remove_var("OPAQ_MARKETPLACE_REPO");
        assert_eq!(marketplace_repo(), "moukrea/claude-code-plugins");
    }

    #[test]
    fn marketplace_repo_override() {
        std::env::set_var("OPAQ_MARKETPLACE_REPO", "custom/repo");
        assert_eq!(marketplace_repo(), "custom/repo");
        std::env::remove_var("OPAQ_MARKETPLACE_REPO");
    }

    #[test]
    fn git_repo_detection() {
        // This test verifies that the is_in_git_repo function works.
        // The result depends on where tests run. We just verify it returns
        // a bool without panicking.
        let _ = is_in_git_repo();
    }
}
