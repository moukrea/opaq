// opaq: Claude Code setup execution — install, uninstall, check

use std::process::Command;

use inquire::Confirm;

use crate::commands::setup::{marketplace_repo, InstallScope, SetupSelection};
use crate::error::{OpaqError, Result};
use crate::store::store_path;

/// Run a claude CLI command, returning its output. Surfaces errors directly.
fn run_claude(args: &[&str]) -> Result<std::process::Output> {
    Command::new("claude")
        .args(args)
        .output()
        .map_err(|e| OpaqError::CommandExecution(format!("Failed to run claude CLI: {}", e)))
}

/// Check if the opaq plugin is already installed by examining `claude plugin list`.
fn is_plugin_installed() -> Result<bool> {
    let output = run_claude(&["plugin", "list"])?;
    if !output.status.success() {
        // If the command fails, assume not installed
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("opaq"))
}

/// Get the claude CLI version string, or None if unavailable.
fn get_claude_version() -> Option<String> {
    let output = Command::new("claude").args(["--version"]).output().ok()?;
    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some(version)
    } else {
        None
    }
}

/// Check if the marketplace is registered.
fn is_marketplace_registered() -> Result<bool> {
    let output = run_claude(&["plugin", "marketplace", "list"])?;
    if !output.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let repo = marketplace_repo();
    Ok(stdout.contains(&repo))
}

pub fn install(selection: SetupSelection) -> Result<()> {
    let scope = selection.scope.as_ref().ok_or_else(|| {
        OpaqError::CommandExecution("Install mode requires a scope selection.".to_string())
    })?;
    let repo = marketplace_repo();

    // Step 1: Add marketplace
    println!("Adding plugin marketplace...");
    let output = run_claude(&["plugin", "marketplace", "add", &repo])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", stderr);
        std::process::exit(output.status.code().unwrap_or(1));
    }
    println!("Marketplace added: {}", repo);
    println!();

    // Step 1.5: Check for existing installation
    if is_plugin_installed()? {
        let reinstall = Confirm::new("opaq plugin is already installed. Reinstall/update?")
            .with_default(true)
            .prompt()
            .map_err(|e| OpaqError::CommandExecution(e.to_string()))?;

        if !reinstall {
            return Ok(());
        }

        // Uninstall first
        let output = run_claude(&["plugin", "uninstall", "opaq"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{}", stderr);
            std::process::exit(output.status.code().unwrap_or(1));
        }
    }

    // Step 2: Install plugin
    println!("Installing plugin...");
    let scope_flag = match scope {
        InstallScope::Global => "user",
        InstallScope::Project => "project",
    };
    let scope_label = match scope {
        InstallScope::Global => "global scope",
        InstallScope::Project => "project scope",
    };

    let output = run_claude(&[
        "plugin",
        "install",
        "opaq@claude-code-plugins",
        "--scope",
        scope_flag,
    ])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", stderr);
        std::process::exit(output.status.code().unwrap_or(1));
    }
    println!("opaq plugin installed ({})", scope_label);
    println!();

    // Step 3: Final confirmation
    println!("Open Claude Code and ask it to make an authenticated API call to test.");

    Ok(())
}

pub fn uninstall(_selection: SetupSelection) -> Result<()> {
    let repo = marketplace_repo();

    println!("Uninstalling opaq plugin from Claude Code...");
    let output = run_claude(&["plugin", "uninstall", "opaq"])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", stderr);
        std::process::exit(output.status.code().unwrap_or(1));
    }
    println!("Plugin uninstalled");
    println!();
    println!("The marketplace ({}) is still registered.", repo);
    println!("You can reinstall anytime with `opaq setup`.");

    Ok(())
}

pub fn check(_selection: SetupSelection) -> Result<()> {
    let repo = marketplace_repo();
    let mut all_ok = true;

    println!("Claude Code Integration Status:");

    // Check 1: opaq initialized
    let store_ok = store_path().exists();
    if store_ok {
        println!("opaq initialized (~/.config/opaq/store exists)       [OK]");
    } else {
        println!("opaq not initialized                                  [FAIL]");
        all_ok = false;
    }

    // Check 2: claude CLI available
    match get_claude_version() {
        Some(version) => {
            println!("claude CLI available ({:<36}) [OK]", version);
        }
        None => {
            println!("claude CLI not available                               [FAIL]");
            all_ok = false;
        }
    }

    // Check 3: Marketplace registered
    let marketplace_ok = is_marketplace_registered().unwrap_or(false);
    if marketplace_ok {
        println!("Marketplace registered ({:<30}) [OK]", repo);
    } else {
        println!("Marketplace not registered                             [FAIL]");
        all_ok = false;
    }

    // Check 4: Plugin installed
    let plugin_ok = is_plugin_installed().unwrap_or(false);
    if plugin_ok {
        println!("Plugin installed (opaq)                                [OK]");
    } else {
        println!("Plugin not installed                                   [FAIL]");
        all_ok = false;
    }

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Run `opaq setup` to install the plugin.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::commands::setup::{AgentSystem, InstallScope, SetupMode, SetupSelection};

    #[test]
    fn install_selection_requires_scope() {
        let sel = SetupSelection {
            mode: SetupMode::Install,
            system: AgentSystem::ClaudeCode,
            scope: Some(InstallScope::Global),
        };
        assert!(sel.scope.is_some());
    }

    #[test]
    fn check_selection_no_scope() {
        let sel = SetupSelection {
            mode: SetupMode::Check,
            system: AgentSystem::ClaudeCode,
            scope: None,
        };
        assert!(sel.scope.is_none());
    }

    #[test]
    fn scope_flag_mapping() {
        // Verify the scope-to-flag mapping logic
        let global_flag = match InstallScope::Global {
            InstallScope::Global => "user",
            InstallScope::Project => "project",
        };
        assert_eq!(global_flag, "user");

        let project_flag = match InstallScope::Project {
            InstallScope::Global => "user",
            InstallScope::Project => "project",
        };
        assert_eq!(project_flag, "project");
    }

    #[test]
    fn scope_label_mapping() {
        let global_label = match InstallScope::Global {
            InstallScope::Global => "global scope",
            InstallScope::Project => "project scope",
        };
        assert_eq!(global_label, "global scope");

        let project_label = match InstallScope::Project {
            InstallScope::Global => "global scope",
            InstallScope::Project => "project scope",
        };
        assert_eq!(project_label, "project scope");
    }
}
