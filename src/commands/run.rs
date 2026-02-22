// opaq: run command implementation
//
// Orchestrates the full pipeline:
// 1. Decrypt store (master key from keychain)
// 2. Resolve {{SECRET_NAME}} placeholders in command args
// 3. Build streaming output filter (aho-corasick automaton)
// 4. Set up file scrubber (notify-based filesystem watcher)
// 5. Spawn child process with piped stdout/stderr
// 6. Filter output streams concurrently
// 7. Wait for child to exit
// 8. Run file scrubber on modified files
// 9. Exit with child's exit code

use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::error::{OpaqError, Result};
use crate::filter::OutputFilter;
use crate::run::resolve_placeholders;
use crate::scrubber::{parse_output_paths, FileScrubber};
use crate::store::load_store;

pub fn execute(command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        return Err(OpaqError::CommandExecution(
            "No command provided. Usage: opaq run -- <COMMAND...>".to_string(),
        ));
    }

    // Step 1: Decrypt the store
    let entries = load_store()?;

    // Step 2: Resolve placeholders
    let resolved = resolve_placeholders(&command, &entries);

    // Step 3: Build the output filter
    let filter = Arc::new(OutputFilter::new(&resolved.injected_secrets)?);

    // Step 4: Set up file scrubber
    let extra_paths = parse_output_paths(&resolved.args);
    let cwd = std::env::current_dir()?;
    let mut scrubber = FileScrubber::new(
        resolved.injected_secrets.clone(),
        &cwd,
        extra_paths,
    )?;

    // Step 5: Spawn child process
    let mut child = Command::new(&resolved.args[0])
        .args(&resolved.args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| OpaqError::CommandExecution(format!("{}: {}", resolved.args[0], e)))?;

    // Step 6: Filter output streams concurrently
    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    let stdout_filter = Arc::clone(&filter);
    let stderr_filter = Arc::clone(&filter);

    let stdout_handle = std::thread::spawn(move || {
        let mut input = child_stdout;
        let mut output = std::io::stdout();
        stdout_filter.filter_stream(&mut input, &mut output)
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut input = child_stderr;
        let mut output = std::io::stderr();
        stderr_filter.filter_stream(&mut input, &mut output)
    });

    // Wait for filter threads to complete
    let stdout_result = stdout_handle
        .join()
        .map_err(|_| OpaqError::CommandExecution("stdout filter thread panicked".to_string()))?;
    let stderr_result = stderr_handle
        .join()
        .map_err(|_| OpaqError::CommandExecution("stderr filter thread panicked".to_string()))?;

    // Propagate filter errors
    stdout_result?;
    stderr_result?;

    // Step 7: Wait for child to exit
    let status = child.wait()?;

    // Step 8: Run file scrubber
    scrubber.collect_events();
    scrubber.scrub()?;

    // Step 9: Exit with child's exit code
    let exit_code = status.code().unwrap_or(1);
    std::process::exit(exit_code);
}
