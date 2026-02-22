// opaq: post-execution file scrubber (notify-based filesystem watcher)

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::OpaqError;

const MASKED: &str = "[MASKED]";

pub struct FileScrubber {
    pub secrets: Vec<Vec<u8>>,
    pub watcher: RecommendedWatcher,
    pub event_rx: Receiver<Result<Event, notify::Error>>,
    pub modified_files: HashSet<PathBuf>,
    pub extra_paths: Vec<PathBuf>,
}

impl FileScrubber {
    /// Create a new file scrubber watching `watch_dir` recursively and any
    /// additional `extra_paths` (extracted from command arguments).
    pub fn new(
        secrets: Vec<Vec<u8>>,
        watch_dir: &Path,
        extra_paths: Vec<PathBuf>,
    ) -> Result<Self, OpaqError> {
        let (tx, rx) = channel();

        let mut watcher = notify::recommended_watcher(tx)
            .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

        watcher
            .watch(watch_dir, RecursiveMode::Recursive)
            .map_err(|e| OpaqError::Io(std::io::Error::other(e.to_string())))?;

        // Watch parent directories of extra paths so we catch file creation
        for path in &extra_paths {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
                }
            }
        }

        Ok(Self {
            secrets,
            watcher,
            event_rx: rx,
            modified_files: HashSet::new(),
            extra_paths,
        })
    }

    /// Drain the event channel and record all created/modified file paths.
    pub fn collect_events(&mut self) {
        while let Ok(event_result) = self.event_rx.try_recv() {
            if let Ok(event) = event_result {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.is_file() {
                                self.modified_files.insert(path);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Also include extra paths if they exist as files
        for path in &self.extra_paths {
            if path.is_file() {
                self.modified_files.insert(path.clone());
            }
        }
    }

    /// Process all modified files: scrub text files, delete binary files with matches.
    pub fn scrub(&mut self) -> Result<(), OpaqError> {
        if self.secrets.is_empty() {
            return Ok(());
        }

        // Stop watching before scrubbing to avoid triggering events from our own writes
        let _ = self.watcher.unwatch(Path::new("."));

        let files: Vec<PathBuf> = self.modified_files.drain().collect();

        for path in &files {
            if !path.exists() {
                // File was deleted before we could scrub it
                continue;
            }

            match self.scrub_file(path) {
                Ok(()) => {}
                Err(OpaqError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "\u{26A0} Could not read {} for scrubbing: permission denied",
                        path.display()
                    );
                }
                Err(_) => {
                    eprintln!(
                        "\u{26A0} Could not scrub {}: read error",
                        path.display()
                    );
                }
            }
        }

        Ok(())
    }

    fn scrub_file(&self, path: &Path) -> Result<(), OpaqError> {
        if is_binary(path)? {
            self.scrub_binary(path)
        } else {
            self.scrub_text(path)
        }
    }

    fn scrub_text(&self, path: &Path) -> Result<(), OpaqError> {
        let content = fs::read(path)?;
        let mut replaced = content.clone();
        let mut found = false;

        for secret in &self.secrets {
            if secret.is_empty() {
                continue;
            }
            if contains_bytes(&replaced, secret) {
                replaced = replace_bytes(&replaced, secret, MASKED.as_bytes());
                found = true;
            }
        }

        if found {
            fs::write(path, &replaced)?;
            eprintln!(
                "\u{26A0} Secret value detected and scrubbed in {}",
                path.display()
            );
        }

        Ok(())
    }

    fn scrub_binary(&self, path: &Path) -> Result<(), OpaqError> {
        let content = fs::read(path)?;

        for secret in &self.secrets {
            if secret.is_empty() {
                continue;
            }
            if contains_bytes(&content, secret) {
                fs::remove_file(path)?;
                eprintln!(
                    "\u{26A0} Secret value detected in binary file {} \u{2014} file removed for security.",
                    path.display()
                );
                return Ok(());
            }
        }

        Ok(())
    }
}

/// Check if a file is binary by looking for null bytes in the first 8KB.
fn is_binary(path: &Path) -> Result<bool, OpaqError> {
    let mut buf = [0u8; 8192];
    let mut file = File::open(path)?;
    let n = file.read(&mut buf)?;
    Ok(buf[..n].contains(&0))
}

/// Parse command arguments to extract output file paths from -o/--output flags
/// and >/>> redirects.
pub fn parse_output_paths(args: &[String]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        // Handle -o=<path> or --output=<path>
        if let Some(rest) = arg.strip_prefix("-o=") {
            if !rest.is_empty() {
                paths.push(PathBuf::from(rest));
            }
        } else if let Some(rest) = arg.strip_prefix("--output=") {
            if !rest.is_empty() {
                paths.push(PathBuf::from(rest));
            }
        }
        // Handle -o <path>, --output <path>, > <path>, >> <path>
        else if arg == "-o" || arg == "--output" || arg == ">" || arg == ">>" {
            if let Some(next) = iter.next() {
                paths.push(PathBuf::from(next));
            }
        }
    }

    paths
}

/// Check if `haystack` contains the byte sequence `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Replace all occurrences of `needle` in `haystack` with `replacement`.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }

    let mut result = Vec::new();
    let mut i = 0;

    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            result.extend_from_slice(replacement);
            i += needle.len();
        } else {
            result.push(haystack[i]);
            i += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn text_file_scrubbing() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("output.txt");
        fs::write(&file_path, "token is my-secret-value here").unwrap();

        let scrubber = FileScrubber {
            secrets: vec![b"my-secret-value".to_vec()],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path.clone()]),
            extra_paths: vec![],
        };

        scrubber.scrub_text(&file_path).unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "token is [MASKED] here");
    }

    #[test]
    fn text_file_multiple_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("multi.txt");
        fs::write(&file_path, "user=admin pass=hunter2 token=abc123").unwrap();

        let scrubber = FileScrubber {
            secrets: vec![b"hunter2".to_vec(), b"abc123".to_vec()],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path.clone()]),
            extra_paths: vec![],
        };

        scrubber.scrub_text(&file_path).unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "user=admin pass=[MASKED] token=[MASKED]");
    }

    #[test]
    fn binary_file_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("data.bin");
        let mut content = b"header\x00\x00binary data with secret-val".to_vec();
        content.extend_from_slice(b"\x00more binary");
        fs::write(&file_path, &content).unwrap();

        assert!(is_binary(&file_path).unwrap());
    }

    #[test]
    fn text_file_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("data.txt");
        fs::write(&file_path, "this is plain text with no null bytes").unwrap();

        assert!(!is_binary(&file_path).unwrap());
    }

    #[test]
    fn binary_file_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("data.bin");
        let mut content = Vec::new();
        content.extend_from_slice(b"header\x00\x00");
        content.extend_from_slice(b"my-secret-value");
        content.extend_from_slice(b"\x00trailer");
        fs::write(&file_path, &content).unwrap();

        let scrubber = FileScrubber {
            secrets: vec![b"my-secret-value".to_vec()],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path.clone()]),
            extra_paths: vec![],
        };

        scrubber.scrub_binary(&file_path).unwrap();
        assert!(!file_path.exists(), "Binary file should have been deleted");
    }

    #[test]
    fn binary_file_no_match_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("safe.bin");
        let content = b"header\x00\x00no secrets here\x00trailer";
        fs::write(&file_path, content).unwrap();

        let scrubber = FileScrubber {
            secrets: vec![b"my-secret-value".to_vec()],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path.clone()]),
            extra_paths: vec![],
        };

        scrubber.scrub_binary(&file_path).unwrap();
        assert!(file_path.exists(), "Binary file without matches should be preserved");
    }

    #[test]
    fn parse_output_paths_basic() {
        let args: Vec<String> = vec![
            "curl", "-o", "output.json", "https://example.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert_eq!(paths, vec![PathBuf::from("output.json")]);
    }

    #[test]
    fn parse_output_paths_equals() {
        let args: Vec<String> = vec![
            "curl", "--output=response.json", "https://example.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert_eq!(paths, vec![PathBuf::from("response.json")]);
    }

    #[test]
    fn parse_output_paths_redirect() {
        let args: Vec<String> = vec![
            "echo", "hello", ">", "out.txt",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert_eq!(paths, vec![PathBuf::from("out.txt")]);
    }

    #[test]
    fn parse_output_paths_append_redirect() {
        let args: Vec<String> = vec![
            "echo", "hello", ">>", "log.txt",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert_eq!(paths, vec![PathBuf::from("log.txt")]);
    }

    #[test]
    fn parse_output_paths_short_equals() {
        let args: Vec<String> = vec![
            "curl", "-o=data.json", "https://example.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert_eq!(paths, vec![PathBuf::from("data.json")]);
    }

    #[test]
    fn parse_output_paths_none() {
        let args: Vec<String> = vec![
            "curl", "https://example.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let paths = parse_output_paths(&args);
        assert!(paths.is_empty());
    }

    #[test]
    fn empty_secrets_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("output.txt");
        fs::write(&file_path, "this has some content").unwrap();

        let mut scrubber = FileScrubber {
            secrets: vec![],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path.clone()]),
            extra_paths: vec![],
        };

        scrubber.scrub().unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "this has some content");
    }

    #[test]
    fn contains_bytes_basic() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(!contains_bytes(b"hello world", b"xyz"));
        assert!(!contains_bytes(b"hi", b"hello"));
        assert!(!contains_bytes(b"", b"a"));
        assert!(!contains_bytes(b"abc", b""));
    }

    #[test]
    fn replace_bytes_basic() {
        assert_eq!(
            replace_bytes(b"hello secret world", b"secret", b"[MASKED]"),
            b"hello [MASKED] world"
        );
    }

    #[test]
    fn replace_bytes_multiple() {
        assert_eq!(
            replace_bytes(b"abc secret xyz secret end", b"secret", b"[MASKED]"),
            b"abc [MASKED] xyz [MASKED] end"
        );
    }

    #[test]
    fn deleted_file_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("gone.txt");
        // Don't create the file -- simulate it being deleted before scrubbing

        let mut scrubber = FileScrubber {
            secrets: vec![b"secret".to_vec()],
            watcher: notify::recommended_watcher(channel().0).unwrap(),
            event_rx: channel().1,
            modified_files: HashSet::from([file_path]),
            extra_paths: vec![],
        };

        // Should not error
        scrubber.scrub().unwrap();
    }
}
