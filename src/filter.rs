// opaq: streaming output filter (aho-corasick multi-pattern replacement)

use std::io::{Read, Write};

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::OpaqError;

const MASKED: &[u8] = b"[MASKED]";

pub struct OutputFilter {
    /// LeftmostLongest automaton for batch replace_all_bytes.
    automaton: Option<aho_corasick::AhoCorasick>,
    /// One replacement entry per pattern in the automaton (all are MASKED).
    replacements: Vec<&'static [u8]>,
    /// Length of the longest pattern, used for holdback calculation.
    longest_pattern_len: usize,
}

/// Generate all pattern variants for a single secret value.
/// Returns a Vec of byte patterns to match against.
fn generate_variants(secret: &[u8]) -> Vec<Vec<u8>> {
    if secret.is_empty() {
        return vec![];
    }

    let raw = secret.to_vec();
    let mut variants = vec![raw.clone()];

    // URL-encoded variant (only meaningful if the value is valid UTF-8)
    if let Ok(s) = std::str::from_utf8(secret) {
        let url_encoded = urlencoding::encode(s).into_owned().into_bytes();
        if url_encoded != raw {
            variants.push(url_encoded);
        }
    }

    // Base64 standard variant
    let b64_standard = STANDARD.encode(secret).into_bytes();
    if b64_standard != raw {
        variants.push(b64_standard);
    }

    // Base64 URL-safe (no padding) variant
    let b64_url_safe = URL_SAFE_NO_PAD.encode(secret).into_bytes();
    if b64_url_safe != raw {
        variants.push(b64_url_safe);
    }

    // Shell single-quoted variant
    if let Ok(s) = std::str::from_utf8(secret) {
        let single_quoted = format!("'{}'", s).into_bytes();
        if single_quoted != raw {
            variants.push(single_quoted);
        }
    }

    // Shell double-quoted variant
    if let Ok(s) = std::str::from_utf8(secret) {
        let double_quoted = format!("\"{}\"", s).into_bytes();
        if double_quoted != raw {
            variants.push(double_quoted);
        }
    }

    variants
}

impl OutputFilter {
    /// Build an output filter from a list of raw secret values.
    /// Each secret produces multiple pattern variants (raw, URL-encoded,
    /// Base64, shell-escaped) that are all compiled into a single automaton.
    pub fn new(secrets: &[Vec<u8>]) -> Result<Self, OpaqError> {
        let mut all_patterns: Vec<Vec<u8>> = Vec::new();

        for secret in secrets {
            all_patterns.extend(generate_variants(secret));
        }

        if all_patterns.is_empty() {
            return Ok(Self {
                automaton: None,
                replacements: vec![],
                longest_pattern_len: 0,
            });
        }

        let longest_pattern_len = all_patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let pattern_count = all_patterns.len();

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&all_patterns)
            .map_err(|e| OpaqError::FilterBuild(e.to_string()))?;

        Ok(Self {
            automaton: Some(automaton),
            replacements: vec![MASKED; pattern_count],
            longest_pattern_len,
        })
    }

    /// Filter a stream, replacing all secret pattern matches with [MASKED].
    /// Uses a sliding window buffer with LeftmostLongest matching to correctly
    /// handle both buffer boundary splits and overlapping pattern variants.
    pub fn filter_stream(
        &self,
        input: &mut impl Read,
        output: &mut impl Write,
    ) -> Result<(), OpaqError> {
        let ac = match &self.automaton {
            Some(ac) => ac,
            None => {
                // No patterns -- passthrough
                std::io::copy(input, output)?;
                return Ok(());
            }
        };

        // Holdback: keep (longest_pattern_len - 1) bytes in the buffer to
        // catch patterns that span read boundaries.
        let holdback = self.longest_pattern_len.saturating_sub(1);
        let repls = &self.replacements;

        let mut buf = [0u8; 8192];
        let mut pending: Vec<u8> = Vec::new();

        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                // EOF: flush all remaining bytes through the automaton
                if !pending.is_empty() {
                    let replaced = ac.replace_all_bytes(&pending, repls);
                    output.write_all(&replaced)?;
                }
                break;
            }

            pending.extend_from_slice(&buf[..n]);

            if pending.len() <= holdback {
                // Not enough data to safely emit -- keep buffering
                continue;
            }

            if holdback == 0 {
                let replaced = ac.replace_all_bytes(&pending, repls);
                output.write_all(&replaced)?;
                pending.clear();
            } else {
                // We need to emit bytes from the buffer while keeping enough
                // trailing bytes (holdback) to catch cross-boundary matches.
                //
                // Strategy: scan for matches in the full pending buffer. Find
                // the safe emit boundary: the default is (pending.len() - holdback),
                // but if any match spans across that boundary, we must not emit
                // past its start position.
                let safe_end = pending.len() - holdback;
                let mut emit_up_to = safe_end;

                for m in ac.find_iter(&pending) {
                    if m.start() < safe_end && m.end() > safe_end {
                        // This match spans the boundary
                        emit_up_to = emit_up_to.min(m.start());
                    }
                    if m.start() >= safe_end {
                        break;
                    }
                }

                if emit_up_to == 0 {
                    // Can't emit anything safely yet
                    continue;
                }

                // Replace and emit the safe portion
                let to_emit = &pending[..emit_up_to];
                let emitted = ac.replace_all_bytes(to_emit, repls);
                output.write_all(&emitted)?;

                // Keep the rest
                pending = pending[emit_up_to..].to_vec();
            }
        }

        output.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_secrets_passthrough() {
        let filter = OutputFilter::new(&[]).unwrap();
        let input_data = b"Hello, world! No secrets here.";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(output, input_data);
    }

    #[test]
    fn single_secret_raw_match() {
        let filter = OutputFilter::new(&[b"my-secret-token".to_vec()]).unwrap();
        let input_data = b"Authorization: Bearer my-secret-token";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Authorization: Bearer [MASKED]"
        );
    }

    #[test]
    fn multiple_secrets() {
        let filter = OutputFilter::new(&[b"secret-one".to_vec(), b"secret-two".to_vec()]).unwrap();
        let input_data = b"first: secret-one, second: secret-two";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "first: [MASKED], second: [MASKED]"
        );
    }

    #[test]
    fn url_encoded_variant() {
        let filter = OutputFilter::new(&[b"my-secret/token+1".to_vec()]).unwrap();
        let input_data = b"url=my-secret%2Ftoken%2B1&other=val";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "url=[MASKED]&other=val");
    }

    #[test]
    fn base64_standard_variant() {
        let filter = OutputFilter::new(&[b"my-secret/token+1".to_vec()]).unwrap();
        let encoded = STANDARD.encode(b"my-secret/token+1");
        let input_data = format!("Authorization: Basic {}", encoded);
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Authorization: Basic [MASKED]"
        );
    }

    #[test]
    fn base64_url_safe_variant() {
        let filter = OutputFilter::new(&[b"my-secret/token+1".to_vec()]).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(b"my-secret/token+1");
        let input_data = format!("token={}", encoded);
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "token=[MASKED]");
    }

    #[test]
    fn shell_single_quoted_variant() {
        let filter = OutputFilter::new(&[b"my-secret".to_vec()]).unwrap();
        let input_data = b"echo 'my-secret'";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();
        // LeftmostLongest prefers the longer quoted pattern over the raw value
        assert_eq!(result, "echo [MASKED]");
    }

    #[test]
    fn shell_double_quoted_variant() {
        let filter = OutputFilter::new(&[b"my-secret".to_vec()]).unwrap();
        let input_data = b"echo \"my-secret\"";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();
        assert_eq!(result, "echo [MASKED]");
    }

    #[test]
    fn boundary_spanning_match() {
        let filter = OutputFilter::new(&[b"secret-token".to_vec()]).unwrap();

        struct ChunkedReader {
            data: Vec<u8>,
            pos: usize,
            chunk_size: usize,
        }

        impl Read for ChunkedReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                let end = (self.pos + self.chunk_size)
                    .min(self.data.len())
                    .min(self.pos + buf.len());
                let n = end - self.pos;
                buf[..n].copy_from_slice(&self.data[self.pos..end]);
                self.pos += n;
                Ok(n)
            }
        }

        let input_data = b"prefix secret-token suffix".to_vec();
        let mut reader = ChunkedReader {
            data: input_data,
            pos: 0,
            chunk_size: 5,
        };
        let mut output = Vec::new();
        filter.filter_stream(&mut reader, &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "prefix [MASKED] suffix");
    }

    #[test]
    fn no_false_positive() {
        let filter = OutputFilter::new(&[b"secret".to_vec()]).unwrap();
        let input_data = b"This has no matching patterns at all.";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(output, input_data.to_vec());
    }

    #[test]
    fn multiple_occurrences_same_secret() {
        let filter = OutputFilter::new(&[b"tok".to_vec()]).unwrap();
        let input_data = b"tok and tok and tok";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "[MASKED] and [MASKED] and [MASKED]"
        );
    }

    #[test]
    fn variant_dedup_simple_alphanumeric() {
        let filter = OutputFilter::new(&[b"SimpleToken123".to_vec()]).unwrap();
        let input_data = b"Got SimpleToken123 in output";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        filter.filter_stream(&mut input, &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "Got [MASKED] in output");
    }

    #[test]
    fn generate_variants_empty_secret() {
        let variants = generate_variants(b"");
        assert!(variants.is_empty());
    }

    #[test]
    fn generate_variants_has_all_types() {
        let variants = generate_variants(b"my-secret/token+1");
        assert!(variants.len() >= 5);

        assert_eq!(variants[0], b"my-secret/token+1");
        assert!(variants.iter().any(|v| v == b"my-secret%2Ftoken%2B1"));

        let b64_std = STANDARD.encode(b"my-secret/token+1");
        assert!(variants.iter().any(|v| *v == b64_std.as_bytes()));

        let b64_url = URL_SAFE_NO_PAD.encode(b"my-secret/token+1");
        assert!(variants.iter().any(|v| *v == b64_url.as_bytes()));

        assert!(variants.iter().any(|v| v == b"'my-secret/token+1'"));
        assert!(variants.iter().any(|v| v == b"\"my-secret/token+1\""));
    }
}
