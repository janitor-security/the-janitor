//! OTLP log ingestion — identifies referenced symbols in structured JSON logs.
//!
//! Consolidated from the former `lazarus` crate (v6.6.0 Legacy Autopsy).
//!
//! ## Supported formats
//! - Plain JSON: a stream of adjacent JSON objects (NDJSON or concatenated).
//! - Gzip-compressed JSON: files with a `.gz` extension are decompressed on the fly.
//!
//! ## Algorithm
//! 1. Build a single Aho-Corasick automaton over all qualified symbol names.
//! 2. Open the file (decompressing if `.gz`).
//! 3. Stream-parse each JSON value and flatten all `String` leaf nodes into a
//!    single text buffer per object.
//! 4. Scan the buffer with the automaton — O(N) in log bytes, single pass.
//! 5. Return the set of symbol IDs whose names appeared in any log object.

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Ingests OTLP logs from a file and identifies which symbols were referenced.
///
/// # Arguments
/// * `path`    — Path to the log file (plain JSON stream or `.gz`-compressed).
/// * `symbols` — Slice of `(id, qualified_name)` pairs to search for.
///
/// # Returns
/// A `HashSet` containing the IDs of every symbol whose qualified name appeared
/// in at least one log record.
pub fn ingest_otlp_logs(path: &Path, symbols: &[(u64, &str)]) -> Result<HashSet<u64>> {
    let mut patterns: Vec<&str> = Vec::with_capacity(symbols.len());
    let mut ids: Vec<u64> = Vec::with_capacity(symbols.len());

    for (id, name) in symbols {
        if !name.is_empty() {
            patterns.push(name);
            ids.push(*id);
        }
    }

    if patterns.is_empty() {
        return Ok(HashSet::new());
    }

    let ac = AhoCorasick::new(&patterns).context("Failed to build Aho-Corasick automaton")?;
    let mut found_ids = HashSet::new();

    let file = File::open(path).with_context(|| format!("Failed to open log file: {path:?}"))?;
    let reader: Box<dyn Read> = if path.extension().and_then(|ext| ext.to_str()) == Some("gz") {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let buf_reader = BufReader::new(reader);

    let stream = serde_json::Deserializer::from_reader(buf_reader).into_iter::<Value>();
    for result in stream {
        match result {
            Ok(value) => {
                let mut buffer = String::new();
                flatten_json_value(&value, &mut buffer);
                for mat in ac.find_iter(&buffer) {
                    if let Some(&id) = ids.get(mat.pattern().as_usize()) {
                        found_ids.insert(id);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Malformed JSON object in log stream: {e}");
            }
        }
    }

    Ok(found_ids)
}

/// Recursively flattens all `String` leaf nodes in a JSON value into `buffer`.
///
/// A space separator is appended after each string to prevent accidental
/// cross-field concatenation matches.
fn flatten_json_value(value: &Value, buffer: &mut String) {
    match value {
        Value::String(s) => {
            buffer.push_str(s);
            buffer.push(' ');
        }
        Value::Array(arr) => {
            for v in arr {
                flatten_json_value(v, buffer);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj {
                flatten_json_value(v, buffer);
            }
        }
        _ => {} // Numbers, bools, null do not contain symbol names.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_ingest_plain_json() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("logs.json");
        let log = serde_json::json!({"body": "Calling my_module.test_func now"});
        std::fs::write(&file_path, serde_json::to_vec(&log)?)?;

        let symbols: &[(u64, &str)] = &[(101, "my_module.test_func"), (202, "my_module.unused")];
        let found = ingest_otlp_logs(&file_path, symbols)?;
        assert!(found.contains(&101));
        assert!(!found.contains(&202));
        Ok(())
    }

    #[test]
    fn test_ingest_otlp_logs_gz() -> Result<()> {
        let symbols: &[(u64, &str)] = &[(101, "my_module.test_func"), (202, "my_module.unused")];

        let log_data = vec![
            serde_json::json!({"body": "Starting application...", "severity": "INFO"}),
            serde_json::json!({"body": "Calling my_module.test_func now", "severity": "DEBUG",
                "attributes": {"span_name": "execution_trace"}}),
            serde_json::json!({"body": "Unrelated log", "severity": "INFO"}),
        ];

        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("test_logs.json.gz");
        let file = std::fs::File::create(&file_path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        for log in log_data {
            serde_json::to_writer(&mut encoder, &log)?;
            writeln!(encoder)?;
        }
        encoder.finish()?;

        let found_ids = ingest_otlp_logs(&file_path, symbols)?;
        assert!(
            found_ids.contains(&101),
            "Should have found 'my_module.test_func' (ID 101)"
        );
        assert!(
            !found_ids.contains(&202),
            "Should NOT have found 'my_module.unused' (ID 202)"
        );
        Ok(())
    }

    #[test]
    fn test_empty_symbols_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("logs.json");
        std::fs::write(&file_path, b"{\"body\": \"hello\"}")?;
        let found = ingest_otlp_logs(&file_path, &[])?;
        assert!(found.is_empty());
        Ok(())
    }
}
