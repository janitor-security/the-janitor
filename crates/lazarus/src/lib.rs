use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use common::registry::SymbolRegistry;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Ingests OTLP logs from a file (JSON or JSON.gz) and identifies referenced symbols.
///
/// # Arguments
/// * `path` - Path to the log file.
/// * `registry` - The symbol registry containing symbols to search for.
///
/// # Returns
/// A `HashSet` of symbol IDs that were found in the logs.
pub fn ingest_otlp_logs(path: &Path, registry: &SymbolRegistry) -> Result<HashSet<u64>> {
    // 1. Prepare Aho-Corasick automaton
    let mut patterns = Vec::new();
    let mut ids = Vec::new();

    for entry in &registry.entries {
        // Use qualified name as the pattern
        if !entry.qualified_name.is_empty() {
            patterns.push(entry.qualified_name.as_str());
            ids.push(entry.id);
        }
    }

    let ac = AhoCorasick::new(&patterns).context("Failed to build Aho-Corasick automaton")?;
    let mut found_ids = HashSet::new();

    // 2. Open file and setup decoder
    let file = File::open(path).with_context(|| format!("Failed to open log file: {:?}", path))?;
    let reader: Box<dyn Read> = if path.extension().and_then(|ext| ext.to_str()) == Some("gz") {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let buf_reader = BufReader::new(reader);

    // 3. Stream Parsing
    let stream = serde_json::Deserializer::from_reader(buf_reader).into_iter::<Value>();

    for result in stream {
        match result {
            Ok(value) => {
                // 4. Extraction & Matching
                let mut buffer = String::new();
                flatten_json_value(&value, &mut buffer);

                for mat in ac.find_iter(&buffer) {
                    let pattern_index = mat.pattern().as_usize();
                    if let Some(&id) = ids.get(pattern_index) {
                        found_ids.insert(id);
                    }
                }
            }
            Err(e) => {
                // Resilience: Log warning and continue
                eprintln!("Warning: Malformed JSON object in log stream: {}", e);
                continue;
            }
        }
    }

    Ok(found_ids)
}

/// Helper to flatten JSON values into a single string buffer.
/// It recursively visits strings in the JSON object.
fn flatten_json_value(value: &Value, buffer: &mut String) {
    match value {
        Value::String(s) => {
            buffer.push_str(s);
            buffer.push(' '); // Separator to avoid accidental concatenation matches
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
        _ => {} // Ignore Numbers, Bools, Null for now as we are looking for symbol names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::registry::SymbolEntry;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_ingest_otlp_logs_gz() -> Result<()> {
        // 1. Create a dummy registry
        let mut registry = SymbolRegistry::new();
        registry.insert(SymbolEntry {
            id: 101,
            name: "test_func".into(),
            qualified_name: "my_module.test_func".into(),
            file_path: "src/main.rs".into(),
            entity_type: 0,
            start_line: 1,
            end_line: 5,
            start_byte: 0,
            end_byte: 100,
            structural_hash: 0,
            protected_by: None,
        });
        registry.insert(SymbolEntry {
            id: 202,
            name: "unused".into(),
            qualified_name: "my_module.unused".into(),
            file_path: "src/lib.rs".into(),
            entity_type: 0,
            start_line: 1,
            end_line: 5,
            start_byte: 0,
            end_byte: 100,
            structural_hash: 0,
            protected_by: None,
        });

        // 2. Create a temporary .json.gz file with OTLP-like logs
        let log_data = vec![
            serde_json::json!({
                "body": "Starting application...",
                "severity": "INFO"
            }),
            serde_json::json!({
                "body": "Calling my_module.test_func now",
                "severity": "DEBUG",
                "attributes": {
                    "span_name": "execution_trace"
                }
            }),
            serde_json::json!({
                "body": "Unrelated log",
                "severity": "INFO"
            }),
        ];

        let _temp_file = NamedTempFile::new()?;
        // Construct a gz file with an explicit extension in a temp dir.
        // ingest_otlp_logs checks file extension; NamedTempFile uses a random name.
        // Let's create a file in temp dir with explicit name.

        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("test_logs.json.gz");
        let file = File::create(&file_path)?;

        let mut encoder = GzEncoder::new(file, Compression::default());
        for log in log_data {
            serde_json::to_writer(&mut encoder, &log)?;
            // Write a newline or nothing? serde_json::Deserializer::from_reader can handle stream of JSON values.
            // But usually NDJSON has newlines. serde_json::Deserializer handles adjacent values too.
            // Let's add whitespace just in case.
            write!(encoder, "\n")?;
        }
        encoder.finish()?;

        // 3. Run ingestor
        let found_ids = ingest_otlp_logs(&file_path, &registry)?;

        // 4. Verify
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
}
