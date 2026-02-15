use anyhow::{Context, Result};
use common::wisdom::{ImmortalityRulesWrapper, MetaPattern, WisdomSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

fn main() -> Result<()> {
    let root_dir = Path::new("rules");
    if !root_dir.exists() {
        eprintln!(
            "Warning: 'rules' directory not found at {}. Creating empty wisdom.rkyv.",
            root_dir.display()
        );
        let mut empty_set = WisdomSet::default();
        save_wisdom_set(&mut empty_set)?;
        return Ok(());
    }

    let wisdom_set = load_json_rules(root_dir)?;
    save_wisdom_set(&mut wisdom_set.clone())?; // Clone because save sorts in place, but we might want to inspect or verify? Actually save consumes or takes mut ref.

    println!(
        "Successfully compiled wisdom.rkyv with {} rules and {} meta patterns.",
        wisdom_set.immortality_rules.len(),
        wisdom_set.meta_patterns.exact_matches.len()
            + wisdom_set.meta_patterns.suffix_matches.len()
            + wisdom_set.meta_patterns.prefix_matches.len()
            + wisdom_set.meta_patterns.syntax_markers.len()
    );

    Ok(())
}

fn load_json_rules(root: &Path) -> Result<WisdomSet> {
    let mut wisdom_set = WisdomSet::default();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            println!("Processing: {:?}", path);
            let content =
                fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

            // Try parsing as ImmortalityRulesWrapper
            if let Ok(wrapper) = serde_json::from_str::<ImmortalityRulesWrapper>(&content) {
                wisdom_set
                    .immortality_rules
                    .extend(wrapper.immortality_rules);
                continue;
            }

            // Try parsing as MetaPattern
            if let Ok(pattern) = serde_json::from_str::<MetaPattern>(&content) {
                wisdom_set.meta_patterns.merge(pattern);
                continue;
            }

            // Fallback: Check if it's a raw list of ImmortalityRule (some frameworks might just be a list?)
            // The spec says "Format 3: Framework-Keyed Rules (JS/TS)".
            // We might need to handle that later. For now, we stick to the mandate.
            eprintln!(
                "Warning: Could not identify JSON schema for {:?}. Skipping.",
                path
            );
        }
    }

    Ok(wisdom_set)
}

fn save_wisdom_set(wisdom_set: &mut WisdomSet) -> Result<()> {
    // 1. Sort for determinism
    wisdom_set.sort();

    // 2. Serialize
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(wisdom_set)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))?;

    // 3. Write to disk
    fs::write("wisdom.rkyv", bytes).context("Failed to write wisdom.rkyv")?;

    Ok(())
}
