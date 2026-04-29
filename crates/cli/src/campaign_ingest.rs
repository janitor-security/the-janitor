use anyhow::Context as _;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: &str = "janitor.target-ledger.v1";

const SEED_ATTACK_KEYWORDS: &[&str] = &[
    "OAuth",
    "Azure",
    "Terraform",
    "LLM",
    "GraphQL",
    "SAML",
    "OIDC",
    "Auth0",
    "Kubernetes",
    "GitHub",
    "Microsoft Graph",
    "RAG",
    "MCP",
];

const LANGUAGE_HINTS: &[(&str, &str)] = &[
    ("rust", "Rust"),
    ("cargo", "Rust"),
    ("go", "Go"),
    ("golang", "Go"),
    ("python", "Python"),
    ("django", "Python"),
    ("fastapi", "Python"),
    ("java", "Java"),
    ("spring", "Java"),
    ("javascript", "JavaScript"),
    ("typescript", "TypeScript"),
    ("js/ts", "JS/TS"),
    ("react", "TypeScript"),
    ("node", "JavaScript"),
    ("solidity", "Solidity"),
    ("evm", "Solidity"),
    ("terraform", "Terraform"),
    ("graphql", "GraphQL"),
    ("azure", "Azure"),
    ("llm", "LLM"),
    ("oauth", "OAuth"),
];

#[derive(Debug, Serialize)]
struct TargetLedger {
    schema_version: &'static str,
    generated_by: &'static str,
    attack_ledger_keywords: Vec<String>,
    targets: Vec<CampaignTarget>,
}

#[derive(Debug, Serialize)]
struct CampaignTarget {
    engagement: String,
    source_file: String,
    line_number: usize,
    target: String,
    urls: Vec<String>,
    language_tags: Vec<String>,
    matched_attack_keywords: Vec<String>,
    priority_score: u32,
}

pub(crate) fn cmd_ingest_campaigns(dir: &Path) -> anyhow::Result<()> {
    let output_path = ingest_campaigns(dir)?;
    println!("wrote {}", output_path.display());
    Ok(())
}

fn ingest_campaigns(dir: &Path) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        dir.is_dir(),
        "campaign ingestion path is not a directory: {}",
        dir.display()
    );

    let attack_ledger = load_attack_ledger(dir)?;
    let keywords = attack_keywords(&attack_ledger);
    let mut targets = Vec::new();

    for path in markdown_files(dir)? {
        if path
            .file_name()
            .is_some_and(|name| name == "ATTACK_LEDGER.md" || name == "TARGET_LEDGER.md")
        {
            continue;
        }
        ingest_file(dir, &path, &keywords, &mut targets)?;
    }

    targets.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then_with(|| left.engagement.cmp(&right.engagement))
            .then_with(|| left.target.cmp(&right.target))
    });

    let ledger = TargetLedger {
        schema_version: SCHEMA_VERSION,
        generated_by: "janitor ingest-campaigns",
        attack_ledger_keywords: keywords.iter().cloned().collect(),
        targets,
    };
    let output_path = dir.join("target_ledger.json");
    let json = serde_json::to_vec_pretty(&ledger).context("serialize target ledger")?;
    fs::write(&output_path, json).with_context(|| {
        format!(
            "failed to write campaign target ledger to {}",
            output_path.display()
        )
    })?;
    Ok(output_path)
}

fn load_attack_ledger(dir: &Path) -> anyhow::Result<String> {
    let candidates = [
        dir.join("ATTACK_LEDGER.md"),
        PathBuf::from("tools/campaign/ATTACK_LEDGER.md"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return fs::read_to_string(&candidate)
                .with_context(|| format!("failed to read {}", candidate.display()));
        }
    }
    Ok(String::new())
}

fn markdown_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir).follow_links(false) {
        let entry = entry.with_context(|| format!("failed to walk {}", dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn ingest_file(
    root: &Path,
    path: &Path,
    attack_keywords: &BTreeSet<String>,
    targets: &mut Vec<CampaignTarget>,
) -> anyhow::Result<()> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read campaign file {}", path.display()))?;
    let engagement = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unknown")
        .to_string();
    let source_file = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let urls = extract_urls(trimmed);
        if !is_target_line(trimmed, &urls) {
            continue;
        }

        let language_tags = language_tags(trimmed);
        let matched_attack_keywords = matched_keywords(trimmed, attack_keywords);
        let priority_score =
            priority_score(trimmed, &urls, &language_tags, &matched_attack_keywords);
        targets.push(CampaignTarget {
            engagement: engagement.clone(),
            source_file: source_file.clone(),
            line_number: idx + 1,
            target: normalize_target(trimmed),
            urls,
            language_tags,
            matched_attack_keywords,
            priority_score,
        });
    }
    Ok(())
}

fn is_target_line(line: &str, urls: &[String]) -> bool {
    line.starts_with("- [ ]")
        || line.starts_with("* [ ]")
        || line.starts_with("[ ]")
        || (!urls.is_empty()
            && !line.starts_with('>')
            && !line.starts_with('#')
            && !line.to_ascii_lowercase().contains("http status"))
}

fn normalize_target(line: &str) -> String {
    line.trim_start_matches("- [ ]")
        .trim_start_matches("* [ ]")
        .trim_start_matches("[ ]")
        .trim()
        .to_string()
}

fn attack_keywords(attack_ledger: &str) -> BTreeSet<String> {
    let mut keywords = BTreeSet::new();
    for keyword in SEED_ATTACK_KEYWORDS {
        if attack_ledger.is_empty()
            || attack_ledger
                .to_ascii_lowercase()
                .contains(&keyword.to_ascii_lowercase())
        {
            keywords.insert((*keyword).to_string());
        }
    }
    keywords
}

fn language_tags(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut tags = BTreeSet::new();
    for (needle, tag) in LANGUAGE_HINTS {
        if lower.contains(needle) {
            tags.insert((*tag).to_string());
        }
    }
    tags.into_iter().collect()
}

fn matched_keywords(line: &str, attack_keywords: &BTreeSet<String>) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    attack_keywords
        .iter()
        .filter(|keyword| lower.contains(&keyword.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn priority_score(
    line: &str,
    urls: &[String],
    language_tags: &[String],
    matched_attack_keywords: &[String],
) -> u32 {
    let mut score = 10;
    if line.starts_with("- [ ]") || line.starts_with("* [ ]") || line.starts_with("[ ]") {
        score += 5;
    }
    score += (urls.len() as u32).saturating_mul(2);
    score += (language_tags.len() as u32).saturating_mul(3);
    score += (matched_attack_keywords.len() as u32).saturating_mul(20);
    score
}

fn extract_urls(line: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    for token in line.split(|ch: char| ch.is_whitespace() || ch == '(' || ch == ')' || ch == ',') {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '\'' | '"' | '[' | ']' | '<' | '>' | '{' | '}' | '.' | ';' | ':'
            )
        });
        if clean.starts_with("https://") || clean.starts_with("http://") {
            urls.insert(clean.to_string());
        }
    }
    urls.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_target_ranks_above_generic_target() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        fs::write(
            tmp.path().join("ATTACK_LEDGER.md"),
            "## OAuth Scope Drift\n## GraphQL Exposure\n",
        )
        .expect("write attack ledger");
        fs::write(
            tmp.path().join("targets.md"),
            "- [ ] https://generic.example.com static marketing site\n\
             - [ ] https://auth.example.com OAuth JS/TS integration API\n",
        )
        .expect("write campaign file");

        let output = ingest_campaigns(tmp.path()).expect("ingest campaigns");
        let json = fs::read_to_string(output).expect("read output");
        let ledger: serde_json::Value = serde_json::from_str(&json).expect("parse output");
        let targets = ledger["targets"].as_array().expect("targets array");

        assert!(targets[0]["target"]
            .as_str()
            .expect("target")
            .contains("OAuth"));
        assert!(
            targets[0]["priority_score"].as_u64().expect("score")
                > targets[1]["priority_score"].as_u64().expect("score")
        );
    }
}
