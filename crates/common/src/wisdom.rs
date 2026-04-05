use crate::deps::DependencyEcosystem;
use memmap2::Mmap;
use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use semver::{Version, VersionReq};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct ImmortalityRule {
    pub framework: String,
    pub patterns: Vec<String>,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub action: Option<String>,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct MetaPattern {
    #[serde(default)]
    pub exact_matches: Vec<String>,
    #[serde(default)]
    pub suffix_matches: Vec<String>,
    #[serde(default)]
    pub prefix_matches: Vec<String>,
    #[serde(default)]
    pub syntax_markers: Vec<String>,
}

impl MetaPattern {
    pub fn merge(&mut self, other: MetaPattern) {
        self.exact_matches.extend(other.exact_matches);
        self.suffix_matches.extend(other.suffix_matches);
        self.prefix_matches.extend(other.prefix_matches);
        self.syntax_markers.extend(other.syntax_markers);
    }

    pub fn sort(&mut self) {
        self.exact_matches.sort();
        self.suffix_matches.sort();
        self.prefix_matches.sort();
        self.syntax_markers.sort();
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct WisdomSet {
    pub immortality_rules: Vec<ImmortalityRule>,
    pub meta_patterns: MetaPattern,
    #[serde(default)]
    pub kev_dependency_rules: Vec<KevDependencyRule>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
    CheckBytes,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct KevDependencyRule {
    pub package_name: String,
    pub ecosystem: DependencyEcosystem,
    pub cve_id: String,
    #[serde(default)]
    pub affected_versions: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KevDependencyHit {
    pub package_name: String,
    pub version: String,
    pub ecosystem: DependencyEcosystem,
    pub cve_id: String,
    pub summary: String,
}

impl WisdomSet {
    pub fn sort(&mut self) {
        self.immortality_rules.sort();
        self.meta_patterns.sort();
        self.kev_dependency_rules.sort();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedDependency {
    name: String,
    version: String,
    ecosystem: DependencyEcosystem,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct LegacyWisdomSet {
    pub immortality_rules: Vec<ImmortalityRule>,
    pub meta_patterns: MetaPattern,
}

pub fn find_kev_dependency_hits(lockfile: &[u8], wisdom_db: &Path) -> Vec<KevDependencyHit> {
    let Ok(lockfile_str) = std::str::from_utf8(lockfile) else {
        return Vec::new();
    };
    let resolved = parse_cargo_lock_dependencies(lockfile_str);
    if resolved.is_empty() {
        return Vec::new();
    }

    let Some(wisdom) = load_wisdom_set(wisdom_db) else {
        return Vec::new();
    };
    if wisdom.kev_dependency_rules.is_empty() {
        return Vec::new();
    }

    let mut hits = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();

    for dep in resolved {
        for rule in &wisdom.kev_dependency_rules {
            if rule.ecosystem != dep.ecosystem
                || !rule.package_name.eq_ignore_ascii_case(&dep.name)
                || !kev_rule_matches_version(&rule.affected_versions, &dep.version)
            {
                continue;
            }

            let dedup_key = (
                dep.name.to_ascii_lowercase(),
                dep.version.clone(),
                rule.cve_id.clone(),
            );
            if !seen.insert(dedup_key) {
                continue;
            }

            hits.push(KevDependencyHit {
                package_name: dep.name.clone(),
                version: dep.version.clone(),
                ecosystem: dep.ecosystem,
                cve_id: rule.cve_id.clone(),
                summary: rule.summary.clone(),
            });
        }
    }

    hits.sort();
    hits
}

/// Load a `wisdom.rkyv` archive from `path`.
///
/// Returns `None` when the file is missing, corrupt, or not a supported
/// archived Wisdom format.
pub fn load_wisdom_set(path: &Path) -> Option<WisdomSet> {
    let file = File::open(path).ok()?;
    let mmap = unsafe { Mmap::map(&file).ok()? };

    if let Ok(archived) = rkyv::access::<ArchivedWisdomSet, rkyv::rancor::Error>(&mmap[..]) {
        return rkyv::deserialize::<WisdomSet, rkyv::rancor::Error>(archived).ok();
    }

    let archived = rkyv::access::<ArchivedLegacyWisdomSet, rkyv::rancor::Error>(&mmap[..]).ok()?;
    let legacy = rkyv::deserialize::<LegacyWisdomSet, rkyv::rancor::Error>(archived).ok()?;
    Some(WisdomSet {
        immortality_rules: legacy.immortality_rules,
        meta_patterns: legacy.meta_patterns,
        kev_dependency_rules: Vec::new(),
    })
}

/// Resolve and validate the KEV dependency database under `janitor_dir`.
///
/// The machine-readable KEV correlation rules live in `wisdom.rkyv`; the
/// adjacent `wisdom_manifest.json` is only a human/diff-friendly CISA snapshot
/// and cannot reconstruct package-version bindings on its own.
pub fn resolve_kev_database(janitor_dir: &Path) -> anyhow::Result<PathBuf> {
    let wisdom_path = janitor_dir.join("wisdom.rkyv");
    let manifest_path = janitor_dir.join("wisdom_manifest.json");

    anyhow::ensure!(
        wisdom_path.exists(),
        if manifest_path.exists() {
            format!(
                "KEV database missing at {}; {} exists but cannot replace package-version bindings from wisdom.rkyv",
                wisdom_path.display(),
                manifest_path.display()
            )
        } else {
            format!("KEV database missing at {}", wisdom_path.display())
        }
    );

    let wisdom = load_wisdom_set(&wisdom_path).ok_or_else(|| {
        anyhow::anyhow!(
            "failed to deserialize KEV database at {}; file is missing, corrupt, or incompatible",
            wisdom_path.display()
        )
    })?;

    anyhow::ensure!(
        !wisdom.kev_dependency_rules.is_empty(),
        "KEV database at {} contains no dependency rules",
        wisdom_path.display()
    );

    Ok(wisdom_path)
}

fn parse_cargo_lock_dependencies(content: &str) -> Vec<ResolvedDependency> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(packages) = val.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };

    let mut deps = Vec::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let name = table
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .trim();
        let version = table
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        deps.push(ResolvedDependency {
            name: name.to_owned(),
            version: version.to_owned(),
            ecosystem: DependencyEcosystem::Cargo,
        });
    }
    deps
}

fn kev_rule_matches_version(ranges: &[String], version: &str) -> bool {
    let version = version.trim_start_matches('v');
    let Ok(parsed_version) = Version::parse(version) else {
        return false;
    };

    ranges
        .iter()
        .any(|range| version_req_matches(range, &parsed_version))
}

fn version_req_matches(range: &str, version: &Version) -> bool {
    let trimmed = range.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Ok(exact) = Version::parse(trimmed.trim_start_matches('v')) {
        return &exact == version;
    }

    VersionReq::parse(trimmed)
        .map(|req| req.matches(version))
        .unwrap_or(false)
}

/// Wrapper for JSON (de)serialization of `immortality_rules.json` files.
///
/// Used by `tools/wisdom-bake` to load rule files from disk and merge them
/// into a [`WisdomSet`].
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
pub struct ImmortalityRulesWrapper {
    pub immortality_rules: Vec<ImmortalityRule>,
}

impl ImmortalityRulesWrapper {
    /// Returns `true` if this wrapper contains no rules.
    pub fn is_empty(&self) -> bool {
        self.immortality_rules.is_empty()
    }
}
