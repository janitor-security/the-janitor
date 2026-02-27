//! Dependency registry — declared package dependencies extracted from manifests.
//!
//! Stores the set of packages declared in `package.json`, `Cargo.toml`,
//! `requirements.txt`, and `pyproject.toml` so that the anatomist pipeline
//! can cross-reference them against actual import statements to identify
//! zombie dependencies (declared but never imported).
//!
//! ## File format (`.janitor/deps.rkyv`)
//! Same checksum-prefixed rkyv layout as `symbols.rkyv`:
//! `[0..32]  BLAKE3 hash of the rkyv payload`
//! `[32..]   rkyv-serialized DependencyRegistry (aligned)`

use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

/// Package ecosystem / manifest type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(u8)]
pub enum DependencyEcosystem {
    /// Node.js / npm / yarn / pnpm (`package.json`).
    Npm = 0,
    /// Rust / Cargo (`Cargo.toml`).
    Cargo = 1,
    /// Python / pip (`requirements.txt`, `pyproject.toml`).
    Pip = 2,
    /// WebAssembly WASI interface (`spin.toml`).
    Wasm = 3,
    /// Cloudflare Workers binding (`wrangler.toml`).
    CloudflareBinding = 4,
}

impl std::fmt::Display for DependencyEcosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyEcosystem::Npm => f.write_str("npm"),
            DependencyEcosystem::Cargo => f.write_str("cargo"),
            DependencyEcosystem::Pip => f.write_str("pip"),
            DependencyEcosystem::Wasm => f.write_str("wasm"),
            DependencyEcosystem::CloudflareBinding => f.write_str("cloudflare"),
        }
    }
}

/// A single declared dependency from a manifest file.
#[derive(Debug, Clone, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct DependencyEntry {
    /// Package name as declared in the manifest (e.g. `"lodash"`, `"serde"`).
    pub name: String,
    /// Declared version constraint (e.g. `"^4.17.21"`, `"1.0"`, `"*"`).
    pub version: String,
    /// Package ecosystem / manifest format.
    pub ecosystem: DependencyEcosystem,
    /// `true` if this is a dev / test-only dependency.
    pub dev: bool,
}

/// Registry of all declared dependencies across all manifest files in a project.
///
/// Built by `anatomist::manifest` during a scan and cross-referenced against
/// import statements to identify zombie dependencies.
#[derive(Debug, Clone, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct DependencyRegistry {
    pub entries: Vec<DependencyEntry>,
}

impl DependencyRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts a dependency entry.
    pub fn insert(&mut self, entry: DependencyEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of declared dependencies.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no dependencies have been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all dependency names for a given ecosystem.
    pub fn names_for(&self, ecosystem: DependencyEcosystem) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.ecosystem == ecosystem)
            .map(|e| e.name.as_str())
            .collect()
    }
}

impl Default for DependencyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_registry_roundtrip() {
        let mut registry = DependencyRegistry::new();
        registry.insert(DependencyEntry {
            name: "lodash".into(),
            version: "^4.17.21".into(),
            ecosystem: DependencyEcosystem::Npm,
            dev: false,
        });
        registry.insert(DependencyEntry {
            name: "jest".into(),
            version: "^29.0.0".into(),
            ecosystem: DependencyEcosystem::Npm,
            dev: true,
        });

        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        let npm_names = registry.names_for(DependencyEcosystem::Npm);
        assert!(npm_names.contains(&"lodash"));
        assert!(npm_names.contains(&"jest"));

        let cargo_names = registry.names_for(DependencyEcosystem::Cargo);
        assert!(cargo_names.is_empty());
    }

    #[test]
    fn test_ecosystem_display() {
        assert_eq!(DependencyEcosystem::Npm.to_string(), "npm");
        assert_eq!(DependencyEcosystem::Cargo.to_string(), "cargo");
        assert_eq!(DependencyEcosystem::Pip.to_string(), "pip");
    }
}
