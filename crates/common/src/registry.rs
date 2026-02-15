//! # Symbol Registry: Disk-Backed Symbol Index
//!
//! Stores cross-file symbol references via `rkyv` zero-copy serialization.
//! Enables fast mmap-based lookups for reference graph construction.

use crate::Protection;
use memmap2::Mmap;
use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::Path;

/// Errors from registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Deserialization error: {0}")]
    DeserializeError(String),
}

/// SipHash of symbol ID strings. Deterministic within a Rust version.
///
/// # Examples
/// ```
/// # use common::registry::symbol_hash;
/// let h1 = symbol_hash("src/api.py::foo");
/// let h2 = symbol_hash("src/api.py::foo");
/// assert_eq!(h1, h2);
/// ```
pub fn symbol_hash(s: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Single symbol entry in the registry.
#[derive(Debug, Clone, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct SymbolEntry {
    pub id: u64,
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub entity_type: u8,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    /// Alpha-normalized structural fingerprint (0 for classes/assignments).
    pub structural_hash: u64,
    /// Protection reason (if entity survived the pipeline). `None` = candidate for deletion.
    pub protected_by: Option<Protection>,
}

/// In-memory symbol registry, serializable to disk.
#[derive(Debug, Clone, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct SymbolRegistry {
    pub entries: Vec<SymbolEntry>,
}

impl SymbolRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts a symbol entry.
    pub fn insert(&mut self, entry: SymbolEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of symbols.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sorts entries by ID and serializes the registry to bytes using `rkyv`.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, RegistryError> {
        self.entries.sort_by_key(|e| e.id);
        let aligned = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| RegistryError::DeserializeError(e.to_string()))?;
        Ok(aligned.to_vec())
    }

    /// Saves the registry to a file (sorts by ID before writing).
    pub fn save(&mut self, path: &Path) -> Result<(), RegistryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = self.to_bytes()?;
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }
}

impl Default for SymbolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped read-only registry handle.
pub struct MappedRegistry {
    _mmap: Mmap,
}

impl MappedRegistry {
    /// Opens a registry file via mmap.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Validate the archive
        rkyv::access::<ArchivedSymbolRegistry, rkyv::rancor::Error>(&mmap)
            .map_err(|e| RegistryError::DeserializeError(e.to_string()))?;

        Ok(Self { _mmap: mmap })
    }

    /// Returns a reference to the archived registry (zero-copy).
    pub fn archived(&self) -> &ArchivedSymbolRegistry {
        // SAFETY: We validated the archive in `open()` via rkyv::access.
        // The mmap is held for the lifetime of self, so the reference is valid.
        unsafe { rkyv::access_unchecked::<ArchivedSymbolRegistry>(&self._mmap[..]) }
    }

    /// Finds an entry by symbol ID (binary search; requires sorted registry).
    pub fn find_by_id(&self, id: u64) -> Option<&ArchivedSymbolEntry> {
        let entries = &self.archived().entries;
        let idx = entries.binary_search_by_key(&id, |e| e.id.into()).ok()?;
        Some(&entries[idx])
    }

    /// Returns the number of symbols.
    pub fn len(&self) -> usize {
        self.archived().entries.len()
    }

    /// Returns `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.archived().entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_determinism() {
        let h1 = symbol_hash("src/api.py::foo");
        let h2 = symbol_hash("src/api.py::foo");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_uniqueness() {
        let h1 = symbol_hash("src/api.py::foo");
        let h2 = symbol_hash("src/api.py::bar");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_registry_roundtrip() {
        let mut registry = SymbolRegistry::new();
        registry.insert(SymbolEntry {
            id: 12345,
            name: "foo".into(),
            qualified_name: "module.foo".into(),
            file_path: "src/test.py".into(),
            entity_type: 0,
            start_line: 10,
            end_line: 20,
            start_byte: 100,
            end_byte: 200,
            structural_hash: 0,
            protected_by: None,
        });

        let bytes = registry.to_bytes().unwrap();
        let archived = rkyv::access::<ArchivedSymbolRegistry, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(archived.entries.len(), 1);
        assert_eq!(archived.entries[0].id, 12345);
        assert_eq!(archived.entries[0].name.as_str(), "foo");
    }

    #[test]
    fn test_save_and_mmap() {
        let mut registry = SymbolRegistry::new();
        registry.insert(SymbolEntry {
            id: 999,
            name: "bar".into(),
            qualified_name: "pkg.bar".into(),
            file_path: "pkg/mod.py".into(),
            entity_type: 1,
            start_line: 5,
            end_line: 10,
            start_byte: 50,
            end_byte: 150,
            structural_hash: 0,
            protected_by: Some(Protection::LifecycleMethod),
        });

        let tmp_path = std::env::temp_dir().join("test_registry.db");
        registry.save(&tmp_path).unwrap();

        let mapped = MappedRegistry::open(&tmp_path).unwrap();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped.archived().entries[0].id, 999);

        std::fs::remove_file(tmp_path).ok();
    }

    #[test]
    fn test_empty_registry() {
        let registry = SymbolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_find_by_id_miss() {
        let mut registry = SymbolRegistry::new();
        registry.insert(SymbolEntry {
            id: 100,
            name: "test".into(),
            qualified_name: "test".into(),
            file_path: "test.py".into(),
            entity_type: 0,
            start_line: 1,
            end_line: 2,
            start_byte: 0,
            end_byte: 10,
            structural_hash: 0,
            protected_by: None,
        });

        let tmp_path = std::env::temp_dir().join("test_find_by_id.db");
        registry.save(&tmp_path).unwrap();

        let mapped = MappedRegistry::open(&tmp_path).unwrap();
        assert!(mapped.find_by_id(999).is_none());

        std::fs::remove_file(tmp_path).ok();
    }
}
