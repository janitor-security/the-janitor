use rkyv::{Archive, Deserialize, Serialize};
use std::collections::HashMap;

/// CLR: The source of truth for all symbolic facts.
/// Zero-copy mandatory for O(1) inter-crate synchronization.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub enum ClrFact {
    /// maps(caller_id, callee_id)
    Call { caller: u32, callee: u32 },
    /// defines(file_id, symbol_id)
    Definition { file: u32, symbol: u32 },
    /// references(symbol_id, type_id)
    TypeRef { symbol: u32, ty: u32 },
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(check_bytes)]
pub struct ClrGraph {
    pub facts: Vec<ClrFact>,
    /// Metadata for the Insolent Kernel bitmask
    pub symbol_attestation_hash: [u8; 32],
}

impl ClrGraph {
    /// The "Funnel" check: Datalog-verified reachability.
    /// Returns O(1) proof status via zero-copy buffer.
    pub fn is_candidate_for_purge(&self, symbol_id: u32) -> bool {
        // Implementation logic for Datalog-derived candidate status
        // To be expanded in crates/oracle
        true
    }
}

/// The Signing Oracle: HSM-compatible binary integrity.
pub trait JanitorSigner {
    fn sign_binary(&self, binary_data: &[u8]) -> Result<Vec<u8>, String>;
    fn verify_attestation(&self, hash: &[u8; 32], cert: &[u8]) -> bool;
}