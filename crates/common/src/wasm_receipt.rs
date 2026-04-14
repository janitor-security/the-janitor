use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Deterministic provenance envelope for an executed Wasm policy module.
///
/// The `imported_capabilities` field lists every `module::field` import
/// declared in the module's import section (e.g., `wasi_snapshot_preview1::fd_write`).
/// An auditor can assert that a module whose `imported_capabilities` is empty
/// had **zero** access to the host filesystem, network, or WASI syscall surface.
///
/// `host_abi_version` records the host ABI contract version enforced during
/// execution — distinct from any version the guest module may declare.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct WasmPolicyReceipt {
    pub module_digest: String,
    pub rule_id: String,
    pub abi_version: String,
    pub result_digest: String,
    /// Host-ABI version string enforced for this execution.
    pub host_abi_version: String,
    /// Every `module::field` import declared in the Wasm module's import section.
    /// Empty means the module imported nothing — no WASI, no host functions.
    pub imported_capabilities: Vec<String>,
}
