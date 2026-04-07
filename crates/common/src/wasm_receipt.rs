use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Deterministic provenance envelope for an executed Wasm policy module.
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
}
