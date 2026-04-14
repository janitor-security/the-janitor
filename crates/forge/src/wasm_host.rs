//! Wasm rule host — executes BYOP (Bring Your Own Policy) Wasm modules
//! against patch source bytes in a fuel- and memory-bounded sandbox.
//!
//! # Resource limits (DoS prevention)
//!
//! - **Linear memory**: 10 MiB per instance.  Enforced at the [`Engine`] level
//!   via [`Config::static_memory_maximum_size`] so that no instantiation of any
//!   compiled module can exceed this ceiling regardless of what the Wasm imports
//!   declare.
//! - **Execution fuel**: 100 000 000 units — equivalent to ~100 M lightweight
//!   Wasm instructions; prevents unbounded loops in adversarially-crafted rules.
//!
//! # Host-guest ABI
//!
//! The guest module MUST export:
//!
//! | Export | Signature | Contract |
//! |--------|-----------|----------|
//! | `memory` | linear memory | Shared I/O region; host writes source bytes at offset [`SRC_OFFSET`] |
//! | `analyze` | `(i32, i32) -> i32` | `analyze(src_ptr, src_len) -> output_len`; writes findings to `output_ptr()` |
//! | `output_ptr` | `() -> i32` | Returns the base address of the findings output buffer |
//!
//! The host writes source bytes at memory offset 4096 and calls
//! `analyze(4096, src_len)`.  The guest returns the number of bytes written
//! starting at `output_ptr()`.  Findings are newline-delimited JSON, one
//! [`common::slop::StructuredFinding`] object per line.

use anyhow::{Context, Result};
use base64::Engine as _;
use common::slop::StructuredFinding;
use common::wasm_receipt::WasmPolicyReceipt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use wasmtime::{Config, Engine, Instance, Module, ResourceLimiter, Store, StoreLimitsBuilder};

/// Source-bytes offset within the guest's linear memory (4 KiB).
///
/// The first 4 KiB are reserved for the findings output buffer so that
/// source writes do not overlap with an output buffer anchored at offset 0.
const SRC_OFFSET: usize = 4096;

/// Maximum linear memory per Wasm instance (10 MiB — DoS ceiling).
const MAX_MEMORY_BYTES: usize = 10 * 1024 * 1024;

/// Maximum Wasm fuel per `analyze` invocation (~100 M lightweight instructions).
const FUEL_LIMIT: u64 = 100_000_000;
/// Wall-clock timeout per `analyze` invocation via wasmtime epoch interruption.
///
/// Fires after 100 ms regardless of remaining fuel — prevents host-side
/// allocator pressure and non-deterministic latency (CT-015).
const EPOCH_TICK_MS: u64 = 10;
const EPOCH_DEADLINE_TICKS: u64 = 10;
const WASM_POLICY_ABI_VERSION: &str = "janitor.wasm_policy.v1";

static WASM_ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();
static WASM_WATCHDOG: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone)]
struct LoadedModule {
    path: String,
    rule_id: String,
    abi_version: String,
    module_digest: String,
    module: Module,
    /// Every `module::field` import declared in the Wasm binary's import section.
    /// Collected once at load time; proves the capability surface to auditors.
    imported_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WasmExecutionResult {
    pub findings: Vec<StructuredFinding>,
    pub receipts: Vec<WasmPolicyReceipt>,
}

/// Pre-compiled BYOP Wasm rule engine.
///
/// Modules are compiled once at construction time via Cranelift JIT.  Each
/// call to [`WasmHost::run`] instantiates a fresh, fuel-bounded,
/// memory-limited store to guarantee isolation between analysis runs — a
/// faulting or fuel-exhausted module cannot affect subsequent invocations.
pub struct WasmHost {
    engine: Arc<Engine>,
    modules: Vec<LoadedModule>,
}

impl WasmHost {
    /// Compile all Wasm rule modules at the given file paths.
    ///
    /// Accepts both `.wasm` binary format and `.wat` text format (WAT
    /// compilation is handled transparently by wasmtime when the `wat`
    /// Cargo feature is enabled).
    ///
    /// Returns an error if any path is unreadable or fails to compile.
    pub fn new(
        wasm_paths: &[&str],
        wasm_pins: &HashMap<String, String>,
        pqc_pub_key: Option<&str>,
    ) -> Result<Self> {
        let engine = shared_engine()?;
        let mut modules = Vec::with_capacity(wasm_paths.len());
        for path in wasm_paths {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading Wasm rule module: {path}"))?;
            let blake3_hash = blake3::hash(&bytes);
            let module_digest = blake3_hash.to_hex().to_string();
            if let Some(expected_digest) = wasm_pins.get(*path) {
                if module_digest != *expected_digest {
                    anyhow::bail!(
                        "Wasm rule integrity pin mismatch: {path}: expected {expected_digest}, got {module_digest}"
                    );
                }
            }
            // PQC publisher verification: if a publisher key is configured, every Wasm rule
            // must carry a detached ML-DSA-65 signature file at `<path>.sig`.
            if let Some(pub_key_b64) = pqc_pub_key {
                let sig_path = format!("{path}.sig");
                let sig_b64 = std::fs::read_to_string(&sig_path).with_context(|| {
                    format!(
                        "Wasm rule signature file not found: {sig_path}; PQC verification required"
                    )
                })?;
                let sig_b64 = sig_b64.trim();
                let pub_key_bytes = base64::engine::general_purpose::STANDARD
                    .decode(pub_key_b64)
                    .context("Wasm publisher ML-DSA-65 public key base64 decode failed")?;
                let hash_bytes: [u8; 32] = *blake3_hash.as_bytes();
                let valid = common::pqc::verify_wasm_rule_ml_dsa_signature(
                    &hash_bytes,
                    &pub_key_bytes,
                    sig_b64,
                )?;
                if !valid {
                    anyhow::bail!("Wasm rule PQC signature verification failed for: {path}");
                }
            }
            let module = Module::new(engine.as_ref(), &bytes)
                .map_err(|e| anyhow::anyhow!("compiling Wasm rule module: {path}: {e:#}"))?;
            // Enumerate every import declared in the module's import section.
            // Format: "module_name::field_name" (e.g., "wasi_snapshot_preview1::fd_write").
            // An empty vec mathematically proves zero host-capability access.
            let imported_capabilities: Vec<String> = module
                .imports()
                .map(|imp| format!("{}::{}", imp.module(), imp.name()))
                .collect();
            let rule_id = Path::new(path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| !stem.is_empty())
                .unwrap_or("unknown_rule")
                .to_string();
            modules.push(LoadedModule {
                path: (*path).to_string(),
                rule_id,
                abi_version: WASM_POLICY_ABI_VERSION.to_string(),
                module_digest,
                module,
                imported_capabilities,
            });
        }
        Ok(Self { engine, modules })
    }

    /// Returns the declared import capabilities for every loaded module, in
    /// load order.
    ///
    /// Each inner `Vec<String>` is the `module::field` import list for one
    /// rule.  An empty inner vec means the corresponding rule imported nothing —
    /// provably zero host-capability access.  Used by auditors and tests.
    pub fn capabilities_snapshot(&self) -> Vec<Vec<String>> {
        self.modules
            .iter()
            .map(|m| m.imported_capabilities.clone())
            .collect()
    }

    /// Execute all loaded rule modules against `src` bytes.
    ///
    /// Each module runs in an isolated store with fresh memory and fuel.
    /// Findings from all modules are concatenated and returned.
    ///
    /// A module that exhausts fuel, exceeds the memory ceiling, or violates
    /// the ABI contract logs an error to `stderr` and is skipped — the host
    /// never panics on adversarial guest behaviour.  Returns an empty vec
    /// when `src` is empty or no modules are loaded.
    pub fn run(&self, src: &[u8]) -> WasmExecutionResult {
        if self.modules.is_empty() || src.is_empty() {
            return WasmExecutionResult::default();
        }
        let mut result = WasmExecutionResult::default();
        for loaded in &self.modules {
            match self.run_module(&loaded.module, src) {
                Ok(findings) => {
                    let result_digest = serde_json::to_vec(&findings)
                        .map(|payload| blake3::hash(&payload).to_hex().to_string())
                        .unwrap_or_else(|_| blake3::hash(&[]).to_hex().to_string());
                    result.findings.extend(findings);
                    result.receipts.push(WasmPolicyReceipt {
                        module_digest: loaded.module_digest.clone(),
                        rule_id: loaded.rule_id.clone(),
                        abi_version: loaded.abi_version.clone(),
                        result_digest,
                        host_abi_version: WASM_POLICY_ABI_VERSION.to_string(),
                        imported_capabilities: loaded.imported_capabilities.clone(),
                    });
                }
                Err(e) => {
                    eprintln!("wasm_host: rule module '{}' error: {e:#}", loaded.path);
                }
            }
        }
        result
    }

    fn run_module(&self, module: &Module, src: &[u8]) -> Result<Vec<StructuredFinding>> {
        // Fresh store per invocation — fuel and memory limits reset each time.
        // `StoreLimits` implements `ResourceLimiter` to enforce the 10 MiB memory ceiling.
        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_BYTES)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store
            .set_fuel(FUEL_LIMIT)
            .map_err(|e| anyhow::anyhow!("configuring Wasm execution fuel: {e:#}"))?;
        // CT-023: a single process-wide watchdog increments the shared engine epoch
        // every 10 ms; deadline 10 yields a 100 ms wall-clock termination budget.
        store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);

        let instance = Instance::new(&mut store, module, &[])
            .map_err(|e| anyhow::anyhow!("instantiating Wasm rule module: {e:#}"))?;

        // Resolve mandatory ABI exports.
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("Wasm rule module must export 'memory' (linear memory)")?;
        let output_ptr_fn = instance
            .get_typed_func::<(), i32>(&mut store, "output_ptr")
            .map_err(|e| {
                anyhow::anyhow!("Wasm rule module must export 'output_ptr() -> i32': {e:#}")
            })?;
        let analyze_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "analyze")
            .map_err(|e| {
                anyhow::anyhow!("Wasm rule module must export 'analyze(i32, i32) -> i32': {e:#}")
            })?;

        // Guard: source must fit within the guest memory budget.
        let src_end = SRC_OFFSET
            .checked_add(src.len())
            .filter(|&end| end <= MAX_MEMORY_BYTES)
            .context("source bytes exceed Wasm sandbox memory ceiling (10 MiB)")?;

        // Grow guest memory if the current allocation cannot accommodate the
        // source write.  Each Wasm page is exactly 64 KiB.
        let current_bytes = memory.data_size(&store);
        if current_bytes < src_end {
            let pages_needed = (src_end - current_bytes).div_ceil(65536);
            memory
                .grow(&mut store, pages_needed as u64)
                .map_err(|e| anyhow::anyhow!("growing Wasm linear memory: {e:#}"))?;
        }

        // Write source bytes into guest memory at SRC_OFFSET.
        memory.data_mut(&mut store)[SRC_OFFSET..SRC_OFFSET + src.len()].copy_from_slice(src);

        // Invoke analysis; guest writes findings to its output buffer.
        let output_len = analyze_fn
            .call(&mut store, (SRC_OFFSET as i32, src.len() as i32))
            .map_err(|e| anyhow::anyhow!("calling Wasm 'analyze' function: {e:#}"))?;
        if output_len <= 0 {
            return Ok(Vec::new());
        }

        let output_base = output_ptr_fn
            .call(&mut store, ())
            .map_err(|e| anyhow::anyhow!("calling Wasm 'output_ptr' function: {e:#}"))?;

        // Bounds-check the output range before reading.
        let base = output_base as usize;
        let end = base
            .checked_add(output_len as usize)
            .filter(|&e| e <= memory.data_size(&store))
            .context("Wasm 'analyze' returned an out-of-bounds output range")?;
        let output_bytes = memory.data(&store)[base..end].to_vec();

        // Parse newline-delimited JSON findings.
        let mut findings = Vec::new();
        for line in output_bytes.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_slice::<StructuredFinding>(line) {
                Ok(f) => findings.push(f),
                Err(e) => {
                    eprintln!("wasm_host: malformed finding JSON from rule module: {e}");
                }
            }
        }
        Ok(findings)
    }
}

fn shared_engine() -> Result<Arc<Engine>> {
    let engine = if let Some(engine) = WASM_ENGINE.get() {
        Arc::clone(engine)
    } else {
        let mut config = Config::new();
        // Fuel-based execution limit: each Wasm instruction consumes one unit.
        config.consume_fuel(true);
        // CT-015/CT-023: epoch interruption provides a wall-clock safety net
        // while the singleton watchdog drives epoch progression in O(1) space.
        config.epoch_interruption(true);
        // Wasm target pinning: explicitly disable the memory64 proposal.
        // BYOP rule modules MUST target wasm32-wasip1 (classic 32-bit linear
        // memory, no 64-bit addressing).  This rejects wasm64/wasip2 modules at
        // engine level, insulating the host from the Rust wasm32-wasi → wasip1/wasip2
        // target split.  Classic wasip1 modules compile with `--target wasm32-wasip1`
        // (formerly `wasm32-wasi`) and require only 32-bit memory.
        config.wasm_memory64(false);
        let engine = Arc::new(
            Engine::new(&config)
                .map_err(|e| anyhow::anyhow!("failed to create Wasm engine: {e:#}"))?,
        );
        match WASM_ENGINE.set(Arc::clone(&engine)) {
            Ok(()) => engine,
            Err(existing_engine) => existing_engine,
        }
    };
    WASM_WATCHDOG.get_or_init(|| {
        let engine = Arc::clone(&engine);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
            engine.increment_epoch();
        });
    });
    Ok(Arc::clone(&engine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Minimal WAT module for unit tests: always emits one `security:test_rule` finding.
    ///
    /// Output buffer starts at offset 0; source bytes land at [`SRC_OFFSET`] (4096).
    /// JSON: `{"id":"security:test_rule","file":null,"line":null}\n` = 52 bytes.
    const MOCK_WAT: &str = r#"(module
  (memory (export "memory") 2)
  (data (i32.const 0) "{\"id\":\"security:test_rule\",\"file\":null,\"line\":null}\n")
  (func (export "output_ptr") (result i32)
    i32.const 0
  )
  (func (export "analyze") (param i32 i32) (result i32)
    i32.const 52
  )
)"#;

    /// Write WAT source text to a temp file.
    ///
    /// `WasmHost::new` passes the raw bytes to `wasmtime::Module::new` which
    /// auto-detects WAT text format (feature "wat") and compiles it — no
    /// separate `wasmtime::wat::parse_str` call required.
    fn wat_to_tempfile(wat: &str) -> (tempfile::TempPath, String) {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".wat").unwrap();
        tmp.write_all(wat.as_bytes()).unwrap();
        let path = tmp.into_temp_path();
        let path_str = path.to_str().unwrap().to_owned();
        (path, path_str)
    }

    #[test]
    fn test_empty_rules_returns_empty() {
        let host = WasmHost::new(&[], &HashMap::new(), None).unwrap();
        let result = host.run(b"fn foo() {}");
        assert!(
            result.findings.is_empty(),
            "no modules must yield no findings"
        );
        assert!(
            result.receipts.is_empty(),
            "no modules must yield no receipts"
        );
    }

    #[test]
    fn test_empty_source_returns_empty() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let host = WasmHost::new(&[&path], &HashMap::new(), None).unwrap();
        let result = host.run(b"");
        assert!(
            result.findings.is_empty(),
            "empty source must yield no findings"
        );
        assert!(
            result.receipts.is_empty(),
            "empty source must yield no receipts"
        );
    }

    #[test]
    fn test_mock_rule_fires_on_source() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let host = WasmHost::new(&[&path], &HashMap::new(), None).unwrap();
        let result = host.run(b"fn foo() {}");
        assert_eq!(
            result.findings.len(),
            1,
            "mock rule must emit exactly one finding"
        );
        assert_eq!(
            result.receipts.len(),
            1,
            "mock rule must emit exactly one receipt"
        );
        assert_eq!(
            result.findings[0].id, "security:test_rule",
            "finding id must match"
        );
        assert_eq!(result.findings[0].file, None, "file must be None");
        assert_eq!(result.findings[0].line, None, "line must be None");
        assert!(!result.receipts[0].rule_id.is_empty());
        assert_eq!(result.receipts[0].abi_version, WASM_POLICY_ABI_VERSION);
    }

    #[test]
    fn test_fuel_limit_enforced() {
        // An infinite-loop WAT module must be killed by the fuel gate without panicking.
        let infinite_wat = r#"(module
  (memory (export "memory") 1)
  (func (export "output_ptr") (result i32) i32.const 0)
  (func (export "analyze") (param i32 i32) (result i32)
    (loop $l (br $l))
    i32.const 0
  )
)"#;
        let (_tmp, path) = wat_to_tempfile(infinite_wat);
        let host = WasmHost::new(&[&path], &HashMap::new(), None).unwrap();
        // Must not hang — fuel exhaustion skips the module and returns empty.
        let result = host.run(b"int main() {}");
        assert!(
            result.findings.is_empty(),
            "fuel-exhausted module must yield no findings"
        );
        assert!(
            result.receipts.is_empty(),
            "fuel-exhausted module must yield no receipts"
        );
    }

    #[test]
    fn test_wasm_pin_match_allows_module_load() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let bytes = std::fs::read(&path).unwrap();
        let mut pins = HashMap::new();
        pins.insert(path.clone(), blake3::hash(&bytes).to_hex().to_string());
        let host = WasmHost::new(&[&path], &pins, None).unwrap();
        let result = host.run(b"fn foo() {}");
        assert_eq!(result.findings.len(), 1, "pinned module must still execute");
    }

    #[test]
    fn test_wasm_pin_mismatch_rejected() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let mut pins = HashMap::new();
        pins.insert(path.clone(), "deadbeef".repeat(8));
        let err = WasmHost::new(&[&path], &pins, None)
            .err()
            .expect("mismatched pin must fail module initialisation");
        assert!(
            err.to_string().contains("integrity pin mismatch"),
            "mismatched pin must hard-fail module initialisation"
        );
    }

    #[test]
    fn test_wasm_rule_pqc_missing_sig_file_rejected() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        // Any valid-length base64 pub key — error occurs at sig-file read, before key parse.
        let fake_pub_key = base64::engine::general_purpose::STANDARD
            .encode([0u8; common::pqc::ML_DSA_PUBLIC_KEY_LEN]);
        let err = WasmHost::new(&[&path], &HashMap::new(), Some(&fake_pub_key))
            .err()
            .expect("missing .sig file must fail module initialisation");
        assert!(
            err.to_string()
                .contains("Wasm rule signature file not found"),
            "missing sig file must report signature file not found"
        );
    }

    /// A module with no imports must produce an empty `imported_capabilities`
    /// vec — proving zero host-capability access to an auditor.
    #[test]
    fn test_no_import_module_has_empty_capabilities() {
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let host = WasmHost::new(&[&path], &HashMap::new(), None).unwrap();
        let result = host.run(b"fn foo() {}");
        assert_eq!(result.receipts.len(), 1, "expected one receipt");
        let receipt = &result.receipts[0];
        assert!(
            receipt.imported_capabilities.is_empty(),
            "module with no imports must report zero capabilities"
        );
        assert_eq!(
            receipt.host_abi_version, WASM_POLICY_ABI_VERSION,
            "host_abi_version must match the constant"
        );
    }

    /// A module that imports a single host function must record that import
    /// in `capabilities_snapshot()` at load time — before any instantiation
    /// attempt.  The sandbox rejects WASI-importing modules at run time (no
    /// host linker is wired), but the capability surface is still captured
    /// statically from the module's import section, which is the evidentiary
    /// artifact the auditor needs.
    #[test]
    fn test_wasi_import_module_capabilities_captured() {
        // WAT module declaring one WASI import — used for capability auditing.
        // `WasmHost::run` will reject this at instantiation (no linker), but
        // the declared imports are captured at load time by `capabilities_snapshot`.
        let wat_with_import = r#"(module
  (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
  (memory (export "memory") 2)
  (func (export "output_ptr") (result i32) i32.const 0)
  (func (export "analyze") (param i32 i32) (result i32) i32.const 0)
)"#;
        let (_tmp, path) = wat_to_tempfile(wat_with_import);
        let host = WasmHost::new(&[&path], &HashMap::new(), None).unwrap();
        let snapshot = host.capabilities_snapshot();
        assert_eq!(
            snapshot.len(),
            1,
            "one module must produce one capability list"
        );
        let caps = &snapshot[0];
        assert_eq!(
            caps.len(),
            1,
            "one import must produce one capability entry"
        );
        assert_eq!(
            caps[0], "wasi_snapshot_preview1::proc_exit",
            "capability entry must be formatted as module::field"
        );
    }

    #[test]
    fn test_wasm_rule_pqc_wrong_length_sig_rejected() {
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen as MlKeyGen, SerDes as MlSerDes};
        let (pk, _sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA keygen must succeed");
        let (_tmp, path) = wat_to_tempfile(MOCK_WAT);
        let sig_path = format!("{path}.sig");
        // Write a signature that is far too short — must fail length check.
        let short_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        std::fs::write(&sig_path, short_sig.as_bytes()).unwrap();
        let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.into_bytes());
        let err = WasmHost::new(&[&path], &HashMap::new(), Some(&pub_key_b64))
            .err()
            .expect("wrong-length signature must fail module initialisation");
        assert!(
            err.to_string().contains("exactly"),
            "wrong-length sig must report expected byte length"
        );
        let _ = std::fs::remove_file(&sig_path);
    }
}
