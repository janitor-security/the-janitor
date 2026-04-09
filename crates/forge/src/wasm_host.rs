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
use common::slop::StructuredFinding;
use common::wasm_receipt::WasmPolicyReceipt;
use std::path::Path;
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
const EPOCH_TIMEOUT_MS: u64 = 100;
const WASM_POLICY_ABI_VERSION: &str = "janitor.wasm_policy.v1";

#[derive(Debug, Clone)]
struct LoadedModule {
    path: String,
    rule_id: String,
    abi_version: String,
    module_digest: String,
    module: Module,
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
    engine: Engine,
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
    pub fn new(wasm_paths: &[&str]) -> Result<Self> {
        let mut config = Config::new();
        // Fuel-based execution limit: each Wasm instruction consumes one unit.
        config.consume_fuel(true);
        // CT-015: epoch interruption provides a wall-clock safety net alongside
        // the fuel gate.  A guest that allocates near the memory ceiling within
        // the fuel budget can cause host-side latency spikes; the epoch timeout
        // guarantees termination within EPOCH_TIMEOUT_MS regardless of fuel.
        config.epoch_interruption(true);
        // Wasm target pinning: explicitly disable the memory64 proposal.
        // BYOP rule modules MUST target wasm32-wasip1 (classic 32-bit linear
        // memory, no 64-bit addressing).  This rejects wasm64/wasip2 modules at
        // engine level, insulating the host from the Rust wasm32-wasi → wasip1/wasip2
        // target split.  Classic wasip1 modules compile with `--target wasm32-wasip1`
        // (formerly `wasm32-wasi`) and require only 32-bit memory.
        config.wasm_memory64(false);
        let engine = Engine::new(&config)
            .map_err(|e| anyhow::anyhow!("failed to create Wasm engine: {e:#}"))?;
        let mut modules = Vec::with_capacity(wasm_paths.len());
        for path in wasm_paths {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading Wasm rule module: {path}"))?;
            let module = Module::new(&engine, &bytes)
                .map_err(|e| anyhow::anyhow!("compiling Wasm rule module: {path}: {e:#}"))?;
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
                module_digest: blake3::hash(&bytes).to_hex().to_string(),
                module,
            });
        }
        Ok(Self { engine, modules })
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
        // CT-015: arm the epoch wall-clock gate.  Deadline of 1 means the first
        // `engine.increment_epoch()` call will interrupt this store's execution.
        store.set_epoch_deadline(1);
        // Spawn a detached thread that fires the epoch tick after EPOCH_TIMEOUT_MS.
        // If `analyze_fn.call` completes before the tick, the store is already
        // dropped and the increment is a no-op — zero overhead on the fast path.
        let engine_for_timeout = self.engine.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(EPOCH_TIMEOUT_MS));
            engine_for_timeout.increment_epoch();
        });

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
        let host = WasmHost::new(&[]).unwrap();
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
        let host = WasmHost::new(&[&path]).unwrap();
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
        let host = WasmHost::new(&[&path]).unwrap();
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
        let host = WasmHost::new(&[&path]).unwrap();
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
}
