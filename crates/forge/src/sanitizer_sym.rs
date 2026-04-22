//! SMT transfer registry for sanitizer effects.

use std::collections::BTreeMap;

use common::taint::TaintKind;

use crate::sanitizer::SanitizerRegistry;

/// Symbolic vulnerability family label controlled by sanitizer transfer functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolicTaint {
    /// Server-side request forgery taint.
    Ssrf,
    /// Cross-site scripting taint.
    Xss,
    /// Generic user-input taint.
    UserInput,
    /// Unknown taint.
    Unknown,
}

/// Symbolic value state before or after sanitizer transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicValue {
    /// SMT symbol naming the value.
    pub symbol: String,
    /// Active symbolic taint labels.
    pub taints: Vec<SymbolicTaint>,
}

impl SymbolicValue {
    /// Construct a symbolic value with deterministic taint ordering.
    pub fn new(symbol: impl Into<String>, mut taints: Vec<SymbolicTaint>) -> Self {
        taints.sort();
        taints.dedup();
        Self {
            symbol: symbol.into(),
            taints,
        }
    }
}

/// SMT-level transformation emitted by a sanitizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicTransferFunction {
    /// Sanitizer function name.
    pub name: &'static str,
    /// SMT sort of the output value.
    pub output_sort: &'static str,
    /// SMT-LIB assertion over `input` and `output`.
    pub smt_assertion: &'static str,
    /// Registry-level taint kinds killed by the sanitizer.
    pub kills: Vec<TaintKind>,
    /// Symbolic vulnerability labels killed by the sanitizer.
    pub kills_symbolic: Vec<SymbolicTaint>,
}

impl SymbolicTransferFunction {
    /// Apply the symbolic taint-kill effect to `input`, naming the result `output_symbol`.
    pub fn apply(&self, input: &SymbolicValue, output_symbol: impl Into<String>) -> SymbolicValue {
        let mut taints = input.taints.clone();
        taints.retain(|taint| !self.kills_symbolic.contains(taint));
        SymbolicValue::new(output_symbol, taints)
    }
}

/// Deterministic registry of sanitizer SMT transfer functions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolicTransferRegistry {
    transfers: BTreeMap<&'static str, SymbolicTransferFunction>,
}

impl SymbolicTransferRegistry {
    /// Build transfer functions from the existing sanitizer registry.
    pub fn from_sanitizers(registry: &SanitizerRegistry) -> Self {
        let mut transfers = BTreeMap::new();
        for transfer in [urlencode_transfer(registry), html_escape_transfer(registry)]
            .into_iter()
            .flatten()
        {
            transfers.insert(transfer.name, transfer);
        }
        Self { transfers }
    }

    /// Build transfer functions from `SanitizerRegistry::with_defaults()`.
    pub fn with_defaults() -> Self {
        Self::from_sanitizers(&SanitizerRegistry::with_defaults())
    }

    /// Return the transfer function for `name`, if registered.
    pub fn get(&self, name: &str) -> Option<&SymbolicTransferFunction> {
        self.transfers.get(name)
    }

    /// Return the number of registered symbolic transfers.
    pub fn len(&self) -> usize {
        self.transfers.len()
    }

    /// Return `true` when no symbolic transfers are registered.
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }
}

fn urlencode_transfer(registry: &SanitizerRegistry) -> Option<SymbolicTransferFunction> {
    let spec = registry.spec_for("urlencode")?;
    Some(SymbolicTransferFunction {
        name: "urlencode",
        output_sort: spec.predicate.map_or("String", |p| p.output_sort),
        smt_assertion: r#"(= output (str.replace_all (str.replace_all input ":" "%3A") "/" "%2F"))"#,
        kills: spec.kills.clone(),
        kills_symbolic: vec![SymbolicTaint::Ssrf],
    })
}

fn html_escape_transfer(registry: &SanitizerRegistry) -> Option<SymbolicTransferFunction> {
    let spec = registry.spec_for("html_escape")?;
    Some(SymbolicTransferFunction {
        name: "html_escape",
        output_sort: spec.predicate.map_or("String", |p| p.output_sort),
        smt_assertion: r#"(not (str.contains output "<"))"#,
        kills: spec.kills.clone(),
        kills_symbolic: vec![SymbolicTaint::Xss],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_exposes_urlencode_and_html_escape_transfers() {
        let registry = SymbolicTransferRegistry::with_defaults();
        assert!(registry.get("urlencode").is_some());
        assert!(registry.get("html_escape").is_some());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn urlencode_transfer_kills_ssrf_taint_only() {
        let registry = SymbolicTransferRegistry::with_defaults();
        let transfer = registry.get("urlencode").expect("urlencode transfer");
        let input = SymbolicValue::new("input", vec![SymbolicTaint::Ssrf, SymbolicTaint::Xss]);
        let output = transfer.apply(&input, "output");
        assert_eq!(output.taints, vec![SymbolicTaint::Xss]);
        assert!(transfer.smt_assertion.contains("str.replace_all"));
    }

    #[test]
    fn html_escape_transfer_kills_xss_taint_only() {
        let registry = SymbolicTransferRegistry::with_defaults();
        let transfer = registry.get("html_escape").expect("html escape transfer");
        let input = SymbolicValue::new("input", vec![SymbolicTaint::Ssrf, SymbolicTaint::Xss]);
        let output = transfer.apply(&input, "output");
        assert_eq!(output.taints, vec![SymbolicTaint::Ssrf]);
        assert!(transfer.smt_assertion.contains("str.contains"));
    }
}
