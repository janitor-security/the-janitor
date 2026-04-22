//! Canonical Tree-sitter-to-IFDS fact adapter primitives.

use tree_sitter::Node;

/// Canonical IFDS fact kind emitted by language adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanonicalFactKind {
    /// Function, method, initializer, class, object, lambda, or handler entry.
    Entry,
    /// Parameter or local source binding.
    Parameter,
    /// Assignment propagation edge.
    Assignment,
    /// General call or expression propagation edge.
    Call,
    /// Receiver-side propagation edge.
    Receiver,
    /// Argument-side propagation edge.
    Argument,
    /// Return propagation edge.
    Return,
    /// Throw propagation edge.
    Throw,
    /// Field read propagation edge.
    FieldRead,
    /// Field write propagation edge.
    FieldWrite,
    /// Index read propagation edge.
    IndexRead,
    /// Index write propagation edge.
    IndexWrite,
    /// Lambda capture propagation edge.
    LambdaCapture,
    /// Conditional guard lattice transition.
    ControlGuard,
    /// Known sanitizer call.
    SanitizerCall,
    /// Security sink call.
    SinkCall,
}

/// Canonical fact emitted for one Tree-sitter node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFact {
    /// Canonical IFDS fact kind.
    pub kind: CanonicalFactKind,
    /// Original Tree-sitter node kind.
    pub node_kind: &'static str,
    /// Node start byte in the source buffer.
    pub start_byte: usize,
    /// Node end byte in the source buffer.
    pub end_byte: usize,
    /// Best-effort callee, sink, sanitizer, or transition label.
    pub symbol: Option<String>,
}

/// Exact P2-1 Tree-sitter node map for one grammar.
#[derive(Debug, Clone, Copy)]
pub struct NodeMap {
    /// Entry node kinds.
    pub entry_nodes: &'static [&'static str],
    /// Source and parameter node kinds.
    pub parameter_nodes: &'static [&'static str],
    /// Propagation node kinds.
    pub propagation_nodes: &'static [&'static str],
    /// Sink-bearing node kinds.
    pub sink_nodes: &'static [&'static str],
}

/// Collect canonical IFDS facts by walking `root` once.
pub fn collect_canonical_facts(
    root: Node<'_>,
    source: &[u8],
    map: NodeMap,
    sink_targets: &[&str],
) -> Vec<CanonicalFact> {
    let mut facts = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let text = node.utf8_text(source).unwrap_or("");
        if map.entry_nodes.contains(&kind) {
            facts.push(fact(CanonicalFactKind::Entry, node, None));
        }
        if map.parameter_nodes.contains(&kind) {
            facts.push(fact(CanonicalFactKind::Parameter, node, None));
        }
        if map.sink_nodes.contains(&kind) {
            if let Some(target) = matching_target(text, sink_targets) {
                facts.push(fact(CanonicalFactKind::SinkCall, node, Some(target)));
            } else if let Some(target) = matching_target(text, SANITIZER_TARGETS) {
                facts.push(fact(CanonicalFactKind::SanitizerCall, node, Some(target)));
            }
        }
        if map.propagation_nodes.contains(&kind) {
            facts.push(fact(propagation_kind(kind, text), node, None));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    facts.sort_by_key(|f| (f.start_byte, f.end_byte, fact_rank(f.kind)));
    facts
}

const SANITIZER_TARGETS: &[&str] = &[
    "escape_html",
    "escapeHtml",
    "html_escape",
    "htmlspecialchars",
    "htmlentities",
    "encodeURIComponent",
    "encodeURI",
    "urlencode",
    "rawurlencode",
    "quote_plus",
    "url_encode",
];

fn fact(kind: CanonicalFactKind, node: Node<'_>, symbol: Option<&str>) -> CanonicalFact {
    CanonicalFact {
        kind,
        node_kind: node.kind(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        symbol: symbol.map(str::to_string),
    }
}

fn matching_target<'a>(text: &str, targets: &'a [&str]) -> Option<&'a str> {
    targets.iter().copied().find(|target| text.contains(target))
}

fn propagation_kind(kind: &str, text: &str) -> CanonicalFactKind {
    if kind.contains("assignment") || kind == "assignment" {
        CanonicalFactKind::Assignment
    } else if kind.contains("argument") || kind == "value_arguments" {
        CanonicalFactKind::Argument
    } else if kind.contains("navigation") || kind.contains("field") {
        CanonicalFactKind::Receiver
    } else if kind.contains("index") {
        CanonicalFactKind::IndexRead
    } else if kind.contains("lambda") || kind.contains("capture") {
        CanonicalFactKind::LambdaCapture
    } else if kind.contains("if_")
        || kind.contains("guard")
        || kind.contains("when")
        || kind.contains("match")
        || text.contains("?.")
        || text.contains("!!")
    {
        CanonicalFactKind::ControlGuard
    } else {
        CanonicalFactKind::Call
    }
}

fn fact_rank(kind: CanonicalFactKind) -> u8 {
    match kind {
        CanonicalFactKind::Entry => 0,
        CanonicalFactKind::Parameter => 1,
        CanonicalFactKind::Assignment => 2,
        CanonicalFactKind::Call => 3,
        CanonicalFactKind::Receiver => 4,
        CanonicalFactKind::Argument => 5,
        CanonicalFactKind::Return => 6,
        CanonicalFactKind::Throw => 7,
        CanonicalFactKind::FieldRead => 8,
        CanonicalFactKind::FieldWrite => 9,
        CanonicalFactKind::IndexRead => 10,
        CanonicalFactKind::IndexWrite => 11,
        CanonicalFactKind::LambdaCapture => 12,
        CanonicalFactKind::ControlGuard => 13,
        CanonicalFactKind::SanitizerCall => 14,
        CanonicalFactKind::SinkCall => 15,
    }
}
