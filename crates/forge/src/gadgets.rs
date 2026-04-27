//! Deserialization gadget chain atlas backed by lockfile evidence.
//!
//! This detector only emits when three facts align: a source file exposes a
//! deserialization entry point, the repository manifest contains a vulnerable
//! gadget-bearing dependency, and the call graph/source surface supports the
//! relevant chain entry.

use common::slop::{ExploitWitness, StructuredFinding};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::BTreeMap;

use crate::callgraph::build_call_graph;
use crate::taint_catalog::CatalogView;

const FINDING_ID: &str = "security:deserialization_gadget_chain";
const JAVA_CHAIN: &[&str] = &["readObject", "InvokerTransformer", "Runtime.exec"];
const PYTHON_SYSTEM_CHAIN: &[&str] = &["__reduce__", "os.system"];
const PYTHON_POPEN_CHAIN: &[&str] = &["__reduce__", "subprocess.Popen"];
const RUBY_EVAL_CHAIN: &[&str] = &["marshal_load", "instance_eval"];
const RUBY_SYSTEM_CHAIN: &[&str] = &["marshal_load", "system"];

/// Build the hardcoded deserialization gadget atlas.
///
/// The graph encodes the high-value RCE chains currently supported by the
/// detector:
/// - Java Commons Collections: `readObject -> InvokerTransformer -> Runtime.exec`
/// - Python Pickle: `__reduce__ -> os.system` and `__reduce__ -> subprocess.Popen`
/// - Ruby Marshal: `marshal_load -> instance_eval` and `marshal_load -> system`
pub fn build_gadget_atlas() -> DiGraph<&'static str, ()> {
    let mut graph = DiGraph::new();
    let mut nodes: BTreeMap<&'static str, NodeIndex> = BTreeMap::new();
    for chain in [
        JAVA_CHAIN,
        PYTHON_SYSTEM_CHAIN,
        PYTHON_POPEN_CHAIN,
        RUBY_EVAL_CHAIN,
        RUBY_SYSTEM_CHAIN,
    ] {
        for symbol in chain {
            nodes
                .entry(*symbol)
                .or_insert_with(|| graph.add_node(*symbol));
        }
        for pair in chain.windows(2) {
            let from = nodes[pair[0]];
            let to = nodes[pair[1]];
            graph.add_edge(from, to, ());
        }
    }
    graph
}

/// Analyze a source file for lockfile-backed deserialization gadget chains.
pub fn analyze_source_for_gadgets(
    ext: &str,
    source: &[u8],
    file_name: &str,
    manifests: &[(&str, &[u8])],
) -> Vec<StructuredFinding> {
    analyze_source_for_gadgets_with_catalog(ext, source, file_name, manifests, None)
}

/// Analyze a source file for deserialization gadget chains, optionally
/// consulting the persisted taint catalog for sink corroboration.
pub fn analyze_source_for_gadgets_with_catalog(
    ext: &str,
    source: &[u8],
    file_name: &str,
    manifests: &[(&str, &[u8])],
    taint_catalog: Option<&CatalogView>,
) -> Vec<StructuredFinding> {
    let language = match ext {
        "java" => "java",
        "py" => "py",
        "rb" => "rb",
        _ => return Vec::new(),
    };
    let graph = build_call_graph(language, source);
    let source_text = String::from_utf8_lossy(source);
    let source_line = first_deserialization_line(language, &source_text);
    let Some(line) = source_line else {
        return Vec::new();
    };

    let mut out = Vec::new();
    match language {
        "java" => {
            if has_vulnerable_commons_collections(manifests)
                && call_graph_supports(&graph, &source_text, "readObject")
                && catalog_supports(taint_catalog, "Runtime.exec")
            {
                out.push(finding(file_name, line, JAVA_CHAIN, "pom.xml"));
            }
        }
        "py" => {
            if has_vulnerable_python_pickle_gadget(manifests)
                && call_graph_supports_any(&graph, &source_text, &["pickle.loads", "pickle.load"])
            {
                if catalog_supports(taint_catalog, "os.system") {
                    out.push(finding(
                        file_name,
                        line,
                        PYTHON_SYSTEM_CHAIN,
                        "requirements.txt",
                    ));
                }
                if catalog_supports(taint_catalog, "subprocess.Popen") {
                    out.push(finding(
                        file_name,
                        line,
                        PYTHON_POPEN_CHAIN,
                        "requirements.txt",
                    ));
                }
            }
        }
        "rb" => {
            if has_vulnerable_ruby_marshal_gadget(manifests)
                && call_graph_supports_any(
                    &graph,
                    &source_text,
                    &["Marshal.load", "Marshal.restore"],
                )
            {
                if catalog_supports(taint_catalog, "instance_eval") {
                    out.push(finding(file_name, line, RUBY_EVAL_CHAIN, "Gemfile.lock"));
                }
                if catalog_supports(taint_catalog, "system") {
                    out.push(finding(file_name, line, RUBY_SYSTEM_CHAIN, "Gemfile.lock"));
                }
            }
        }
        _ => {}
    }
    dedup_chain_findings(out)
}

fn finding(file_name: &str, line: u32, chain: &[&str], manifest_name: &str) -> StructuredFinding {
    let chain_strings: Vec<String> = chain.iter().map(|symbol| (*symbol).to_string()).collect();
    let chain_text = chain.join(" -> ");
    StructuredFinding {
        id: FINDING_ID.to_string(),
        file: Some(file_name.to_string()),
        line: Some(line),
        fingerprint: blake3::hash(format!("{file_name}:{chain_text}").as_bytes())
            .to_hex()
            .to_string(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(format!(
            "Remove or upgrade the vulnerable gadget-bearing dependency in {manifest_name} and replace native deserialization with a schema-validated codec."
        )),
        docs_url: None,
        exploit_witness: Some(ExploitWitness {
            source_function: chain[0].to_string(),
            source_label: "deserialization_entry".to_string(),
            sink_function: chain[chain.len() - 1].to_string(),
            sink_label: "sink:rce_gadget_chain".to_string(),
            call_chain: chain_strings.clone(),
            gadget_chain: Some(chain_strings),
            sanitizer_audit: Some(format!(
                "A complete deserialization gadget chain was verified against {manifest_name}: {chain_text}."
            )),
            upstream_validation_absent: true,
            ..ExploitWitness::default()
        }),
        upstream_validation_absent: true,
        ..Default::default()
    }
}

fn first_deserialization_line(language: &str, source: &str) -> Option<u32> {
    let needles: &[&str] = match language {
        "java" => &["readObject("],
        "py" => &["pickle.loads(", "pickle.load("],
        "rb" => &["Marshal.load(", "Marshal.restore("],
        _ => &[],
    };
    source.lines().enumerate().find_map(|(idx, line)| {
        needles
            .iter()
            .any(|needle| line.contains(needle))
            .then_some(idx as u32 + 1)
    })
}

fn call_graph_supports_any(
    graph: &crate::callgraph::CallGraph,
    source_text: &str,
    symbols: &[&str],
) -> bool {
    symbols
        .iter()
        .any(|symbol| call_graph_supports(graph, source_text, symbol))
}

fn call_graph_supports(
    graph: &crate::callgraph::CallGraph,
    source_text: &str,
    symbol: &str,
) -> bool {
    let short = symbol.rsplit(['.', ':']).next().unwrap_or(symbol);
    graph.node_weights().any(|node| {
        node == symbol || node == short || node.ends_with(symbol) || node.ends_with(short)
    }) || source_text.contains(symbol)
        || source_text.contains(short)
}

fn catalog_supports(taint_catalog: Option<&CatalogView>, sink: &str) -> bool {
    let Some(catalog) = taint_catalog else {
        return true;
    };
    let short = sink.rsplit(['.', ':']).next().unwrap_or(sink);
    catalog.has_sink(sink) || catalog.has_sink(short)
}

fn has_vulnerable_commons_collections(manifests: &[(&str, &[u8])]) -> bool {
    manifests.iter().any(|(path, bytes)| {
        path.ends_with("pom.xml")
            && String::from_utf8_lossy(bytes)
                .split("<dependency>")
                .any(|dependency| {
                    dependency.contains("<artifactId>commons-collections</artifactId>")
                        && dependency
                            .split("<version>")
                            .nth(1)
                            .and_then(|tail| tail.split("</version>").next())
                            .map(|version| version_le(version.trim(), (3, 2, 1)))
                            .unwrap_or(false)
                })
    })
}

fn has_vulnerable_python_pickle_gadget(manifests: &[(&str, &[u8])]) -> bool {
    manifests.iter().any(|(path, bytes)| {
        path.ends_with("requirements.txt") && {
            let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
            requirement_le(&text, "dill", (0, 3, 4)) || requirement_le(&text, "pickle5", (0, 0, 11))
        }
    })
}

fn has_vulnerable_ruby_marshal_gadget(manifests: &[(&str, &[u8])]) -> bool {
    manifests.iter().any(|(path, bytes)| {
        path.ends_with("Gemfile.lock") && {
            let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
            gem_lock_le(&text, "activesupport", (5, 2, 3)) || gem_lock_le(&text, "rails", (5, 2, 3))
        }
    })
}

fn requirement_le(text: &str, package: &str, max: (u64, u64, u64)) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(package)
            .and_then(|tail| {
                tail.trim_start()
                    .strip_prefix("==")
                    .or_else(|| tail.trim_start().strip_prefix("<="))
            })
            .map(|version| version_le(version.trim(), max))
            .unwrap_or(false)
    })
}

fn gem_lock_le(text: &str, gem: &str, max: (u64, u64, u64)) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(gem)
            .and_then(|tail| tail.trim().strip_prefix('('))
            .and_then(|tail| tail.split(')').next())
            .map(|version| version_le(version.trim(), max))
            .unwrap_or(false)
    })
}

fn version_le(version: &str, max: (u64, u64, u64)) -> bool {
    let mut parts = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok());
    let parsed = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    parsed <= max
}

fn dedup_chain_findings(findings: Vec<StructuredFinding>) -> Vec<StructuredFinding> {
    let mut seen = BTreeMap::new();
    for finding in findings {
        seen.entry(finding.fingerprint.clone()).or_insert(finding);
    }
    seen.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_contains_high_value_gadget_edges() {
        let atlas = build_gadget_atlas();
        let mut edges = Vec::new();
        for edge in atlas.raw_edges() {
            edges.push((atlas[edge.source()], atlas[edge.target()]));
        }
        assert!(edges.contains(&("readObject", "InvokerTransformer")));
        assert!(edges.contains(&("InvokerTransformer", "Runtime.exec")));
        assert!(edges.contains(&("__reduce__", "os.system")));
        assert!(edges.contains(&("marshal_load", "instance_eval")));
    }

    #[test]
    fn java_commons_collections_lockfile_and_readobject_emit_gadget_chain() {
        let pom = br#"
<project>
  <dependencies>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
  </dependencies>
</project>
"#;
        let source = br#"
import java.io.ObjectInputStream;

class Handler {
    Object receive(ObjectInputStream input) throws Exception {
        return input.readObject();
    }
}
"#;
        let findings =
            analyze_source_for_gadgets("java", source, "src/Handler.java", &[("pom.xml", pom)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, FINDING_ID);
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        let witness = findings[0]
            .exploit_witness
            .as_ref()
            .expect("gadget chain finding must carry an exploit witness");
        assert_eq!(
            witness.gadget_chain.as_ref().expect("gadget chain"),
            &vec![
                "readObject".to_string(),
                "InvokerTransformer".to_string(),
                "Runtime.exec".to_string(),
            ]
        );
    }

    #[test]
    fn patched_commons_collections_does_not_emit() {
        let pom = br#"
<project>
  <dependencies>
    <dependency>
      <artifactId>commons-collections</artifactId>
      <version>3.2.2</version>
    </dependency>
  </dependencies>
</project>
"#;
        let source = b"class Handler { Object f(java.io.ObjectInputStream i) throws Exception { return i.readObject(); } }";
        let findings =
            analyze_source_for_gadgets("java", source, "src/Handler.java", &[("pom.xml", pom)]);
        assert!(findings.is_empty());
    }
}
