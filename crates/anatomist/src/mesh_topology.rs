//! # P4-8 Phase A — Mesh Topology Discovery
//!
//! Scans a repository tree for `docker-compose.yml` files and builds a
//! lightweight `MeshTopologyGraph` of service nodes, images, and exposed ports.
//! Phase B (K8s / Istio manifests) and Phase C (cross-repo IFDS lift) are
//! tracked in `.INNOVATION_LOG.md` under P4-8.

use anyhow::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

/// A single service discovered in a mesh manifest.
#[derive(Debug, Clone)]
pub struct MeshNode {
    pub service_name: String,
    pub repo_path: String,
    pub image: Option<String>,
    pub ports: Vec<String>,
}

/// A directed dependency edge between two mesh services.
#[derive(Debug, Clone)]
pub struct MeshContract {
    pub producer: NodeIndex,
    pub consumer: NodeIndex,
    /// Raw `depends_on` service name extracted from the manifest.
    pub depends_on_name: String,
}

/// Weighted graph of mesh nodes; edges carry `MeshContract` metadata.
pub type MeshTopologyGraph = DiGraph<MeshNode, MeshContract>;

// ─── serde_yaml deserialization targets ─────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct ComposeFile {
    #[serde(default)]
    services: HashMap<String, ComposeService>,
}

#[derive(Debug, Deserialize, Default)]
struct ComposeService {
    image: Option<String>,
    #[serde(default)]
    ports: Vec<serde_yaml::Value>,
    #[serde(default)]
    depends_on: DependsOn,
    build: Option<serde_yaml::Value>,
}

/// `depends_on` can be a list of strings or a map of `{service: {condition: …}}`.
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum DependsOn {
    #[default]
    None,
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
}

impl DependsOn {
    fn names(&self) -> Vec<String> {
        match self {
            DependsOn::None => vec![],
            DependsOn::List(v) => v.clone(),
            DependsOn::Map(m) => m.keys().cloned().collect(),
        }
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Scan `repo_root` recursively for `docker-compose.yml` / `docker-compose.yaml`
/// files and assemble a [`MeshTopologyGraph`] from all discovered services.
///
/// Services from multiple compose files in the same repo are merged into a
/// single graph; `depends_on` edges become directed arcs.
pub fn discover_mesh_topology(repo_root: &Path) -> Result<MeshTopologyGraph> {
    let mut graph: MeshTopologyGraph = DiGraph::new();
    // service_name → NodeIndex (dedup across compose files)
    let mut name_to_idx: HashMap<String, NodeIndex> = HashMap::new();
    // Deferred edges: (producer_name, consumer_name, depends_on_name)
    let mut deferred_edges: Vec<(String, String, String)> = Vec::new();

    for entry in WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let file_name = entry.file_name().to_string_lossy();
        if file_name != "docker-compose.yml" && file_name != "docker-compose.yaml" {
            continue;
        }

        let raw = std::fs::read_to_string(entry.path())?;
        let compose: ComposeFile = serde_yaml::from_str(&raw).unwrap_or_default();
        let repo_path = repo_root.to_string_lossy().to_string();

        for (svc_name, svc) in &compose.services {
            let image = svc.image.clone().or_else(|| {
                // If no explicit image, derive from build context path.
                svc.build
                    .as_ref()
                    .and_then(|b| b.as_str().map(|s| format!("build:{s}")))
            });
            let ports = svc
                .ports
                .iter()
                .map(|p| match p {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>();

            let idx = *name_to_idx.entry(svc_name.clone()).or_insert_with(|| {
                graph.add_node(MeshNode {
                    service_name: svc_name.clone(),
                    repo_path: repo_path.clone(),
                    image,
                    ports,
                })
            });
            // Collect depends_on for deferred edge resolution.
            for dep in svc.depends_on.names() {
                deferred_edges.push((dep.clone(), svc_name.clone(), dep));
            }
            let _ = idx;
        }
    }

    // Resolve deferred edges (both sides must be present in the graph).
    for (producer_name, consumer_name, dep_name) in deferred_edges {
        if let (Some(&prod_idx), Some(&cons_idx)) = (
            name_to_idx.get(&producer_name),
            name_to_idx.get(&consumer_name),
        ) {
            graph.add_edge(
                prod_idx,
                cons_idx,
                MeshContract {
                    producer: prod_idx,
                    consumer: cons_idx,
                    depends_on_name: dep_name,
                },
            );
        }
    }

    Ok(graph)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_compose(dir: &TempDir, content: &str) {
        let path = dir.path().join("docker-compose.yml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn test_single_service_no_deps() {
        let dir = TempDir::new().unwrap();
        write_compose(
            &dir,
            "services:\n  web:\n    image: nginx:latest\n    ports:\n      - \"80:80\"\n",
        );
        let graph = discover_mesh_topology(dir.path()).unwrap();
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
        let node = graph.node_indices().next().unwrap();
        assert_eq!(graph[node].service_name, "web");
        assert_eq!(graph[node].image.as_deref(), Some("nginx:latest"));
        assert_eq!(graph[node].ports, vec!["80:80"]);
    }

    #[test]
    fn test_two_services_with_dependency_edge() {
        let dir = TempDir::new().unwrap();
        write_compose(
            &dir,
            "services:\n  db:\n    image: postgres:15\n  api:\n    image: api:latest\n    depends_on:\n      - db\n",
        );
        let graph = discover_mesh_topology(dir.path()).unwrap();
        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_empty_compose_returns_empty_graph() {
        let dir = TempDir::new().unwrap();
        write_compose(&dir, "services: {}\n");
        let graph = discover_mesh_topology(dir.path()).unwrap();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_build_context_derives_image_tag() {
        let dir = TempDir::new().unwrap();
        write_compose(
            &dir,
            "services:\n  worker:\n    build: ./worker\n    ports:\n      - \"8080:8080\"\n",
        );
        let graph = discover_mesh_topology(dir.path()).unwrap();
        assert_eq!(graph.node_count(), 1);
        let node = graph.node_indices().next().unwrap();
        assert!(graph[node].image.as_deref().unwrap().starts_with("build:"));
    }

    #[test]
    fn test_no_compose_file_returns_empty_graph() {
        let dir = TempDir::new().unwrap();
        let graph = discover_mesh_topology(dir.path()).unwrap();
        assert_eq!(graph.node_count(), 0);
    }
}
