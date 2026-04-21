//! Service-boundary schema graph extraction.
//!
//! This module converts OpenAPI v3 and protobuf service declarations into a
//! deterministic trust-boundary graph. Phase A records ingress nodes only; later
//! phases can attach handlers, outbound clients, queues, and datastore sinks.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use openapiv3::OpenAPI;
use petgraph::graph::{Graph, NodeIndex};
use protobuf_parse::Parser;

/// Protocol family for an ingress schema declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiProtocol {
    /// REST/OpenAPI endpoint.
    Rest,
    /// gRPC/protobuf service method.
    Grpc,
}

/// A normalized ingress endpoint discovered from a schema file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApiIngress {
    /// Stable endpoint identifier such as `GET /api/v1/users` or
    /// `UserService.CreateUser`.
    pub id: String,
    /// Protocol family.
    pub protocol: ApiProtocol,
    /// HTTP method for REST endpoints.
    pub method: Option<String>,
    /// REST path or gRPC service method name.
    pub route: String,
    /// Optional protobuf package or OpenAPI operation id.
    pub namespace: Option<String>,
    /// Source schema path relative to the scanned root when possible.
    pub source_path: String,
}

/// Node payload for the trust-boundary graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustBoundaryNode {
    /// External origin for all public ingress edges.
    Boundary { name: String },
    /// API ingress parsed from a schema artifact.
    Ingress(ApiIngress),
}

/// Directed edge payload between trust-boundary nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBoundaryEdge {
    /// Machine-readable edge kind.
    pub kind: String,
}

/// Deterministic property graph for cross-service schema ingress.
#[derive(Debug, Clone)]
pub struct TrustBoundaryGraph {
    graph: Graph<TrustBoundaryNode, TrustBoundaryEdge>,
    internet: NodeIndex,
    ingress: BTreeMap<String, NodeIndex>,
}

impl Default for TrustBoundaryGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustBoundaryGraph {
    /// Create an empty graph seeded with the external internet boundary.
    pub fn new() -> Self {
        let mut graph = Graph::new();
        let internet = graph.add_node(TrustBoundaryNode::Boundary {
            name: "internet".to_owned(),
        });

        Self {
            graph,
            internet,
            ingress: BTreeMap::new(),
        }
    }

    /// Parse all supported schema files under `root`.
    pub fn from_repository(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let mut graph = Self::new();
        let files = collect_schema_files(root)?;

        for path in files {
            graph.ingest_file(root, &path)?;
        }

        Ok(graph)
    }

    /// Parse one supported schema file into the graph.
    pub fn ingest_file(&mut self, root: &Path, path: &Path) -> Result<()> {
        match normalized_extension(path).as_deref() {
            Some("proto") => self.ingest_proto(root, path),
            Some("json") => self.ingest_openapi(root, path, SchemaEncoding::Json),
            Some("yaml") | Some("yml") => self.ingest_openapi(root, path, SchemaEncoding::Yaml),
            _ => Ok(()),
        }
    }

    /// Return ingress nodes sorted by stable endpoint id.
    pub fn ingress_nodes(&self) -> Vec<ApiIngress> {
        self.ingress
            .values()
            .filter_map(|idx| match self.graph.node_weight(*idx) {
                Some(TrustBoundaryNode::Ingress(ingress)) => Some(ingress.clone()),
                _ => None,
            })
            .collect()
    }

    /// Return true when an ingress id is present.
    pub fn contains_ingress(&self, id: &str) -> bool {
        self.ingress.contains_key(id)
    }

    /// Number of registered ingress nodes.
    pub fn ingress_count(&self) -> usize {
        self.ingress.len()
    }

    /// Borrow the backing `petgraph` graph.
    pub fn graph(&self) -> &Graph<TrustBoundaryNode, TrustBoundaryEdge> {
        &self.graph
    }

    fn ingest_openapi(&mut self, root: &Path, path: &Path, encoding: SchemaEncoding) -> Result<()> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read OpenAPI schema {}", path.display()))?;
        let api: OpenAPI = match encoding {
            SchemaEncoding::Json => serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse OpenAPI JSON {}", path.display()))?,
            SchemaEncoding::Yaml => serde_yaml::from_slice(&bytes)
                .with_context(|| format!("failed to parse OpenAPI YAML {}", path.display()))?,
        };

        let mut endpoints = api
            .operations()
            .map(|(route, method, operation)| {
                let method = method.to_ascii_uppercase();
                ApiIngress {
                    id: format!("{method} {route}"),
                    protocol: ApiProtocol::Rest,
                    method: Some(method),
                    route: route.to_owned(),
                    namespace: operation.operation_id.clone(),
                    source_path: relative_path(root, path),
                }
            })
            .collect::<Vec<_>>();
        endpoints.sort();

        for endpoint in endpoints {
            self.add_ingress(endpoint);
        }

        Ok(())
    }

    fn ingest_proto(&mut self, root: &Path, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or(root);
        let descriptor_set = Parser::new()
            .pure()
            .include(root)
            .include(parent)
            .input(path)
            .file_descriptor_set()
            .with_context(|| format!("failed to parse protobuf schema {}", path.display()))?;

        let mut endpoints = Vec::new();
        for file in descriptor_set.file {
            let package = empty_to_none(file.package().to_owned());
            for service in file.service {
                let service_name = service.name().to_owned();
                for method in service.method {
                    let method_name = method.name().to_owned();
                    let route = format!("{service_name}.{method_name}");
                    endpoints.push(ApiIngress {
                        id: route.clone(),
                        protocol: ApiProtocol::Grpc,
                        method: None,
                        route,
                        namespace: package.clone(),
                        source_path: relative_path(root, path),
                    });
                }
            }
        }
        endpoints.sort();

        for endpoint in endpoints {
            self.add_ingress(endpoint);
        }

        Ok(())
    }

    fn add_ingress(&mut self, ingress: ApiIngress) {
        if self.ingress.contains_key(&ingress.id) {
            return;
        }

        let id = ingress.id.clone();
        let node = self.graph.add_node(TrustBoundaryNode::Ingress(ingress));
        self.graph.add_edge(
            self.internet,
            node,
            TrustBoundaryEdge {
                kind: "public_ingress".to_owned(),
            },
        );
        self.ingress.insert(id, node);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaEncoding {
    Json,
    Yaml,
}

fn collect_schema_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_schema_files_inner(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_schema_files_inner(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", path.display()))?;

        if file_type.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            collect_schema_files_inner(&path, files)?;
        } else if file_type.is_file() && is_schema_file(&path) {
            files.push(path);
        }
    }

    Ok(())
}

fn is_schema_file(path: &Path) -> bool {
    matches!(
        normalized_extension(path).as_deref(),
        Some("json" | "proto" | "yaml" | "yml")
    )
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".janitor" | "node_modules" | "target"))
}

fn normalized_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn empty_to_none(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_rpc_methods_register_as_ingress_nodes() {
        let temp = tempfile::tempdir().expect("tempdir must be created");
        let proto_path = temp.path().join("users.proto");
        fs::write(
            &proto_path,
            r#"
syntax = "proto3";

package janitor.users;

message CreateUserRequest {
  string email = 1;
}

message User {
  string id = 1;
}

service UserService {
  rpc CreateUser (CreateUserRequest) returns (User);
  rpc GetUser (CreateUserRequest) returns (User);
}
"#,
        )
        .expect("proto fixture must be written");

        let graph = TrustBoundaryGraph::from_repository(temp.path()).expect("proto must parse");
        let ingress = graph.ingress_nodes();

        assert_eq!(graph.ingress_count(), 2);
        assert!(graph.contains_ingress("UserService.CreateUser"));
        assert!(graph.contains_ingress("UserService.GetUser"));
        assert_eq!(ingress[0].id, "UserService.CreateUser");
        assert_eq!(ingress[0].namespace.as_deref(), Some("janitor.users"));
        assert_eq!(ingress[0].protocol, ApiProtocol::Grpc);
    }

    #[test]
    fn openapi_yaml_paths_register_rest_ingress_nodes() {
        let temp = tempfile::tempdir().expect("tempdir must be created");
        let openapi_path = temp.path().join("openapi.yaml");
        fs::write(
            &openapi_path,
            r#"
openapi: 3.0.0
info:
  title: Users
  version: 1.0.0
paths:
  /api/v1/users:
    post:
      operationId: createUser
      responses:
        "200":
          description: ok
"#,
        )
        .expect("openapi fixture must be written");

        let graph = TrustBoundaryGraph::from_repository(temp.path()).expect("openapi must parse");

        assert!(graph.contains_ingress("POST /api/v1/users"));
        let ingress = graph.ingress_nodes();
        assert_eq!(ingress[0].route, "/api/v1/users");
        assert_eq!(ingress[0].method.as_deref(), Some("POST"));
        assert_eq!(ingress[0].namespace.as_deref(), Some("createUser"));
    }
}
