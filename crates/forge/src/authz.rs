//! Framework-aware API router and authorization surface extraction.
//!
//! Extracts deterministic HTTP ingress metadata from Spring Boot, Flask/FastAPI,
//! and Express controller definitions so exploit witnesses can bind to real
//! routes instead of abstract handler names.

use tree_sitter::{Node, Tree};

/// Public controller/router surface exposed by an application handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSurface {
    pub file: String,
    pub route_path: String,
    pub http_method: String,
    pub auth_requirement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointSurfaceMatch {
    pub surface: EndpointSurface,
    pub handler_name: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
}

/// Extract the public controller surface from a parsed source tree.
pub fn extract_controller_surface(tree: &Tree, lang: &str, source: &[u8]) -> Vec<EndpointSurface> {
    extract_controller_surface_with_file(tree, lang, source, String::new())
        .into_iter()
        .map(|entry| entry.surface)
        .collect()
}

pub(crate) fn extract_controller_surface_with_file(
    tree: &Tree,
    lang: &str,
    source: &[u8],
    file: String,
) -> Vec<EndpointSurfaceMatch> {
    match lang {
        "java" => extract_spring_surfaces(tree.root_node(), source, file),
        "py" => extract_python_surfaces(tree.root_node(), source, file),
        "js" | "jsx" | "ts" | "tsx" => extract_express_surfaces(tree.root_node(), source, file),
        _ => Vec::new(),
    }
}

pub(crate) fn match_surface_for_witness<'a>(
    surfaces: &'a [EndpointSurfaceMatch],
    source_function: &str,
    line: Option<u32>,
) -> Option<&'a EndpointSurfaceMatch> {
    let source_leaf = handler_leaf_name(source_function);
    surfaces.iter().find(|surface| {
        if let Some(handler_name) = surface.handler_name.as_deref() {
            if handler_leaf_name(handler_name) == source_leaf {
                return true;
            }
        }
        if let Some(line) = line {
            return surface.start_line <= line && line <= surface.end_line;
        }
        false
    })
}

fn extract_spring_surfaces(
    root: Node<'_>,
    source: &[u8],
    file: String,
) -> Vec<EndpointSurfaceMatch> {
    let mut classes = Vec::new();
    collect_nodes_of_kind(root, "class_declaration", &mut classes);

    let mut surfaces = Vec::new();
    for class_node in classes {
        let Some(body) = class_node.child_by_field_name("body") else {
            continue;
        };
        let header = slice(source, class_node.start_byte(), body.start_byte());
        let class_annotations = extract_java_annotations(header);
        let class_route = class_annotations.iter().find_map(|annotation| {
            parse_spring_mapping(annotation).map(|(_, route_path)| route_path)
        });
        let class_auth = class_annotations
            .iter()
            .find_map(|annotation| parse_auth_requirement(annotation));

        let mut methods = Vec::new();
        collect_nodes_of_kind(body, "method_declaration", &mut methods);
        for method_node in methods {
            let Some(method_body) = method_node.child_by_field_name("body") else {
                continue;
            };
            let method_header = slice(source, method_node.start_byte(), method_body.start_byte());
            let method_annotations = extract_java_annotations(method_header);
            let Some((http_method, method_path)) = method_annotations
                .iter()
                .find_map(|annotation| parse_spring_mapping(annotation))
            else {
                continue;
            };
            let auth_requirement = method_annotations
                .iter()
                .find_map(|annotation| parse_auth_requirement(annotation))
                .or_else(|| class_auth.clone());
            let handler_name = method_node
                .child_by_field_name("name")
                .and_then(|node| node.utf8_text(source).ok())
                .map(str::to_string);
            surfaces.push(EndpointSurfaceMatch {
                surface: EndpointSurface {
                    file: file.clone(),
                    route_path: join_route(class_route.as_deref(), Some(method_path.as_str())),
                    http_method,
                    auth_requirement,
                },
                handler_name,
                start_line: line_number_for_byte(source, method_node.start_byte()),
                end_line: line_number_for_byte(source, method_node.end_byte()),
            });
        }
    }

    surfaces
}

fn extract_python_surfaces(
    root: Node<'_>,
    source: &[u8],
    file: String,
) -> Vec<EndpointSurfaceMatch> {
    let mut decorated = Vec::new();
    collect_nodes_of_kind(root, "decorated_definition", &mut decorated);

    let mut surfaces = Vec::new();
    for decorated_node in decorated {
        let Some(function_node) = decorated_node
            .children(&mut decorated_node.walk())
            .find(|child| child.kind() == "function_definition")
        else {
            continue;
        };
        let header = slice(
            source,
            decorated_node.start_byte(),
            function_node.start_byte(),
        );
        let decorators = header
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('@'))
            .map(str::to_string)
            .collect::<Vec<_>>();

        let route = decorators
            .iter()
            .find_map(|decorator| parse_python_route(decorator));
        let Some((http_method, route_path)) = route else {
            continue;
        };
        let auth_requirement = decorators
            .iter()
            .filter(|decorator| parse_python_route(decorator).is_none())
            .find_map(|decorator| parse_auth_requirement(decorator));
        let handler_name = function_node
            .child_by_field_name("name")
            .and_then(|node| node.utf8_text(source).ok())
            .map(str::to_string);
        surfaces.push(EndpointSurfaceMatch {
            surface: EndpointSurface {
                file: file.clone(),
                route_path,
                http_method,
                auth_requirement,
            },
            handler_name,
            start_line: line_number_for_byte(source, function_node.start_byte()),
            end_line: line_number_for_byte(source, function_node.end_byte()),
        });
    }

    surfaces
}

fn extract_express_surfaces(
    root: Node<'_>,
    source: &[u8],
    file: String,
) -> Vec<EndpointSurfaceMatch> {
    let mut call_nodes = Vec::new();
    collect_nodes_of_kind(root, "call_expression", &mut call_nodes);

    let mut surfaces = Vec::new();
    for call_node in call_nodes {
        let Some(function_node) = call_node.child_by_field_name("function") else {
            continue;
        };
        let Some(arguments_node) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        let Ok(callee_text) = function_node.utf8_text(source) else {
            continue;
        };
        let Some(http_method) = parse_express_method(callee_text) else {
            continue;
        };
        let args = arguments_node
            .named_children(&mut arguments_node.walk())
            .collect::<Vec<_>>();
        let Some(path_arg) = args.first() else {
            continue;
        };
        let Ok(path_text) = path_arg.utf8_text(source) else {
            continue;
        };
        let Some(route_path) = parse_string_literal(path_text) else {
            continue;
        };

        let auth_requirement = if args.len() > 2 {
            args.get(1)
                .and_then(|node| node.utf8_text(source).ok())
                .map(str::trim)
                .map(str::to_string)
        } else {
            None
        };
        let handler_name = args
            .last()
            .and_then(|node| node.utf8_text(source).ok())
            .map(handler_leaf_name)
            .filter(|name| !name.is_empty());

        surfaces.push(EndpointSurfaceMatch {
            surface: EndpointSurface {
                file: file.clone(),
                route_path,
                http_method,
                auth_requirement,
            },
            handler_name,
            start_line: line_number_for_byte(source, call_node.start_byte()),
            end_line: line_number_for_byte(source, call_node.end_byte()),
        });
    }

    surfaces
}

fn collect_nodes_of_kind<'a>(node: Node<'a>, kind: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == kind {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_nodes_of_kind(child, kind, out);
    }
}

fn slice(source: &[u8], start: usize, end: usize) -> &str {
    std::str::from_utf8(&source[start.min(source.len())..end.min(source.len())]).unwrap_or("")
}

fn extract_java_annotations(header: &str) -> Vec<String> {
    let bytes = header.as_bytes();
    let mut annotations = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'@' {
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'(' {
            let mut depth = 0u32;
            let mut quote: Option<u8> = None;
            while index < bytes.len() {
                let byte = bytes[index];
                if let Some(active) = quote {
                    if byte == active && bytes.get(index.saturating_sub(1)) != Some(&b'\\') {
                        quote = None;
                    }
                } else if byte == b'\'' || byte == b'"' {
                    quote = Some(byte);
                } else if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        index += 1;
                        break;
                    }
                }
                index += 1;
            }
        }
        annotations.push(header[start..index].trim().to_string());
    }
    annotations
}

fn parse_spring_mapping(annotation: &str) -> Option<(String, String)> {
    let name = annotation_name(annotation);
    let path = extract_named_or_first_string(annotation, &["path", "value"])?;
    match name.as_str() {
        "GetMapping" => Some(("GET".to_string(), path)),
        "PostMapping" => Some(("POST".to_string(), path)),
        "PutMapping" => Some(("PUT".to_string(), path)),
        "DeleteMapping" => Some(("DELETE".to_string(), path)),
        "PatchMapping" => Some(("PATCH".to_string(), path)),
        "RequestMapping" => {
            let method =
                extract_request_method(annotation).unwrap_or_else(|| "REQUEST".to_string());
            Some((method, path))
        }
        _ => None,
    }
}

fn parse_python_route(decorator: &str) -> Option<(String, String)> {
    let name = annotation_name(decorator);
    let path = extract_named_or_first_string(decorator, &["path"])?;
    let method = if name.ends_with(".route") {
        extract_first_array_string(decorator, "methods").unwrap_or_else(|| "GET".to_string())
    } else if name.ends_with(".get") {
        "GET".to_string()
    } else if name.ends_with(".post") {
        "POST".to_string()
    } else if name.ends_with(".put") {
        "PUT".to_string()
    } else if name.ends_with(".delete") {
        "DELETE".to_string()
    } else if name.ends_with(".patch") {
        "PATCH".to_string()
    } else {
        return None;
    };

    Some((method, path))
}

fn parse_express_method(callee: &str) -> Option<String> {
    let lowered = callee.trim();
    if lowered.ends_with(".get") {
        Some("GET".to_string())
    } else if lowered.ends_with(".post") {
        Some("POST".to_string())
    } else if lowered.ends_with(".put") {
        Some("PUT".to_string())
    } else if lowered.ends_with(".delete") {
        Some("DELETE".to_string())
    } else if lowered.ends_with(".patch") {
        Some("PATCH".to_string())
    } else {
        None
    }
}

fn parse_auth_requirement(annotation: &str) -> Option<String> {
    let name = annotation_name(annotation);
    match name.as_str() {
        "PreAuthorize" | "roles_required" | "role_required" | "permission_required" => {
            extract_role_name(annotation).or_else(|| first_string_literal(annotation))
        }
        "RolesAllowed" | "Secured" => {
            extract_role_name(annotation).or_else(|| first_string_literal(annotation))
        }
        "PermitAll" | "allow_anonymous" => Some("Public".to_string()),
        "login_required" => Some("Authenticated".to_string()),
        _ => {
            if name.contains("login_required") {
                Some("Authenticated".to_string())
            } else {
                None
            }
        }
    }
}

fn extract_role_name(annotation: &str) -> Option<String> {
    for marker in ["hasRole", "hasAuthority", "ROLE_", "ADMIN", "USER"] {
        if let Some(pos) = annotation.find(marker) {
            if marker == "ROLE_" || marker == "ADMIN" || marker == "USER" {
                if let Some(role) = first_string_literal(&annotation[pos..]) {
                    return Some(role);
                }
            } else {
                let tail = &annotation[pos..];
                if let Some(role) = first_string_literal(tail) {
                    return Some(role);
                }
            }
        }
    }
    first_string_literal(annotation)
}

fn extract_request_method(annotation: &str) -> Option<String> {
    let marker = "RequestMethod.";
    let start = annotation.find(marker)? + marker.len();
    let tail = &annotation[start..];
    let method = tail
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .collect::<String>();
    if method.is_empty() {
        None
    } else {
        Some(method)
    }
}

fn extract_named_or_first_string(annotation: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = extract_named_string(annotation, key) {
            return Some(value);
        }
    }
    first_string_literal(annotation)
}

fn extract_named_string(annotation: &str, key: &str) -> Option<String> {
    let start = find_named_argument_start(annotation, key)?;
    first_string_literal(&annotation[start..])
}

fn extract_first_array_string(annotation: &str, key: &str) -> Option<String> {
    let start = find_named_argument_start(annotation, key)?;
    first_string_literal(&annotation[start..])
}

fn find_named_argument_start(annotation: &str, key: &str) -> Option<usize> {
    let key_pos = annotation.find(key)?;
    let mut index = key_pos + key.len();
    let bytes = annotation.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'=') {
        return None;
    }
    index += 1;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    Some(index)
}

fn first_string_literal(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' || bytes[index] == b'"' {
            let quote = bytes[index];
            let start = index + 1;
            index += 1;
            while index < bytes.len() {
                if bytes[index] == quote && bytes.get(index.saturating_sub(1)) != Some(&b'\\') {
                    return Some(text[start..index].to_string());
                }
                index += 1;
            }
            return None;
        }
        index += 1;
    }
    None
}

fn parse_string_literal(text: &str) -> Option<String> {
    first_string_literal(text)
}

fn annotation_name(annotation: &str) -> String {
    annotation
        .trim()
        .trim_start_matches('@')
        .split(|ch: char| ch == '(' || ch.is_whitespace())
        .next()
        .unwrap_or("")
        .to_string()
}

fn join_route(prefix: Option<&str>, suffix: Option<&str>) -> String {
    let prefix = prefix.unwrap_or("").trim();
    let suffix = suffix.unwrap_or("").trim();
    if prefix.is_empty() {
        return normalize_route(suffix);
    }
    if suffix.is_empty() {
        return normalize_route(prefix);
    }
    normalize_route(&format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    ))
}

fn normalize_route(route: &str) -> String {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    let normalized = trimmed.replace("//", "/");
    if normalized.starts_with('/') {
        normalized
    } else {
        format!("/{normalized}")
    }
}

fn line_number_for_byte(source: &[u8], byte_offset: usize) -> u32 {
    let capped = byte_offset.min(source.len());
    source[..capped]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u32
        + 1
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
}

fn handler_leaf_name(name: &str) -> String {
    name.trim()
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .rsplit(['.', ':'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str, language: tree_sitter::Language) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).unwrap();
        parser.parse(source.as_bytes(), None).unwrap()
    }

    #[test]
    fn extracts_spring_controller_surface() {
        let source = br#"
@RequestMapping("/api/v1")
class UserController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public String listUsers() { return "ok"; }
}
"#;
        let tree = parse(
            std::str::from_utf8(source).unwrap(),
            tree_sitter_java::LANGUAGE.into(),
        );
        let surfaces = extract_controller_surface(&tree, "java", source);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].route_path, "/api/v1/users");
        assert_eq!(surfaces[0].http_method, "GET");
        assert_eq!(surfaces[0].auth_requirement.as_deref(), Some("ADMIN"));
    }

    #[test]
    fn extracts_flask_surface() {
        let source = br#"
@app.route("/admin/users", methods=["POST"])
@login_required
def create_user():
    return "ok"
"#;
        let tree = parse(
            std::str::from_utf8(source).unwrap(),
            tree_sitter_python::LANGUAGE.into(),
        );
        let surfaces = extract_controller_surface(&tree, "py", source);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].route_path, "/admin/users");
        assert_eq!(surfaces[0].http_method, "POST");
        assert_eq!(
            surfaces[0].auth_requirement.as_deref(),
            Some("Authenticated")
        );
    }

    #[test]
    fn extracts_express_surface() {
        let source = br#"
router.post("/api/v1/users", requireAdmin, createUser);
"#;
        let tree = parse(
            std::str::from_utf8(source).unwrap(),
            tree_sitter_javascript::LANGUAGE.into(),
        );
        let surfaces = extract_controller_surface(&tree, "js", source);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].route_path, "/api/v1/users");
        assert_eq!(surfaces[0].http_method, "POST");
        assert_eq!(
            surfaces[0].auth_requirement.as_deref(),
            Some("requireAdmin")
        );
    }
}
