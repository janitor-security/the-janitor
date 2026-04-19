//! Framework-aware API router and authorization surface extraction.
//!
//! Extracts deterministic HTTP ingress metadata from Spring Boot, Flask/FastAPI,
//! and Express controller definitions so exploit witnesses can bind to real
//! routes instead of abstract handler names.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use common::slop::StructuredFinding;
use tree_sitter::{Node, Tree};

/// Public controller/router surface exposed by an application handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSurface {
    pub file: String,
    pub route_path: String,
    pub http_method: String,
    pub auth_requirement: Option<String>,
    pub controller: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointSurfaceMatch {
    pub surface: EndpointSurface,
    pub handler_name: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
}

/// Frontend router edge mapping a component or file to a URL path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendRoute {
    pub file: String,
    pub route_path: String,
    pub component: Option<String>,
    pub component_file: Option<String>,
    pub line: Option<u32>,
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

/// Extract frontend router edges from React Router or Vue Router source text.
pub fn extract_frontend_routes_from_source(
    lang: &str,
    source: &[u8],
    file: String,
) -> Vec<FrontendRoute> {
    if !matches!(lang, "js" | "jsx" | "ts" | "tsx") {
        return Vec::new();
    }
    let text = std::str::from_utf8(source).unwrap_or("");
    let imports = collect_js_imports(text, &file);
    let mut routes = extract_react_router_routes(text, source, &file, &imports);
    routes.extend(extract_vue_router_routes(text, source, &file, &imports));

    let mut deduped = Vec::with_capacity(routes.len());
    let mut seen = std::collections::BTreeSet::new();
    for route in routes {
        let key = (
            route.route_path.clone(),
            route.component.clone().unwrap_or_default(),
            route.component_file.clone().unwrap_or_default(),
        );
        if seen.insert(key) {
            deduped.push(route);
        }
    }
    deduped
}

/// Resolve the most likely frontend route for a vulnerable source file.
pub fn match_frontend_route_for_file<'a>(
    routes: &'a [FrontendRoute],
    file_path: &str,
) -> Option<&'a FrontendRoute> {
    let normalized_file = strip_script_extension(&normalize_virtual_path(file_path));
    let file_stem = path_leaf_no_ext(&normalized_file).to_ascii_lowercase();

    routes.iter().find(|route| {
        if strip_script_extension(&normalize_virtual_path(&route.file)) == normalized_file {
            return true;
        }
        if let Some(component_file) = route.component_file.as_deref() {
            let normalized_component =
                strip_script_extension(&normalize_virtual_path(component_file));
            if normalized_component == normalized_file {
                return true;
            }
            if path_leaf_no_ext(&normalized_component).eq_ignore_ascii_case(&file_stem) {
                return true;
            }
        }
        route
            .component
            .as_deref()
            .map(normalize_component_name)
            .map(|component| component == file_stem)
            .unwrap_or(false)
    })
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

/// Check whether endpoint authorization requirements are materially weaker than
/// the dominant peer requirement inside the same controller/router group.
pub fn check_authz_consistency(endpoints: &[EndpointSurface]) -> Vec<StructuredFinding> {
    let mut grouped: HashMap<(String, String), Vec<&EndpointSurface>> = HashMap::new();
    for endpoint in endpoints {
        let controller = endpoint
            .controller
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("file");
        grouped
            .entry((endpoint.file.clone(), controller.to_string()))
            .or_default()
            .push(endpoint);
    }

    let mut findings = Vec::new();
    for ((_file, _controller), group) in grouped {
        if group.len() < 2 {
            continue;
        }
        let Some((expected_auth, dominant_count)) = dominant_auth_requirement(&group) else {
            continue;
        };
        if dominant_count * 5 < group.len() * 4 {
            continue;
        }

        for endpoint in group {
            let actual_auth = canonical_auth(endpoint.auth_requirement.as_deref());
            if is_less_restrictive_than_peers(Some(actual_auth.as_str()), &expected_auth) {
                let remediation = format!(
                    "Endpoint {} {} lacks the authorization constraint ({}) present on its peers.",
                    endpoint.http_method, endpoint.route_path, expected_auth
                );
                let fingerprint_material = format!(
                    "{}:{}:{}:{}:{}",
                    endpoint.file,
                    endpoint.line.unwrap_or_default(),
                    endpoint.http_method,
                    endpoint.route_path,
                    expected_auth
                );
                findings.push(StructuredFinding {
                    id: "security:missing_authz_check".to_string(),
                    file: Some(endpoint.file.clone()),
                    line: endpoint.line,
                    fingerprint: blake3::hash(fingerprint_material.as_bytes())
                        .to_hex()
                        .to_string(),
                    severity: Some("KevCritical".to_string()),
                    remediation: Some(remediation),
                    docs_url: None,
                    exploit_witness: None,
                });
            }
        }
    }

    findings
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
        let controller_name = class_node
            .child_by_field_name("name")
            .and_then(|node| node.utf8_text(source).ok())
            .map(str::to_string);

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
                    controller: controller_name.clone(),
                    line: Some(line_number_for_byte(source, method_node.start_byte())),
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
        let controller_name = decorators
            .iter()
            .find_map(|decorator| parse_decorator_controller(decorator));
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
                controller: controller_name,
                line: Some(line_number_for_byte(source, function_node.start_byte())),
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
        let controller_name = callee_text
            .split('.')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
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
                controller: controller_name,
                line: Some(line_number_for_byte(source, call_node.start_byte())),
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

fn collect_js_imports(text: &str, file: &str) -> HashMap<String, String> {
    let mut imports = HashMap::new();
    for line in text.lines().map(str::trim) {
        if !line.starts_with("import ") || !line.contains(" from ") {
            continue;
        }
        let Some(imported_from) = first_string_literal(line) else {
            continue;
        };
        let resolved = resolve_import_path(file, &imported_from);
        if let Some(default_alias) = parse_default_import_alias(line) {
            imports.insert(default_alias, resolved.clone());
        }
        for alias in parse_named_import_aliases(line) {
            imports.insert(alias, resolved.clone());
        }
    }
    imports
}

fn extract_react_router_routes(
    text: &str,
    source: &[u8],
    file: &str,
    imports: &HashMap<String, String>,
) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    let mut search_from = 0usize;
    while let Some(relative_start) = text[search_from..].find("<Route") {
        let start = search_from + relative_start;
        let Some(end_relative) = text[start..].find('>') else {
            break;
        };
        let end = start + end_relative + 1;
        let tag = &text[start..end];
        let Some(route_path) = extract_jsx_attribute_string(tag, "path") else {
            search_from = end;
            continue;
        };
        let component = extract_react_route_component(tag);
        let component_file = component
            .as_deref()
            .and_then(|name| imports.get(name))
            .cloned();
        routes.push(FrontendRoute {
            file: file.to_string(),
            route_path: normalize_route(&route_path),
            component,
            component_file,
            line: Some(line_number_for_byte(source, start)),
        });
        search_from = end;
    }
    routes
}

fn extract_vue_router_routes(
    text: &str,
    source: &[u8],
    file: &str,
    imports: &HashMap<String, String>,
) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    let mut search_from = 0usize;
    while let Some(relative_start) = text[search_from..].find("path") {
        let start = search_from + relative_start;
        let tail = &text[start..];
        if !tail.starts_with("path") {
            search_from = start + 4;
            continue;
        }
        let Some(path_value_start) = tail.find(':') else {
            search_from = start + 4;
            continue;
        };
        let route_slice = &tail[path_value_start + 1..];
        let Some(route_path) = first_string_literal(route_slice) else {
            search_from = start + 4;
            continue;
        };
        let window_end = tail.find('}').unwrap_or(tail.len()).min(256);
        let window = &tail[..window_end];
        let component = extract_vue_component_name(window);
        let component_file = if let Some(dynamic_import) = extract_dynamic_import_path(window) {
            Some(resolve_import_path(file, &dynamic_import))
        } else {
            component
                .as_deref()
                .and_then(|name| imports.get(name))
                .cloned()
        };
        routes.push(FrontendRoute {
            file: file.to_string(),
            route_path: normalize_route(&route_path),
            component,
            component_file,
            line: Some(line_number_for_byte(source, start)),
        });
        search_from = start + 4;
    }
    routes
}

fn extract_jsx_attribute_string(tag: &str, attribute: &str) -> Option<String> {
    let marker = format!("{attribute}=");
    let start = tag.find(&marker)? + marker.len();
    first_string_literal(&tag[start..])
}

fn extract_react_route_component(tag: &str) -> Option<String> {
    for marker in ["element={<", "Component={", "component={"] {
        let Some(start) = tag.find(marker) else {
            continue;
        };
        let tail = &tag[start + marker.len()..];
        let ident = take_identifier(tail);
        if !ident.is_empty() {
            return Some(ident.to_string());
        }
    }
    None
}

fn extract_vue_component_name(window: &str) -> Option<String> {
    let marker = "component";
    let start = window.find(marker)? + marker.len();
    let tail = &window[start..];
    let colon = tail.find(':')?;
    let ident = take_identifier(&tail[colon + 1..]);
    (!ident.is_empty()).then(|| ident.to_string())
}

fn extract_dynamic_import_path(window: &str) -> Option<String> {
    let marker = "import(";
    let start = window.find(marker)? + marker.len();
    first_string_literal(&window[start..])
}

fn parse_default_import_alias(line: &str) -> Option<String> {
    let rest = line.strip_prefix("import ")?;
    let alias = rest.split(" from ").next()?.trim();
    let alias = alias.split(',').next()?.trim();
    if alias.is_empty() || alias.starts_with('{') || alias.starts_with('*') {
        None
    } else {
        Some(alias.to_string())
    }
}

fn parse_named_import_aliases(line: &str) -> Vec<String> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let Some(end) = line[start + 1..].find('}') else {
        return Vec::new();
    };
    line[start + 1..start + 1 + end]
        .split(',')
        .filter_map(|entry| {
            let candidate = entry.split(" as ").last().map(str::trim).unwrap_or("");
            (!candidate.is_empty()).then(|| candidate.to_string())
        })
        .collect()
}

fn resolve_import_path(route_file: &str, imported: &str) -> String {
    if !imported.starts_with('.') {
        return imported.to_string();
    }
    let mut resolved = PathBuf::new();
    if let Some(parent) = Path::new(route_file).parent() {
        resolved.push(parent);
    }
    resolved.push(imported);
    normalize_virtual_path(&resolved.to_string_lossy())
}

fn normalize_virtual_path(raw: &str) -> String {
    let mut clean = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    clean.to_string_lossy().replace('\\', "/")
}

fn strip_script_extension(path: &str) -> String {
    const EXTENSIONS: &[&str] = &[".tsx", ".ts", ".jsx", ".js", ".vue"];
    for extension in EXTENSIONS {
        if let Some(stripped) = path.strip_suffix(extension) {
            return stripped.to_string();
        }
    }
    path.to_string()
}

fn path_leaf_no_ext(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(path)
        .to_string()
}

fn normalize_component_name(component: &str) -> String {
    component
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn take_identifier(text: &str) -> &str {
    let trimmed = text.trim_start();
    let end = trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        .map(char::len_utf8)
        .sum::<usize>();
    &trimmed[..end]
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

fn parse_decorator_controller(decorator: &str) -> Option<String> {
    let name = annotation_name(decorator);
    let controller = name.split('.').next()?.trim();
    if controller.is_empty() {
        None
    } else {
        Some(controller.to_string())
    }
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

fn dominant_auth_requirement(group: &[&EndpointSurface]) -> Option<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for endpoint in group {
        let auth = canonical_auth(endpoint.auth_requirement.as_deref());
        *counts.entry(auth).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|(left_auth, left_count), (right_auth, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| auth_strength(left_auth).cmp(&auth_strength(right_auth)))
                .then_with(|| left_auth.cmp(right_auth))
        })
}

fn canonical_auth(auth_requirement: Option<&str>) -> String {
    let Some(auth_requirement) = auth_requirement
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return "Public".to_string();
    };
    auth_requirement.to_string()
}

fn is_less_restrictive_than_peers(actual_auth: Option<&str>, expected_auth: &str) -> bool {
    let actual = canonical_auth(actual_auth);
    if actual == expected_auth {
        return false;
    }
    let actual_strength = auth_strength(&actual);
    let expected_strength = auth_strength(expected_auth);
    actual_strength < expected_strength
        || (expected_strength > 0 && actual_strength == expected_strength && actual == "Public")
}

fn auth_strength(auth_requirement: &str) -> u8 {
    let lowered = auth_requirement.trim().to_ascii_lowercase();
    if lowered.is_empty()
        || lowered == "public"
        || lowered == "permitall"
        || lowered.contains("anonymous")
    {
        0
    } else if lowered.contains("authenticated") || lowered.contains("login") {
        1
    } else if lowered.contains("admin")
        || lowered.contains("root")
        || lowered.contains("superuser")
        || lowered.contains("super_admin")
    {
        3
    } else {
        2
    }
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
        assert_eq!(surfaces[0].controller.as_deref(), Some("UserController"));
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
        assert_eq!(surfaces[0].controller.as_deref(), Some("app"));
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
        assert_eq!(surfaces[0].controller.as_deref(), Some("router"));
    }

    #[test]
    fn extracts_react_router_frontend_route() {
        let source = br#"
import Captcha from "./captcha";

export function Router() {
    return <Route path="/login" element={<Captcha />} />;
}
"#;
        let routes =
            extract_frontend_routes_from_source("tsx", source, "src/router.tsx".to_string());
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route_path, "/login");
        assert_eq!(routes[0].component.as_deref(), Some("Captcha"));
        assert_eq!(routes[0].component_file.as_deref(), Some("src/captcha"));
    }

    #[test]
    fn extracts_vue_router_frontend_route() {
        let source = br#"
import LoginView from "./views/LoginView.vue";

const routes = [
  { path: "/login", component: LoginView }
];
"#;
        let routes = extract_frontend_routes_from_source("ts", source, "src/router.ts".to_string());
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route_path, "/login");
        assert_eq!(routes[0].component.as_deref(), Some("LoginView"));
    }

    #[test]
    fn matches_frontend_route_by_component_file_stem() {
        let routes = vec![FrontendRoute {
            file: "src/router.tsx".to_string(),
            route_path: "/login".to_string(),
            component: Some("Captcha".to_string()),
            component_file: Some("src/web-auth/captcha".to_string()),
            line: Some(3),
        }];

        let matched =
            match_frontend_route_for_file(&routes, "src/web-auth/captcha.js").expect("route");
        assert_eq!(matched.route_path, "/login");
    }

    #[test]
    fn flags_endpoint_missing_dominant_auth_requirement() {
        let endpoints = vec![
            EndpointSurface {
                file: "src/UserController.java".to_string(),
                route_path: "/api/v1/users".to_string(),
                http_method: "GET".to_string(),
                auth_requirement: Some("ROLE_ADMIN".to_string()),
                controller: Some("UserController".to_string()),
                line: Some(10),
            },
            EndpointSurface {
                file: "src/UserController.java".to_string(),
                route_path: "/api/v1/users/search".to_string(),
                http_method: "GET".to_string(),
                auth_requirement: Some("ROLE_ADMIN".to_string()),
                controller: Some("UserController".to_string()),
                line: Some(20),
            },
            EndpointSurface {
                file: "src/UserController.java".to_string(),
                route_path: "/api/v1/users/{id}".to_string(),
                http_method: "GET".to_string(),
                auth_requirement: Some("ROLE_ADMIN".to_string()),
                controller: Some("UserController".to_string()),
                line: Some(30),
            },
            EndpointSurface {
                file: "src/UserController.java".to_string(),
                route_path: "/api/v1/users/{id}/disable".to_string(),
                http_method: "POST".to_string(),
                auth_requirement: Some("ROLE_ADMIN".to_string()),
                controller: Some("UserController".to_string()),
                line: Some(40),
            },
            EndpointSurface {
                file: "src/UserController.java".to_string(),
                route_path: "/api/v1/users/{id}".to_string(),
                http_method: "DELETE".to_string(),
                auth_requirement: None,
                controller: Some("UserController".to_string()),
                line: Some(50),
            },
        ];

        let findings = check_authz_consistency(&endpoints);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:missing_authz_check");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        assert!(
            findings[0]
                .remediation
                .as_deref()
                .unwrap_or("")
                .contains("Endpoint DELETE /api/v1/users/{id} lacks the authorization constraint (ROLE_ADMIN) present on its peers.")
        );
    }
}
