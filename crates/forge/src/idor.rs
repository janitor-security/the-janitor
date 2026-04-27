//! IDOR detector for route-bound ownership checks.
//!
//! Leverages the extracted endpoint surface to identify handlers whose path
//! parameters reach database lookup sinks without a preceding ownership guard
//! against the authenticated principal.

use common::slop::StructuredFinding;
use tree_sitter::Tree;

use crate::authz::{self, EndpointSurface, EndpointSurfaceMatch};

/// Taint catalog authority used by the endpoint-only IDOR entrypoint.
pub type TaintCatalog = crate::taint_catalog::CatalogView;

const PRINCIPAL_TOKENS: &[&str] = &[
    "current_user.id",
    "current_user.get_id(",
    "request.user.id",
    "g.user.id",
    "session.user.id",
    "req.user.id",
    "req.user?.id",
    "res.locals.user.id",
    "claims.sub",
    "jwt.sub",
    "token.sub",
    "principal.id",
    "principal.getid(",
    "authentication.getname(",
    "auth.uid",
    "subject",
];

const DB_SINK_TOKENS: &[&str] = &[
    "select ",
    ".query(",
    ".execute(",
    ".filter(",
    ".filter_by(",
    ".where(",
    ".find(",
    ".findone(",
    ".findunique(",
    ".findbyid(",
    ".findbypk(",
    ".get(",
    "repository.find",
    "repo.find",
    "db.session.get",
    "db.get(",
    "jdbctemplate",
    "preparestatement(",
    "entitymanager.find",
];

const JOIN_TOKENS: &[&str] = &[
    "owner_id",
    "user_id",
    "account_id",
    "principal_id",
    "subject_id",
    "tenant_id",
    "member_id",
];

/// Scan a parsed source file for missing ownership checks on path-parameter
/// routes.
pub fn scan_tree(tree: &Tree, lang: &str, source: &[u8], file: &str) -> Vec<StructuredFinding> {
    let surfaces =
        authz::extract_controller_surface_with_file(tree, lang, source, file.to_string());
    scan_surfaces(source, file, &surfaces)
}

/// Parse `source` when the extension is supported and scan it for missing
/// ownership checks on route-bound path parameters.
pub fn scan_source(lang: &str, source: &[u8], file: &str) -> Vec<StructuredFinding> {
    let Some(grammar) = ::polyglot::LazyGrammarRegistry::get(lang) else {
        return Vec::new();
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(grammar).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    scan_tree(&tree, lang, source, file)
}

/// Find route-bound database lookups that lack an ownership predicate.
///
/// This public entrypoint consumes the framework-neutral endpoint surface and
/// the persisted taint catalog. Source-backed callers should prefer
/// [`scan_tree`] or [`scan_source`], which verify the ownership predicate in the
/// handler body. Endpoint-only callers still get deterministic coverage when a
/// controller symbol is cataloged as reaching a sink.
pub fn find_missing_ownership_checks(
    endpoints: &[EndpointSurface],
    taint_catalog: &TaintCatalog,
) -> Vec<StructuredFinding> {
    if endpoints.is_empty() || taint_catalog.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for endpoint in endpoints {
        let params = extract_path_params(&endpoint.route_path);
        if params.is_empty() {
            continue;
        }

        let controller = endpoint
            .controller
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(controller) = controller else {
            continue;
        };
        if !taint_catalog.has_sink(controller) {
            continue;
        }

        let line = endpoint.line.unwrap_or_default();
        let fingerprint_material = format!(
            "{}:{}:{}:{}:{}",
            endpoint.file, line, endpoint.http_method, endpoint.route_path, controller
        );
        findings.push(StructuredFinding {
            id: "security:missing_ownership_check".to_string(),
            file: Some(endpoint.file.clone()),
            line: endpoint.line,
            fingerprint: blake3::hash(fingerprint_material.as_bytes())
                .to_hex()
                .to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: Some(format!(
                "Endpoint {} {} routes path parameter(s) {} into cataloged database sink `{controller}` without endpoint-surface evidence of a principal ownership predicate. Constrain the lookup by current_user.id, session.userId, or an equivalent tenant principal in the same query.",
                endpoint.http_method,
                endpoint.route_path,
                params.join(", ")
            )),
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        });
    }
    findings
}

fn scan_surfaces(
    source: &[u8],
    file: &str,
    surfaces: &[EndpointSurfaceMatch],
) -> Vec<StructuredFinding> {
    let mut findings = Vec::new();
    for surface in surfaces {
        let params = extract_path_params(&surface.surface.route_path);
        if params.is_empty() {
            continue;
        }
        let Some((start, end)) =
            line_range_to_byte_span(source, surface.start_line, surface.end_line)
        else {
            continue;
        };
        let handler = &source[start..end.min(source.len())];
        let lines = std::str::from_utf8(handler)
            .unwrap_or("")
            .lines()
            .collect::<Vec<_>>();
        if lines.is_empty() {
            continue;
        }

        let param_refs = build_param_refs(&params);
        let mut sink_line_index = None;
        for (index, line) in lines.iter().enumerate() {
            if reaches_database_sink(line, &param_refs) {
                sink_line_index = Some(index);
                break;
            }
        }
        let Some(sink_line_index) = sink_line_index else {
            continue;
        };

        if has_prior_ownership_check(&lines, sink_line_index, &param_refs) {
            continue;
        }

        let sink_line = lines[sink_line_index].trim();
        let line = surface.start_line.saturating_add(sink_line_index as u32);
        let fingerprint_material = format!(
            "{}:{}:{}:{}:{}",
            file, line, surface.surface.http_method, surface.surface.route_path, sink_line
        );
        findings.push(StructuredFinding {
            id: "security:missing_ownership_check".to_string(),
            file: Some(file.to_string()),
            line: Some(line),
            fingerprint: blake3::hash(fingerprint_material.as_bytes())
                .to_hex()
                .to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: Some(format!(
                "Endpoint {} {} routes path parameter(s) {} into a database lookup before proving ownership against the authenticated principal. Enforce a principal equality guard or include the principal identifier in the query predicate before fetching the record.",
                surface.surface.http_method,
                surface.surface.route_path,
                params.join(", ")
            )),
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        });
    }
    findings
}

fn extract_path_params(route: &str) -> Vec<String> {
    let mut params = Vec::new();
    let bytes = route.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                if let Some(end) = route[index + 1..].find('}') {
                    let raw = &route[index + 1..index + 1 + end];
                    let name = raw.trim().split(':').next_back().unwrap_or("").trim();
                    if !name.is_empty() {
                        params.push(name.to_string());
                    }
                    index += end + 2;
                    continue;
                }
            }
            b':' => {
                let start = index + 1;
                let end = route[start..]
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .map(|offset| start + offset)
                    .unwrap_or(route.len());
                let name = route[start..end].trim();
                if !name.is_empty() {
                    params.push(name.to_string());
                }
                index = end;
                continue;
            }
            b'<' => {
                if let Some(end) = route[index + 1..].find('>') {
                    let raw = &route[index + 1..index + 1 + end];
                    let name = raw.trim().split(':').next_back().unwrap_or("").trim();
                    if !name.is_empty() {
                        params.push(name.to_string());
                    }
                    index += end + 2;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }
    params.sort_unstable();
    params.dedup();
    params
}

fn build_param_refs(params: &[String]) -> Vec<String> {
    let mut refs = Vec::with_capacity(params.len() * 6);
    for param in params {
        let normalized = param.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        refs.push(normalized.clone());
        refs.push(format!("req.params.{normalized}"));
        refs.push(format!("request.params.{normalized}"));
        refs.push(format!("params.{normalized}"));
        refs.push(format!("[\"{normalized}\"]"));
        refs.push(format!("['{normalized}']"));
    }
    refs.sort_unstable();
    refs.dedup();
    refs
}

fn reaches_database_sink(line: &str, param_refs: &[String]) -> bool {
    let lower = line.to_ascii_lowercase();
    let touches_param = param_refs.iter().any(|param| lower.contains(param));
    touches_param && DB_SINK_TOKENS.iter().any(|token| lower.contains(token))
}

fn has_prior_ownership_check(
    lines: &[&str],
    sink_line_index: usize,
    param_refs: &[String],
) -> bool {
    let sink_line = lines[sink_line_index].to_ascii_lowercase();
    if is_join_guard(&sink_line, param_refs) {
        return true;
    }

    lines[..sink_line_index].iter().any(|line| {
        let lower = line.to_ascii_lowercase();
        compares_principal(&lower, param_refs)
    })
}

fn compares_principal(line: &str, param_refs: &[String]) -> bool {
    contains_principal(line)
        && param_refs.iter().any(|param| line.contains(param))
        && (line.contains("==")
            || line.contains("!=")
            || line.contains("===")
            || line.contains("!==")
            || line.contains(".equals(")
            || line.contains(" eq("))
}

fn is_join_guard(line: &str, param_refs: &[String]) -> bool {
    contains_principal(line)
        && param_refs.iter().any(|param| line.contains(param))
        && JOIN_TOKENS.iter().any(|token| line.contains(token))
}

fn contains_principal(line: &str) -> bool {
    PRINCIPAL_TOKENS.iter().any(|token| line.contains(token))
}

fn line_range_to_byte_span(
    source: &[u8],
    start_line: u32,
    end_line: u32,
) -> Option<(usize, usize)> {
    if start_line == 0 || end_line < start_line {
        return None;
    }
    let starts = line_start_offsets(source);
    let start_index = start_line.saturating_sub(1) as usize;
    if start_index >= starts.len() {
        return None;
    }
    let end_line_exclusive = end_line as usize;
    let start = starts[start_index];
    let end = starts
        .get(end_line_exclusive)
        .copied()
        .unwrap_or(source.len());
    Some((start, end))
}

fn line_start_offsets(source: &[u8]) -> Vec<usize> {
    let mut starts = Vec::with_capacity(source.len() / 24 + 2);
    starts.push(0);
    for (index, byte) in source.iter().enumerate() {
        if *byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar must load");
        parser
            .parse(source, None)
            .expect("python parse must succeed")
    }

    #[test]
    fn flags_vulnerable_python_route_without_ownership_check() {
        let source = r#"
@app.get("/users/<int:user_id>")
def show_user(user_id):
    record = db.session.query(User).filter_by(id=user_id).first()
    return jsonify(record)
"#;
        let tree = parse(source);
        let findings = scan_tree(&tree, "py", source.as_bytes(), "app.py");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:missing_ownership_check");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn skips_route_with_prior_principal_equality_guard() {
        let source = r#"
@app.get("/users/<int:user_id>")
def show_user(user_id):
    if user_id != current_user.id:
        abort(403)
    record = db.session.query(User).filter_by(id=user_id).first()
    return jsonify(record)
"#;
        let tree = parse(source);
        let findings = scan_tree(&tree, "py", source.as_bytes(), "app.py");
        assert!(
            findings.is_empty(),
            "principal equality guard must suppress the IDOR finding"
        );
    }
}
