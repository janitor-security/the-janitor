//! Configuration Taint Analysis — framework config object backward-trace.
//!
//! Detects attacker-controlled properties flowing into framework configuration
//! objects (e.g., `new Auth0Lock(clientId, domain, options)` where
//! `options.theme.css` is derived from `window.location.hash`).
//!
//! ## Algorithm
//! 1. Scan the source buffer for assignments that read from a known external
//!    taint source (`URLSearchParams`, `window.location.{hash,search}`,
//!    `postMessage` `event.data`, `document.cookie`).
//! 2. Collect the variable names that receive those tainted values.
//! 3. For each tainted variable, scan for framework config property assignments
//!    where the right-hand side contains that variable name.
//! 4. Emit a [`ConfigTaintFlow`] for every confirmed path.
//!
//! ## Fail-open contract
//! Returns empty `Vec` on any parse edge-case. Never blocks a bounce.

/// External web-API taint source categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigTaintSource {
    /// Value extracted from `new URLSearchParams(window.location.search)` or
    /// `.get()`/`.getAll()` on an existing `URLSearchParams` object.
    UrlSearchParams,
    /// `window.location.hash` or `location.hash` read directly.
    WindowLocationHash,
    /// `window.location.search` or `location.search` read directly.
    WindowLocationSearch,
    /// `event.data` received in a `message` event listener (`postMessage`).
    PostMessage,
    /// `document.cookie` string read directly.
    DocumentCookie,
}

impl ConfigTaintSource {
    /// Human-readable label used in exploit witness text.
    pub fn label(&self) -> &'static str {
        match self {
            Self::UrlSearchParams => "URLSearchParams",
            Self::WindowLocationHash => "window.location.hash",
            Self::WindowLocationSearch => "window.location.search",
            Self::PostMessage => "postMessage event.data",
            Self::DocumentCookie => "document.cookie",
        }
    }
}

/// A confirmed taint flow through a framework configuration property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigTaintFlow {
    /// Dot-path of the config property that is tainted (e.g., `"theme.css"`).
    pub property_path: String,
    /// The external source that supplies attacker-controlled data.
    pub source: ConfigTaintSource,
    /// Byte offset of the taint-carrying assignment in the source buffer.
    pub assignment_byte: usize,
    /// Name of the intermediate variable carrying taint (may equal the
    /// property path if a direct property assignment was detected).
    pub taint_variable: String,
}

// ---------------------------------------------------------------------------
// Taint source signatures — ordered by specificity (longest first).
// ---------------------------------------------------------------------------

const URL_SEARCH_PARAMS_PATTERNS: &[&[u8]] = &[
    b"new URLSearchParams(",
    b"URLSearchParams(",
    b".get(",    // searchParams.get(
    b".getAll(", // searchParams.getAll(
];

const WINDOW_LOCATION_HASH_PATTERNS: &[&[u8]] = &[b"window.location.hash", b"location.hash"];

const WINDOW_LOCATION_SEARCH_PATTERNS: &[&[u8]] = &[b"window.location.search", b"location.search"];

const POST_MESSAGE_PATTERNS: &[&[u8]] = &[b"event.data", b"e.data", b"msg.data", b"message.data"];

const DOCUMENT_COOKIE_PATTERNS: &[&[u8]] = &[b"document.cookie"];

// Framework constructor names that accept a config/options object.
const FRAMEWORK_CONSTRUCTORS: &[&[u8]] = &[
    b"Auth0Lock(",
    b"Lock(",
    b"Auth0(",
    b"createAuth0Client(",
    b"initAuth(",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan JavaScript/TypeScript source for configuration taint flows.
///
/// Returns one [`ConfigTaintFlow`] per confirmed attacker-controlled config
/// property.  The analysis is purely textual (no AST) for maximum portability
/// across JS/TS dialects, JSX, and minified bundles.
pub fn track_config_taint_js(source: &[u8]) -> Vec<ConfigTaintFlow> {
    let mut flows = Vec::new();

    // Step 1: collect (variable_name, ConfigTaintSource, byte_offset) tuples.
    let tainted_vars = collect_tainted_variables(source);
    if tainted_vars.is_empty() {
        return flows;
    }

    // Step 2: for each tainted variable, find config property assignments.
    for (var_name, src_kind, _offset) in &tainted_vars {
        scan_config_assignments(source, var_name, src_kind.clone(), &mut flows);
    }

    // Step 3: deduplicate by (property_path, source discriminant).
    flows.dedup_by(|a, b| a.property_path == b.property_path && a.source == b.source);
    flows
}

/// Check whether a JS/TS source buffer contains any framework constructor
/// call, indicating that config taint analysis is applicable.
pub fn has_framework_constructor(source: &[u8]) -> bool {
    FRAMEWORK_CONSTRUCTORS
        .iter()
        .any(|pat| memmem(source, pat).is_some())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return all (variable_name, ConfigTaintSource, byte_offset) tuples found in
/// the source buffer where a variable is assigned from a taint source.
fn collect_tainted_variables(source: &[u8]) -> Vec<(String, ConfigTaintSource, usize)> {
    let mut out: Vec<(String, ConfigTaintSource, usize)> = Vec::new();

    // Direct read of window.location.hash → var
    for offset in find_all(source, WINDOW_LOCATION_HASH_PATTERNS) {
        if let Some(var) = extract_lhs_variable(source, offset) {
            out.push((var, ConfigTaintSource::WindowLocationHash, offset));
        }
    }

    // Direct read of window.location.search → var
    for offset in find_all(source, WINDOW_LOCATION_SEARCH_PATTERNS) {
        if let Some(var) = extract_lhs_variable(source, offset) {
            out.push((var, ConfigTaintSource::WindowLocationSearch, offset));
        }
    }

    // URLSearchParams construction → var
    for offset in find_all(source, URL_SEARCH_PARAMS_PATTERNS) {
        if let Some(var) = extract_lhs_variable(source, offset) {
            out.push((var, ConfigTaintSource::UrlSearchParams, offset));
        }
    }

    // postMessage event.data → var
    for offset in find_all(source, POST_MESSAGE_PATTERNS) {
        if let Some(var) = extract_lhs_variable(source, offset) {
            out.push((var, ConfigTaintSource::PostMessage, offset));
        }
    }

    // document.cookie → var
    for offset in find_all(source, DOCUMENT_COOKIE_PATTERNS) {
        if let Some(var) = extract_lhs_variable(source, offset) {
            out.push((var, ConfigTaintSource::DocumentCookie, offset));
        }
    }

    out
}

/// Scan source for config property assignments where the RHS contains
/// `taint_var` and emit a [`ConfigTaintFlow`] for each hit.
fn scan_config_assignments(
    source: &[u8],
    taint_var: &str,
    src_kind: ConfigTaintSource,
    flows: &mut Vec<ConfigTaintFlow>,
) {
    let taint_bytes = taint_var.as_bytes();
    let mut search = source;
    let mut base_offset = 0usize;

    while let Some(pos) = memmem(search, taint_bytes) {
        let abs = base_offset + pos;

        // Verify the match is a standalone identifier (not a substring).
        if is_identifier_boundary(source, abs, taint_bytes.len()) {
            if let Some(prop) = find_config_property_for_rhs(source, abs) {
                flows.push(ConfigTaintFlow {
                    property_path: prop,
                    source: src_kind.clone(),
                    assignment_byte: abs,
                    taint_variable: taint_var.to_string(),
                });
            }
        }

        // Advance past this occurrence.
        let step = pos + 1;
        if step >= search.len() {
            break;
        }
        base_offset += step;
        search = &search[step..];
    }
}

/// Walk backward from `rhs_offset` in `source` to find a config property LHS
/// of the form `<ident>.<prop> =` or `theme.<prop> =` or `options.<prop> =`.
///
/// Returns `"<obj>.<prop>"` on success; `None` otherwise.
fn find_config_property_for_rhs(source: &[u8], rhs_offset: usize) -> Option<String> {
    // Scan backward to the start of the current line.
    let line_start = source[..rhs_offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);

    let line = &source[line_start..rhs_offset.min(source.len())];
    let line_str = std::str::from_utf8(line).ok()?.trim();

    // Patterns: `foo.bar =`, `options.theme.css =`, `config["key"] =`
    let eq_pos = line_str.rfind('=')?;
    let lhs = line_str[..eq_pos].trim();

    // Must contain a `.` — indicating a property path.
    if !lhs.contains('.') && !lhs.contains('[') {
        return None;
    }

    // Strip leading keywords: `const`, `let`, `var`, `this.`
    let lhs = lhs
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("this.");

    // Filter noise: `===`, `!==`, `==` are comparisons, not assignments.
    if eq_pos > 0 {
        let before = line_str.as_bytes().get(eq_pos - 1).copied().unwrap_or(0);
        if before == b'!' || before == b'<' || before == b'>' || before == b'=' {
            return None;
        }
    }

    Some(lhs.to_string())
}

/// Extract the variable name that is assigned the result of a taint-source
/// expression at `source_offset`.
///
/// Scans backward to find `var/let/const <name> = ` or `<name> = ` on the
/// same line.  Returns `None` if no clean assignment is found.
fn extract_lhs_variable(source: &[u8], source_offset: usize) -> Option<String> {
    let line_start = source[..source_offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);

    let line = &source[line_start..source_offset.min(source.len())];
    let line_str = std::str::from_utf8(line).ok()?.trim();

    // Find the last `=` that is not `==`/`!=/>=/<= `
    let eq_pos = line_str.rfind('=')?;
    if eq_pos == 0 {
        return None;
    }
    let before = line_str.as_bytes()[eq_pos - 1];
    if before == b'!' || before == b'<' || before == b'>' || before == b'=' {
        return None;
    }

    let lhs = line_str[..eq_pos]
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ");

    // Must be a valid JS identifier (alphanumeric + _ + $, no dots for this pass).
    if lhs.is_empty() || lhs.contains('.') || lhs.contains('[') {
        return None;
    }
    if lhs
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
    {
        Some(lhs.to_string())
    } else {
        None
    }
}

/// True when the byte at `offset..offset+len` in `source` is an isolated
/// identifier (not part of a longer word).
fn is_identifier_boundary(source: &[u8], offset: usize, len: usize) -> bool {
    let before = if offset > 0 { source[offset - 1] } else { b' ' };
    let after = source.get(offset + len).copied().unwrap_or(b' ');
    let before_ok = !before.is_ascii_alphanumeric() && before != b'_' && before != b'$';
    let after_ok = !after.is_ascii_alphanumeric() && after != b'_' && after != b'$';
    before_ok && after_ok
}

/// Find all byte offsets in `source` where any pattern in `patterns` matches.
fn find_all(source: &[u8], patterns: &[&[u8]]) -> Vec<usize> {
    let mut hits = Vec::new();
    for pat in patterns {
        let mut search = source;
        let mut base = 0usize;
        while let Some(pos) = memmem(search, pat) {
            hits.push(base + pos);
            let step = pos + 1;
            if step >= search.len() {
                break;
            }
            base += step;
            search = &search[step..];
        }
    }
    hits.sort_unstable();
    hits
}

/// Minimal `memmem` shim — finds the first occurrence of `needle` in
/// `haystack`.  Uses `std::slice::windows` to stay dependency-free.
#[inline]
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity test: memmem finds needle correctly.
    #[test]
    fn memmem_finds_simple_pattern() {
        assert_eq!(memmem(b"hello world", b"world"), Some(6));
        assert_eq!(memmem(b"hello world", b"xyz"), None);
    }

    #[test]
    fn has_framework_constructor_detects_auth0lock() {
        let src = b"const lock = new Auth0Lock(clientId, domain, options);";
        assert!(has_framework_constructor(src));
    }

    #[test]
    fn has_framework_constructor_negative_plain_function() {
        let src = b"const x = initializeSomething();";
        assert!(!has_framework_constructor(src));
    }

    #[test]
    fn config_taint_detects_location_hash_assigned_to_css_property() {
        // Simulate: options.theme.css = window.location.hash (direct assignment)
        let src = b"\
const rawHash = window.location.hash;\n\
options.theme.css = rawHash;\n\
const lock = new Auth0Lock(clientId, domain, options);\n\
";
        let flows = track_config_taint_js(src);
        assert!(
            !flows.is_empty(),
            "window.location.hash flowing into a config property must be detected"
        );
        let flow = &flows[0];
        assert_eq!(flow.source, ConfigTaintSource::WindowLocationHash);
        assert!(flow.property_path.contains("theme.css") || flow.property_path.contains("css"));
    }

    #[test]
    fn config_taint_detects_url_search_params_in_theme_color() {
        let src = b"\
const params = new URLSearchParams(window.location.search);\n\
const primaryColor = params.get('color');\n\
options.theme.primaryColor = primaryColor;\n\
";
        let flows = track_config_taint_js(src);
        // The URLSearchParams construction will tag `params`, then
        // `primaryColor` will appear as LHS-extracted on the .get() line.
        // At least one flow should link primaryColor to a config property.
        assert!(
            !flows.is_empty(),
            "URLSearchParams theme property taint must be detected"
        );
    }

    #[test]
    fn config_taint_no_false_positive_for_static_css() {
        // Static CSS string with no external source — should produce no flows.
        let src = b"\
const css = '.auth0-lock { background: #fff; }';\n\
options.theme.css = css;\n\
";
        let flows = track_config_taint_js(src);
        assert!(
            flows.is_empty(),
            "static CSS string must not produce a ConfigTaintFlow"
        );
    }

    #[test]
    fn config_taint_detects_postmessage_event_data_in_config() {
        let src = b"\
window.addEventListener('message', function(event) {\n\
  const userCss = event.data;\n\
  lockOptions.theme.css = userCss;\n\
});\n\
";
        let flows = track_config_taint_js(src);
        assert!(
            !flows.is_empty(),
            "postMessage event.data flowing into config must be detected"
        );
        assert_eq!(flows[0].source, ConfigTaintSource::PostMessage);
    }

    #[test]
    fn config_taint_no_false_positive_for_comparison() {
        // `===` is not an assignment — must not produce a flow.
        let src = b"\
if (options.theme.css === window.location.hash) { return; }\n\
";
        let flows = track_config_taint_js(src);
        assert!(
            flows.is_empty(),
            "comparison expression must not produce a ConfigTaintFlow"
        );
    }
}
