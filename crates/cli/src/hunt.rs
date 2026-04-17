//! `janitor hunt` — Offensive security scanner for bug-bounty engagements.
//!
//! Recursively walks a target directory (or a source tree reconstructed from a
//! JavaScript sourcemap / npm tarball / Android APK / Java JAR / Electron ASAR /
//! Docker image tarball), runs the full Janitor detector suite on every file, and
//! emits results as a single JSON array of [`common::slop::StructuredFinding`] to
//! stdout.
//!
//! ## Modes
//!
//! ```text
//! janitor hunt ./target                           # local directory
//! janitor hunt --sourcemap https://x.com/a.map    # JS sourcemap
//! janitor hunt --npm lodash@4.17.21               # npm package
//! janitor hunt --apk app.apk                      # Android APK (requires jadx)
//! janitor hunt --jar app.jar                      # Java archive
//! janitor hunt --asar app.asar                    # Electron ASAR archive
//! janitor hunt --docker image.tar                 # docker save tarball
//! janitor hunt ./target --filter '.[] | select(.severity == "Critical")'
//! ```
//!
//! Stdout is always a valid JSON array.  Use `--filter` for native `jq`-style
//! filtering (no runtime `jq` dependency required).

use anyhow::Context as _;
use common::slop::StructuredFinding;
use forge::slop_hunter::{find_slop, ParsedUnit};
use std::io::Read as _;
use std::path::Path;
use walkdir::WalkDir;

/// 16 MiB — HTTP body cap for sourcemap and npm registry responses.
const HTTP_BODY_LIMIT: u64 = 16 * 1024 * 1024;
/// 1 MiB — per-file circuit breaker matching slop_hunter.rs.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// 512 MiB — total layer data buffered during docker save extraction.
const DOCKER_LAYER_BUDGET: usize = 512 * 1024 * 1024;

pub struct HuntArgs<'a> {
    pub scan_root: Option<&'a Path>,
    pub sourcemap_url: Option<&'a str>,
    pub npm_pkg: Option<&'a str>,
    pub apk_path: Option<&'a Path>,
    pub jar_path: Option<&'a Path>,
    pub asar_path: Option<&'a Path>,
    pub docker_path: Option<&'a Path>,
    pub filter_expr: Option<&'a str>,
    pub corpus_path: Option<&'a Path>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for `janitor hunt`.
///
/// A local `scan_root` or one remote/archive fetcher is required. All modes produce a
/// `Vec<StructuredFinding>`
/// serialised as JSON to stdout.  If `filter_expr` is provided the JSON output
/// is piped through a native `jq`-compatible filter before printing.
pub fn cmd_hunt(args: HuntArgs<'_>) -> anyhow::Result<()> {
    let HuntArgs {
        scan_root,
        sourcemap_url,
        npm_pkg,
        apk_path,
        jar_path,
        asar_path,
        docker_path,
        filter_expr,
        corpus_path,
    } = args;
    let _ = corpus_path; // reserved — slopsquat corpus override

    let source_count = usize::from(scan_root.is_some())
        + usize::from(sourcemap_url.is_some())
        + usize::from(npm_pkg.is_some())
        + usize::from(apk_path.is_some())
        + usize::from(jar_path.is_some())
        + usize::from(asar_path.is_some())
        + usize::from(docker_path.is_some());

    if source_count == 0 {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --apk, --jar, --asar, or --docker"
        );
    }
    if source_count > 1 {
        anyhow::bail!(
            "hunt accepts exactly one source: provide either <path> or one of --sourcemap, --npm, --apk, --jar, --asar, or --docker"
        );
    }

    let findings = if let Some(url) = sourcemap_url {
        ingest_sourcemap(url)?
    } else if let Some(pkg) = npm_pkg {
        ingest_npm(pkg)?
    } else if let Some(apk) = apk_path {
        ingest_apk(apk)?
    } else if let Some(jar) = jar_path {
        ingest_jar(jar)?
    } else if let Some(asar) = asar_path {
        ingest_asar(asar)?
    } else if let Some(docker) = docker_path {
        ingest_docker(docker)?
    } else if let Some(root) = scan_root {
        scan_directory(root)?
    } else {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --apk, --jar, --asar, or --docker"
        );
    };

    let json_val =
        serde_json::to_value(&findings).context("failed to convert findings to JSON value")?;

    let output_val = if let Some(expr) = filter_expr {
        apply_jaq_filter(expr, json_val)?
    } else {
        json_val
    };

    let json = serde_json::to_string_pretty(&output_val)
        .context("failed to serialise findings as JSON")?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Sourcemap ingestion  (Phase A)
// ---------------------------------------------------------------------------

/// Download a JavaScript sourcemap, reconstruct the source tree into a
/// `tempfile::TempDir`, scan it, and return findings.  The tempdir is
/// automatically deleted when the function returns (RAII drop).
fn ingest_sourcemap(url: &str) -> anyhow::Result<Vec<StructuredFinding>> {
    let agent = ureq::Agent::new_with_defaults();
    let map: serde_json::Value = agent
        .get(url)
        .call()
        .map_err(|_| anyhow::anyhow!("sourcemap HTTP fetch failed"))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("sourcemap response is not valid JSON")?;

    let sources = map["sources"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sourcemap missing 'sources' array"))?;
    let contents = map["sourcesContent"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // RAII: tempdir is deleted when `tmpdir` drops at end of scope.
    let tmpdir = tempfile::TempDir::new().context("failed to create sourcemap tmpdir")?;

    for (i, source_val) in sources.iter().enumerate() {
        let raw = source_val.as_str().unwrap_or("");
        let safe = sanitize_sourcemap_path(raw, i);
        let dest = tmpdir.path().join(&safe);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent for sourcemap entry {i}"))?;
        }
        let content = contents.get(i).and_then(|v| v.as_str()).unwrap_or("");
        std::fs::write(&dest, content.as_bytes())
            .with_context(|| format!("write sourcemap entry {i}"))?;
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — reconstructed tree deleted
}

// ---------------------------------------------------------------------------
// npm tarball ingestion  (Phase B)
// ---------------------------------------------------------------------------

/// Download an npm package tarball, extract it to a `tempfile::TempDir`,
/// scan the extracted tree, and return findings.
///
/// `pkg` may be `"lodash"` (resolves latest) or `"lodash@4.17.21"`.
fn ingest_npm(pkg: &str) -> anyhow::Result<Vec<StructuredFinding>> {
    let (name, version) = parse_npm_spec(pkg);
    let resolved_version = if version.is_empty() {
        resolve_npm_latest(name)?
    } else {
        version.to_owned()
    };

    let tgz_url = format!("https://registry.npmjs.org/{name}/-/{name}-{resolved_version}.tgz");

    let agent = ureq::Agent::new_with_defaults();
    let mut response = agent
        .get(&tgz_url)
        .call()
        .map_err(|_| anyhow::anyhow!("npm registry fetch failed for {name}@{resolved_version}"))?;

    // Stream through GzDecoder → tar::Archive → tempdir (RAII drop).
    let tmpdir = tempfile::TempDir::new().context("failed to create npm tmpdir")?;
    {
        let body_reader = response
            .body_mut()
            .with_config()
            .limit(HTTP_BODY_LIMIT)
            .reader();
        let gz = flate2::read::GzDecoder::new(body_reader);
        let mut archive = tar::Archive::new(gz);
        archive
            .unpack(tmpdir.path())
            .context("failed to extract npm tarball")?;
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — extracted package deleted
}

/// Parse `"name@version"` → `("name", "version")`.
/// Handles scoped packages like `"@scope/name@1.0.0"`.
fn parse_npm_spec(pkg: &str) -> (&str, &str) {
    // For scoped packages (@scope/name), the `@` version separator can only
    // appear after the `/`.  Find the last `@` that is not at position 0.
    if let Some(at) = pkg[1..].rfind('@') {
        let pos = at + 1; // offset into original string
        (&pkg[..pos], &pkg[pos + 1..])
    } else {
        (pkg, "")
    }
}

/// Resolve the latest published version for an npm package via the registry
/// metadata endpoint (`https://registry.npmjs.org/<name>/latest`).
fn resolve_npm_latest(name: &str) -> anyhow::Result<String> {
    let url = format!("https://registry.npmjs.org/{name}/latest");
    let agent = ureq::Agent::new_with_defaults();
    let meta: serde_json::Value = agent
        .get(&url)
        .call()
        .map_err(|_| anyhow::anyhow!("npm registry metadata fetch failed for {name}"))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("npm registry metadata is not valid JSON")?;

    meta["version"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("npm registry response missing 'version' field"))
}

// ---------------------------------------------------------------------------
// APK ingestion via jadx  (Phase C)
// ---------------------------------------------------------------------------

/// Decompile an Android APK using `jadx`, scan the decompiled source tree,
/// and return findings.  The decompiled tree is deleted via RAII on return.
///
/// # Errors
///
/// Returns an error if `jadx` is not installed, decompilation fails, or the
/// scan encounters an I/O error.
fn ingest_apk(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    // Preflight: verify jadx is available in PATH.
    std::process::Command::new("jadx")
        .arg("--version")
        .output()
        .map_err(|_| {
            anyhow::anyhow!("jadx is not installed or not in PATH. Required for APK decompilation.")
        })?;

    let tmpdir = tempfile::TempDir::new().context("failed to create APK decompilation tmpdir")?;

    let status = std::process::Command::new("jadx")
        .env("JAVA_OPTS", "-Xmx4G")
        .arg("-d")
        .arg(tmpdir.path())
        .arg("-j")
        .arg("1")
        .arg(path)
        .status()
        .context("failed to spawn jadx")?;

    if !status.success() {
        anyhow::bail!(
            "jadx decompilation failed with exit code {:?}",
            status.code()
        );
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — decompiled source deleted
}

// ---------------------------------------------------------------------------
// Docker save tarball ingestion  (Phase P1-2a)
// ---------------------------------------------------------------------------

/// Internal manifest entry from `manifest.json` in a `docker save` tarball.
#[derive(serde::Deserialize)]
struct DockerManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// Ingest a `docker save` tarball, merge layers into a unified filesystem
/// tree in a `tempfile::TempDir`, scan the tree, and return findings.
///
/// ## docker save format
///
/// ```text
/// manifest.json            — JSON array of DockerManifestEntry
/// <hash>.json              — image config (ignored during scan)
/// <layer_id>/layer.tar     — one tar per layer, applied in order
/// ```
///
/// Whiteout files emitted by the union filesystem are honoured:
/// - `.wh.<name>` — deletes the sibling file/dir named `<name>`
/// - `.wh..wh..opq` — clears the containing directory (opaque whiteout)
///
/// ## Circuit breaker
///
/// Total buffered layer data is capped at `DOCKER_LAYER_BUDGET` (512 MiB).
/// Any tarball that would exceed this limit is skipped.
fn ingest_docker(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    use std::io::Read as _;

    let file =
        std::fs::File::open(path).with_context(|| format!("open docker tar {}", path.display()))?;
    let mut outer = tar::Archive::new(file);

    // First pass: buffer manifest.json and all layer tars keyed by path.
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut layer_bufs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut total_layer_bytes: usize = 0;

    for entry in outer.entries().context("iterate docker tar entries")? {
        let mut entry = entry.context("read docker tar entry")?;
        let entry_path = entry
            .path()
            .context("docker tar entry path")?
            .to_string_lossy()
            .replace('\\', "/")
            .to_string();

        if entry_path == "manifest.json" {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("read manifest.json from docker tar")?;
            manifest_bytes = Some(buf);
        } else if entry_path.ends_with("/layer.tar") || entry_path == "layer.tar" {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("read layer.tar from docker tar")?;
            let new_total = total_layer_bytes.saturating_add(buf.len());
            if new_total > DOCKER_LAYER_BUDGET {
                // Skip layers that breach the circuit breaker.
                continue;
            }
            total_layer_bytes = new_total;
            layer_bufs.insert(entry_path, buf);
        }
    }

    let manifest_bytes =
        manifest_bytes.ok_or_else(|| anyhow::anyhow!("docker tar missing manifest.json"))?;
    let manifests: Vec<DockerManifestEntry> = serde_json::from_slice(&manifest_bytes)
        .context("docker manifest.json is not valid JSON")?;
    let manifest = manifests
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("docker manifest.json contains no entries"))?;

    let tmpdir =
        tempfile::TempDir::new().context("failed to create docker layer extraction tmpdir")?;

    // Apply layers in order, honouring whiteout semantics.
    for layer_path in &manifest.layers {
        // Normalise path separators from manifest.json (may use backslash on Windows images).
        let normalised = layer_path.replace('\\', "/");
        let Some(layer_data) = layer_bufs.get(&normalised) else {
            // Layer not buffered (exceeded circuit breaker or absent) — skip.
            continue;
        };

        let mut layer_tar = tar::Archive::new(layer_data.as_slice());
        for entry in layer_tar.entries().context("iterate layer tar entries")? {
            let mut entry = entry.context("read layer tar entry")?;
            let raw_path = entry
                .path()
                .context("layer entry path")?
                .to_string_lossy()
                .replace('\\', "/")
                .to_string();

            // Sanitize path to prevent traversal.
            let Some(rel) = sanitize_archive_entry_path(&raw_path) else {
                continue;
            };

            let file_name = rel
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Opaque whiteout — clear the entire containing directory.
            if file_name == ".wh..wh..opq" {
                if let Some(parent) = rel.parent() {
                    let dir_to_clear = tmpdir.path().join(parent);
                    if dir_to_clear.exists() {
                        std::fs::remove_dir_all(&dir_to_clear).ok();
                        std::fs::create_dir_all(&dir_to_clear).ok();
                    }
                }
                continue;
            }

            // Regular whiteout — delete the named sibling.
            if let Some(stripped) = file_name.strip_prefix(".wh.") {
                if let Some(parent) = rel.parent() {
                    let target = tmpdir.path().join(parent).join(stripped);
                    if target.is_file() {
                        std::fs::remove_file(&target).ok();
                    } else if target.is_dir() {
                        std::fs::remove_dir_all(&target).ok();
                    }
                }
                continue;
            }

            let dest = tmpdir.path().join(&rel);

            if entry.header().entry_type().is_dir() {
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("create layer dir {}", dest.display()))?;
                continue;
            }

            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create layer parent {}", parent.display()))?;
            }

            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .with_context(|| format!("read layer file {raw_path}"))?;
            std::fs::write(&dest, &buf)
                .with_context(|| format!("write layer file {}", dest.display()))?;
        }
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — merged layer tree deleted
}

// ---------------------------------------------------------------------------
// JAR ingestion  (Phase D)
// ---------------------------------------------------------------------------

/// Extract a Java `.jar` archive into a `tempfile::TempDir`, scan the expanded
/// tree, and return findings.
fn ingest_jar(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open JAR archive {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("failed to parse JAR archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create JAR extraction tmpdir")?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("failed to read JAR entry {i}"))?;
        let Some(safe_rel) = sanitize_archive_entry_path(entry.name()) else {
            continue;
        };
        let dest = tmpdir.path().join(safe_rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create JAR directory {}", dest.display()))?;
            continue;
        }

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create JAR parent {}", parent.display()))?;
        }

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read JAR file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted JAR file {}", dest.display()))?;
    }

    scan_directory(tmpdir.path())
}

// ---------------------------------------------------------------------------
// Electron ASAR ingestion  (Phase E)
// ---------------------------------------------------------------------------

/// Parse an Electron `.asar` archive in pure Rust, extract its contents to a
/// `tempfile::TempDir`, scan the extracted tree, and return findings.
///
/// ## ASAR format (Chromium Pickle):
///
/// ```text
/// [0..4]           uint32 LE = 4              (outer pickle header_size)
/// [4..8]           uint32 LE = header_buf_size (size of the inner pickle)
/// [8..12]          uint32 LE = inner payload   (4 + json_len, 4-byte aligned)
/// [12..16]         uint32 LE = json_len
/// [16..16+json_len] UTF-8 JSON header
/// [8+header_buf_size..] concatenated file data
/// ```
fn ingest_asar(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let data = std::fs::read(path).context("failed to read ASAR file")?;

    if data.len() < 16 {
        anyhow::bail!(
            "not a valid ASAR archive: file too short ({} bytes)",
            data.len()
        );
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != 4 {
        anyhow::bail!(
            "not a valid ASAR archive: bad outer pickle header (expected 4, got {magic})"
        );
    }

    let header_buf_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let json_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    let json_end = 16usize
        .checked_add(json_len)
        .ok_or_else(|| anyhow::anyhow!("ASAR json_len overflow"))?;
    if data.len() < json_end {
        anyhow::bail!(
            "ASAR header JSON truncated: need {json_end} bytes, have {}",
            data.len()
        );
    }

    let header_json: serde_json::Value =
        serde_json::from_slice(&data[16..json_end]).context("ASAR header JSON is not valid")?;

    let data_offset = 8usize
        .checked_add(header_buf_size)
        .ok_or_else(|| anyhow::anyhow!("ASAR data_offset overflow"))?;
    if data.len() < data_offset {
        anyhow::bail!(
            "ASAR data region missing: need offset {data_offset}, have {} bytes",
            data.len()
        );
    }

    let tmpdir = tempfile::TempDir::new().context("failed to create ASAR extraction tmpdir")?;

    if let Some(files) = header_json.get("files") {
        extract_asar_dir(files, &data[data_offset..], tmpdir.path())?;
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — extracted tree deleted
}

/// Recursively extract a directory node from the ASAR header JSON.
///
/// `node` is the object under a `"files"` key.
/// `file_data` is the raw concatenated file data region.
/// `dest_dir` is the target directory on the local filesystem.
fn extract_asar_dir(
    node: &serde_json::Value,
    file_data: &[u8],
    dest_dir: &Path,
) -> anyhow::Result<()> {
    let entries = match node.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };

    for (name, entry) in entries {
        // Path traversal guard: reject any name with separators or dots-only.
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            continue;
        }
        let dest = dest_dir.join(name);

        if let Some(sub_files) = entry.get("files") {
            // Directory node — recurse.
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create ASAR subdir {}", dest.display()))?;
            extract_asar_dir(sub_files, file_data, &dest)?;
        } else {
            // File node — extract bytes by offset + size.
            // ASAR stores offset as a decimal string, not a JSON number.
            let offset = entry
                .get("offset")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let end = offset.saturating_add(size);
            if end > file_data.len() {
                // Truncated file — skip rather than panic.
                continue;
            }
            std::fs::write(&dest, &file_data[offset..end])
                .with_context(|| format!("write ASAR file {}", dest.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Native jq-style filter  (Phase 3 / P2-7)
// ---------------------------------------------------------------------------

/// Apply a `jq`-compatible filter expression to a `serde_json::Value` using
/// the pure-Rust [`jaq`](https://crates.io/crates/jaq-interpret) engine.
///
/// Returns a `Value::Array` of all output values produced by the filter.
fn apply_jaq_filter(
    filter_str: &str,
    findings_json: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use jaq_interpret::{Ctx, FilterT as _, ParseCtx, RcIter, Val};

    // Parse the filter expression.
    let (prog, errs) = jaq_parse::parse(filter_str, jaq_parse::main());
    if !errs.is_empty() {
        anyhow::bail!("jaq: filter parse failed — check filter syntax");
    }
    let prog = prog.ok_or_else(|| anyhow::anyhow!("jaq: empty filter expression"))?;

    // Compile: load native core functions + standard library definitions.
    let mut defs = ParseCtx::new(Vec::new());
    defs.insert_natives(jaq_core::core());
    defs.insert_defs(jaq_std::std());
    let filter = defs.compile(prog);

    // Execute against the findings JSON.
    let inputs = RcIter::new(core::iter::empty());

    let results: Vec<serde_json::Value> = filter
        .run((Ctx::new([], &inputs), Val::from(findings_json)))
        .filter_map(|r| r.ok())
        .map(serde_json::Value::from)
        .collect();

    Ok(serde_json::Value::Array(results))
}

// ---------------------------------------------------------------------------
// Directory walker (shared by all ingestion paths)
// ---------------------------------------------------------------------------

/// Walk `dir` recursively, run all detectors on every file, and return the
/// unified finding list.  Files > 1 MiB and unreadable files are silently
/// skipped.
fn scan_directory(dir: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let mut all: Vec<StructuredFinding> = Vec::new();

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();

        if std::fs::metadata(file_path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            continue;
        }

        let source = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let unit = ParsedUnit::unparsed(&source);
        let raw = find_slop(ext, &unit);

        for f in raw {
            all.push(StructuredFinding {
                id: extract_rule_id(&f.description),
                file: Some(rel_path.clone()),
                line: Some(byte_to_line(&source, f.start_byte)),
                fingerprint: fingerprint_finding(&source, f.start_byte, f.end_byte),
                severity: Some(format!("{:?}", f.severity)),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
            });
        }
    }

    Ok(all)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitise a raw sourcemap `sources[]` path to prevent path traversal.
///
/// Strips `webpack:///`, `file://`, and `//` prefixes; removes `../` sequences;
/// caps depth at 3 components.
pub fn sanitize_sourcemap_path(raw: &str, index: usize) -> String {
    let stripped = raw
        .trim_start_matches("webpack:///")
        .trim_start_matches("webpack://")
        .trim_start_matches("file:///")
        .trim_start_matches("file://")
        .trim_start_matches("//");

    let clean = stripped
        .replace("../", "")
        .replace("..\\", "")
        .replace("..", "");

    let components: Vec<&str> = clean
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    if components.is_empty() {
        return format!("source_{index}");
    }

    let capped = if components.len() > 3 {
        &components[components.len() - 3..]
    } else {
        &components[..]
    };
    capped.join("/")
}

fn byte_to_line(source: &[u8], byte_offset: usize) -> u32 {
    let capped = byte_offset.min(source.len());
    source[..capped].iter().filter(|&&b| b == b'\n').count() as u32 + 1
}

fn extract_rule_id(description: &str) -> String {
    description
        .split(" \u{2014} ") // U+2014 EM DASH with spaces
        .next()
        .unwrap_or(description)
        .to_owned()
}

fn fingerprint_finding(source: &[u8], start: usize, end: usize) -> String {
    let s = start.min(source.len());
    let e = end.min(source.len());
    let window = if s < e { &source[s..e] } else { &source[s..s] };
    hex::encode(&blake3::hash(window).as_bytes()[..8])
}

fn sanitize_archive_entry_path(raw: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, PathBuf};

    let mut clean = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }

    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // -----------------------------------------------------------------------
    // sanitize_sourcemap_path
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_strips_webpack_prefix() {
        assert_eq!(
            sanitize_sourcemap_path("webpack:///src/components/App.js", 0),
            "src/components/App.js"
        );
    }

    #[test]
    fn sanitize_blocks_path_traversal() {
        let result = sanitize_sourcemap_path("webpack:///../../etc/passwd", 0);
        assert!(!result.contains(".."), "must strip path traversal");
        assert!(result.split('/').count() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_caps_depth_at_three() {
        let result = sanitize_sourcemap_path("webpack:///a/b/c/d/e/f/g.js", 0);
        assert!(result.split('/').count() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_empty_path_returns_fallback() {
        assert_eq!(sanitize_sourcemap_path("", 7), "source_7");
    }

    // -----------------------------------------------------------------------
    // extract_rule_id / byte_to_line
    // -----------------------------------------------------------------------

    #[test]
    fn extract_rule_id_splits_on_em_dash() {
        assert_eq!(
            extract_rule_id("security:command_injection \u{2014} system() with dynamic arg"),
            "security:command_injection"
        );
    }

    #[test]
    fn extract_rule_id_no_separator_returns_whole() {
        assert_eq!(extract_rule_id("security:raw"), "security:raw");
    }

    #[test]
    fn byte_to_line_counts_newlines() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(byte_to_line(src, 0), 1);
        assert_eq!(byte_to_line(src, 6), 2);
        assert_eq!(byte_to_line(src, 12), 3);
    }

    // -----------------------------------------------------------------------
    // scan_directory — credential detection
    // -----------------------------------------------------------------------

    #[test]
    fn scan_directory_emits_credential_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.yml"),
            b"AKIAIOSFODNN7EXAMPLE = true",
        )
        .unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            !findings.is_empty(),
            "AWS key prefix must trigger credential finding"
        );
        assert!(
            findings[0].id.contains("credential"),
            "finding id must contain 'credential'"
        );
    }

    #[test]
    fn scan_directory_skips_oversized_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.bin");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_FILE_BYTES + 1).unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.file.as_deref() != Some("big.bin")),
            "oversized file must be skipped"
        );
    }

    // -----------------------------------------------------------------------
    // Sourcemap ingestion — mock JSON round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn sourcemap_reconstruction_scans_inline_content() {
        let map = serde_json::json!({
            "version": 3,
            "sources": ["webpack:///src/server.js"],
            "sourcesContent": [
                "const exec = require('child_process');\n\
                 exec.execSync('rm -rf ' + userInput);\n\
                 const key = 'AKIAIOSFODNN7EXAMPLEKEY123';\n"
            ]
        });
        let map_str = serde_json::to_string(&map).unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("src").join("server.js");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();

        let content = map["sourcesContent"][0].as_str().unwrap();
        std::fs::write(&dest, content.as_bytes()).unwrap();

        let findings = scan_directory(tmp.path()).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "reconstructed source with AWS key must produce a credential finding; map={map_str}"
        );
    }

    // -----------------------------------------------------------------------
    // npm spec parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_npm_spec_versioned() {
        let (name, ver) = parse_npm_spec("lodash@4.17.21");
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_npm_spec_unversioned() {
        let (name, ver) = parse_npm_spec("lodash");
        assert_eq!(name, "lodash");
        assert_eq!(ver, "");
    }

    #[test]
    fn parse_npm_spec_scoped_versioned() {
        let (name, ver) = parse_npm_spec("@scope/pkg@2.0.0");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "2.0.0");
    }

    #[test]
    fn parse_npm_spec_scoped_unversioned() {
        let (name, ver) = parse_npm_spec("@scope/pkg");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "");
    }

    // -----------------------------------------------------------------------
    // npm tarball extraction round-trip (mock tarball in memory)
    // -----------------------------------------------------------------------

    #[test]
    fn npm_tarball_extraction_scans_extracted_files() {
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::fast());
            let mut tar = tar::Builder::new(gz);

            let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "package/index.js", content.as_ref())
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }

        let extract_dir = tempfile::TempDir::new().unwrap();
        {
            let gz = flate2::read::GzDecoder::new(tar_bytes.as_slice());
            let mut archive = tar::Archive::new(gz);
            archive.unpack(extract_dir.path()).unwrap();
        }

        let findings = scan_directory(extract_dir.path()).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "extracted JS with AWS key must produce a credential finding"
        );
    }

    // -----------------------------------------------------------------------
    // JAR extraction round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn jar_extraction_scans_embedded_java_source() {
        let tmp = tempfile::TempDir::new().unwrap();
        let jar_path = tmp.path().join("sample.jar");
        let file = std::fs::File::create(&jar_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        let content = b"class Demo { void run(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }\n";
        zip.start_file("src/Demo.java", options).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();

        let findings = ingest_jar(&jar_path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| { f.id.contains("runtime_exec") || f.id.contains("command_injection") }),
            "JAR-extracted Java source with Runtime.exec must produce a finding"
        );
    }

    // -----------------------------------------------------------------------
    // ASAR parser — synthetic archive round-trip  (Phase D)
    // -----------------------------------------------------------------------

    /// Build a minimal in-memory ASAR archive containing `filename` with `content`.
    fn build_asar(filename: &str, content: &[u8]) -> Vec<u8> {
        let file_header = serde_json::json!({
            "files": {
                filename: {
                    "size": content.len(),
                    "offset": "0"
                }
            }
        });
        let json_str = serde_json::to_string(&file_header).unwrap();
        let json_bytes = json_str.as_bytes();
        let json_len = json_bytes.len();

        // Inner pickle payload: [json_len as u32] + json_bytes, 4-byte aligned.
        let inner_payload = 4 + json_len;
        let inner_payload_padded = (inner_payload + 3) & !3;
        let inner_pickle_size = 4 + inner_payload_padded;

        let mut asar: Vec<u8> = Vec::new();
        // Outer pickle: header_size=4, then inner_pickle_size.
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&(inner_pickle_size as u32).to_le_bytes());
        // Inner pickle: payload_size, then json_len string prefix, then JSON.
        asar.extend_from_slice(&(inner_payload_padded as u32).to_le_bytes());
        asar.extend_from_slice(&(json_len as u32).to_le_bytes());
        asar.extend_from_slice(json_bytes);
        // Padding to 4-byte boundary.
        for _ in 0..(inner_payload_padded - inner_payload) {
            asar.push(0);
        }
        // File data.
        asar.extend_from_slice(content);
        asar
    }

    #[test]
    fn asar_extraction_scans_embedded_credential() {
        let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
        let asar_bytes = build_asar("index.js", content);

        let tmp = tempfile::TempDir::new().unwrap();
        let asar_path = tmp.path().join("app.asar");
        std::fs::write(&asar_path, &asar_bytes).unwrap();

        let findings = ingest_asar(&asar_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "ASAR-extracted JS with AWS key must produce a credential finding"
        );
    }

    #[test]
    fn asar_rejects_bad_magic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("bad.asar");
        // Magic = 0x01020304, not 0x00000004.
        std::fs::write(
            &path,
            b"\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert!(
            ingest_asar(&path).is_err(),
            "invalid ASAR magic must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // Docker save tarball ingestion
    // -----------------------------------------------------------------------

    /// Build a minimal in-memory `docker save` tar containing one layer.
    /// The layer tar contains `filename` with `content`.
    fn build_docker_tar(filename: &str, content: &[u8]) -> Vec<u8> {
        // Build inner layer.tar bytes.
        let mut layer_tar_bytes: Vec<u8> = Vec::new();
        {
            let mut layer_builder = tar::Builder::new(&mut layer_tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            layer_builder
                .append_data(&mut header, filename, content)
                .unwrap();
            layer_builder.finish().unwrap();
        }

        // Build manifest.json.
        let manifest = serde_json::json!([{
            "Config": "abc123.json",
            "RepoTags": ["test:latest"],
            "Layers": ["layer0/layer.tar"]
        }]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        // Build outer docker save tar.
        let mut outer_bytes: Vec<u8> = Vec::new();
        {
            let mut outer = tar::Builder::new(&mut outer_bytes);

            // manifest.json
            let mut mhdr = tar::Header::new_gnu();
            mhdr.set_size(manifest_bytes.len() as u64);
            mhdr.set_mode(0o644);
            mhdr.set_cksum();
            outer
                .append_data(&mut mhdr, "manifest.json", manifest_bytes.as_slice())
                .unwrap();

            // layer0/layer.tar
            let mut lhdr = tar::Header::new_gnu();
            lhdr.set_size(layer_tar_bytes.len() as u64);
            lhdr.set_mode(0o644);
            lhdr.set_cksum();
            outer
                .append_data(&mut lhdr, "layer0/layer.tar", layer_tar_bytes.as_slice())
                .unwrap();

            outer.finish().unwrap();
        }

        outer_bytes
    }

    #[test]
    fn docker_ingest_extracts_and_scans_layer_content() {
        let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
        let docker_bytes = build_docker_tar("app/index.js", content);

        let tmp = tempfile::TempDir::new().unwrap();
        let tar_path = tmp.path().join("image.tar");
        std::fs::write(&tar_path, &docker_bytes).unwrap();

        let findings = ingest_docker(&tar_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "docker layer JS with AWS key must produce a credential finding"
        );
    }

    #[test]
    fn docker_ingest_rejects_missing_manifest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tar_path = tmp.path().join("bad.tar");

        // Build a tar with no manifest.json.
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let content = b"irrelevant";
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(content.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, "some_file.txt", content.as_ref())
                .unwrap();
            builder.finish().unwrap();
        }
        std::fs::write(&tar_path, &bytes).unwrap();

        assert!(
            ingest_docker(&tar_path).is_err(),
            "docker tar without manifest.json must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // jaq native filter  (Phase 3 / P2-7)
    // -----------------------------------------------------------------------

    #[test]
    fn jaq_filter_selects_by_severity() {
        let input = serde_json::json!([
            {"id": "security:a", "severity": "Critical"},
            {"id": "security:b", "severity": "Low"}
        ]);
        let result = apply_jaq_filter(".[] | select(.severity == \"Critical\")", input).unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(
            arr.len(),
            1,
            "filter must select exactly one Critical finding"
        );
        assert_eq!(arr[0]["id"].as_str().unwrap(), "security:a");
    }

    #[test]
    fn jaq_filter_iterates_all_elements() {
        let input = serde_json::json!([{"id": "a"}, {"id": "b"}, {"id": "c"}]);
        let result = apply_jaq_filter(".[]", input).unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3, ".[] must iterate over all elements");
    }

    #[test]
    fn jaq_filter_invalid_syntax_returns_error() {
        let input = serde_json::json!([]);
        assert!(
            apply_jaq_filter("invalid ][[ syntax", input).is_err(),
            "malformed filter must return an error"
        );
    }
}
