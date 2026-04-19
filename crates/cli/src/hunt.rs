//! `janitor hunt` — Offensive security scanner for bug-bounty engagements.
//!
//! Recursively walks a target directory (or a source tree reconstructed from a
//! JavaScript sourcemap / npm tarball / Android APK / Java JAR / Electron ASAR /
//! Docker image tarball), runs the full Janitor detector suite on every file, and
//! emits results as either a JSON array of
//! [`common::slop::StructuredFinding`] or a Bugcrowd-ready Markdown report to
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
//! janitor hunt --ipa app.ipa                      # iOS IPA bundle
//! janitor hunt ./target --filter '.[] | select(.severity == "Critical")'
//! ```
//!
//! JSON mode supports `--filter` for native `jq`-style filtering (no runtime
//! `jq` dependency required).

use anyhow::Context as _;
use common::slop::StructuredFinding;
use common::wisdom::{ArchivedSlopsquatCorpus, SlopsquatCorpus};
use forge::slop_hunter::{find_slop, ParsedUnit};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// 16 MiB — HTTP body cap for sourcemap and npm registry responses.
const HTTP_BODY_LIMIT: u64 = 16 * 1024 * 1024;
/// 64 MiB — wheel / egg download and extraction cap.
const PYPI_BODY_LIMIT: u64 = 64 * 1024 * 1024;
/// 1 MiB — per-file circuit breaker matching slop_hunter.rs.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// 512 MiB — total layer data buffered during docker save extraction.
const DOCKER_LAYER_BUDGET: usize = 512 * 1024 * 1024;

/// Embedded offline-baseline slopsquat corpus produced by `build.rs`.
static EMBEDDED_SLOPSQUAT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/slopsquat_corpus.rkyv"));

pub struct HuntArgs<'a> {
    pub scan_root: Option<&'a Path>,
    pub sourcemap_url: Option<&'a str>,
    pub npm_pkg: Option<&'a str>,
    pub whl_path: Option<&'a Path>,
    pub pypi_pkg: Option<&'a str>,
    pub apk_path: Option<&'a Path>,
    pub jar_path: Option<&'a Path>,
    pub asar_path: Option<&'a Path>,
    pub docker_path: Option<&'a Path>,
    pub ipa_path: Option<&'a Path>,
    pub filter_expr: Option<&'a str>,
    pub format: &'a str,
    pub corpus_path: Option<&'a Path>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for `janitor hunt`.
///
/// A local `scan_root` or one remote/archive fetcher is required. All modes
/// produce a `Vec<StructuredFinding>`. JSON mode serialises findings directly to
/// stdout; Bugcrowd mode renders grouped Markdown reports. If `filter_expr` is
/// provided the result set is piped through a native `jq`-compatible filter
/// before printing or Markdown rendering.
pub fn cmd_hunt(args: HuntArgs<'_>) -> anyhow::Result<()> {
    let HuntArgs {
        scan_root,
        sourcemap_url,
        npm_pkg,
        whl_path,
        pypi_pkg,
        apk_path,
        jar_path,
        asar_path,
        docker_path,
        ipa_path,
        filter_expr,
        format,
        corpus_path,
    } = args;

    match format {
        "json" | "bugcrowd" => {}
        _ => anyhow::bail!(
            "unsupported hunt output format '{format}' (expected 'json' or 'bugcrowd')"
        ),
    }

    let has_explicit_ingest_source = sourcemap_url.is_some()
        || npm_pkg.is_some()
        || whl_path.is_some()
        || pypi_pkg.is_some()
        || apk_path.is_some()
        || jar_path.is_some()
        || asar_path.is_some()
        || docker_path.is_some()
        || ipa_path.is_some();
    let scan_root = if is_placeholder_scan_root(scan_root, has_explicit_ingest_source) {
        None
    } else {
        scan_root
    };

    let source_count = usize::from(scan_root.is_some())
        + usize::from(sourcemap_url.is_some())
        + usize::from(npm_pkg.is_some())
        + usize::from(whl_path.is_some())
        + usize::from(pypi_pkg.is_some())
        + usize::from(apk_path.is_some())
        + usize::from(jar_path.is_some())
        + usize::from(asar_path.is_some())
        + usize::from(docker_path.is_some());
    let source_count = source_count + usize::from(ipa_path.is_some());

    if source_count == 0 {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    }
    if source_count > 1 {
        anyhow::bail!(
            "hunt accepts exactly one source: provide either <path> or one of --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    }

    let findings = if let Some(url) = sourcemap_url {
        ingest_sourcemap(url)?
    } else if let Some(pkg) = npm_pkg {
        ingest_npm(pkg)?
    } else if let Some(path) = whl_path {
        ingest_whl(path, corpus_path)?
    } else if let Some(pkg) = pypi_pkg {
        ingest_pypi(pkg, corpus_path)?
    } else if let Some(apk) = apk_path {
        ingest_apk(apk)?
    } else if let Some(jar) = jar_path {
        ingest_jar(jar)?
    } else if let Some(asar) = asar_path {
        ingest_asar(asar)?
    } else if let Some(docker) = docker_path {
        ingest_docker(docker)?
    } else if let Some(ipa) = ipa_path {
        ingest_ipa(ipa)?
    } else if let Some(root) = scan_root {
        scan_directory(root)?
    } else {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    };

    let findings = if let Some(expr) = filter_expr {
        let filtered = apply_jaq_filter(
            expr,
            serde_json::to_value(&findings).context("failed to convert findings to JSON value")?,
        )?;
        serde_json::from_value::<Vec<StructuredFinding>>(filtered)
            .context("jaq filter must yield an array of structured findings")?
    } else {
        findings
    };

    if format == "bugcrowd" {
        println!("{}", format_bugcrowd_report(&findings));
        return Ok(());
    }

    let output_val =
        serde_json::to_value(&findings).context("failed to convert findings to JSON value")?;

    let json = serde_json::to_string_pretty(&output_val)
        .context("failed to serialise findings as JSON")?;
    println!("{json}");
    Ok(())
}

fn format_bugcrowd_report(findings: &[StructuredFinding]) -> String {
    let mut grouped: BTreeMap<&str, Vec<&StructuredFinding>> = BTreeMap::new();
    for finding in findings {
        grouped
            .entry(finding.id.as_str())
            .or_default()
            .push(finding);
    }

    let mut reports = Vec::with_capacity(grouped.len().max(1));
    for (rule_id, group) in grouped {
        let mut sorted_group = group;
        sorted_group.sort_by(|left, right| {
            let left_key = (
                left.file.as_deref().unwrap_or("~"),
                left.line.unwrap_or(u32::MAX),
                left.fingerprint.as_str(),
            );
            let right_key = (
                right.file.as_deref().unwrap_or("~"),
                right.line.unwrap_or(u32::MAX),
                right.fingerprint.as_str(),
            );
            left_key.cmp(&right_key)
        });

        let details = sorted_group
            .iter()
            .map(|finding| {
                format!(
                    "- File: {}, Line: {}",
                    finding.file.as_deref().unwrap_or("unknown"),
                    finding
                        .line
                        .map(|line| line.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let highest_severity = sorted_group
            .iter()
            .filter_map(|finding| finding.severity.as_deref())
            .max_by_key(|severity| severity_rank(severity));

        let business_impact = business_impact_statement(rule_id, highest_severity);
        let mitigation = suggested_mitigation(&sorted_group);
        let proof_of_concept = proof_of_concept_section(&sorted_group);

        reports.push(format!(
            "**Summary Title:** Multiple instances of {rule_id} in target\n\
**VRT Category:** {}\n\
**Vulnerability Details:**\n\
During a static analysis of the target artifacts, the following critical security sinks were identified:\n\
{details}\n\
**Business Impact:** {business_impact}\n\
**Proof of Concept:**\n\
{proof_of_concept}\n\
**Suggested Mitigation:** {mitigation}",
            vrt_category(rule_id)
        ));
    }

    if reports.is_empty() {
        return String::from(
            "**Summary Title:** Multiple instances of no_findings in target\n\
**VRT Category:** Informational\n\
**Vulnerability Details:**\n\
During a static analysis of the target artifacts, no findings were identified.\n\
**Business Impact:** No direct business impact was identified because the scan did not emit any findings.\n\
**Proof of Concept:**\n\
No automated reproduction command generated. See vulnerable source lines above.\n\
**Suggested Mitigation:** No mitigation required.",
        );
    }

    reports.join("\n\n---\n\n")
}

fn proof_of_concept_section(findings: &[&StructuredFinding]) -> String {
    if let Some(repro_cmd) = findings
        .iter()
        .filter_map(|finding| finding.exploit_witness.as_ref())
        .filter_map(|witness| witness.repro_cmd.as_deref())
        .map(str::trim)
        .find(|cmd| !cmd.is_empty())
    {
        return format!("```text\n{repro_cmd}\n```");
    }
    "No automated reproduction command generated. See vulnerable source lines above.".to_string()
}

fn vrt_category(rule_id: &str) -> &'static str {
    if rule_id.contains("xss") {
        "Cross-Site Scripting (XSS) > DOM-Based"
    } else if rule_id.contains("credential")
        || rule_id.contains("secret")
        || rule_id.contains("hardcoded")
    {
        "Server Security Misconfiguration > Hardcoded Credentials"
    } else if rule_id.contains("command_injection") {
        "Server-Side Code Injection > OS Command Injection"
    } else if rule_id.contains("sql") {
        "SQL Injection"
    } else if rule_id.contains("ssrf") {
        "Server-Side Request Forgery (SSRF)"
    } else if rule_id.contains("path_traversal") || rule_id.contains("directory_traversal") {
        "Path Traversal"
    } else if rule_id.contains("template") || rule_id.contains("ssti") {
        "Server-Side Code Injection > Server-Side Template Injection"
    } else if rule_id.contains("deserialize") {
        "Insecure Deserialization"
    } else if rule_id.contains("idor") || rule_id.contains("auth") {
        "Broken Access Control"
    } else {
        "Informational"
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "KevCritical" => 6,
        "Exhaustion" => 5,
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn business_impact_statement(rule_id: &str, severity: Option<&str>) -> String {
    if rule_id.contains("credential") || rule_id.contains("secret") || rule_id.contains("hardcoded")
    {
        return String::from(
            "Embedded secrets can permit unauthorized access to internal systems, enable account takeover, and create durable compromise paths for an attacker.",
        );
    }
    if rule_id.contains("xss") {
        return String::from(
            "A DOM-based XSS sink can enable session theft, arbitrary action execution in a victim browser, and lateral compromise of privileged user workflows.",
        );
    }
    if rule_id.contains("command_injection") {
        return String::from(
            "Command injection sinks can yield direct remote code execution, host compromise, and rapid pivoting into adjacent infrastructure.",
        );
    }

    match severity {
        Some("KevCritical") | Some("Critical") => String::from(
            "The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows.",
        ),
        Some("High") => String::from(
            "The identified sinks can expose sensitive data or privileged functionality and materially increase the likelihood of exploitable compromise.",
        ),
        Some("Medium") | Some("Low") => String::from(
            "The identified sinks increase attack surface and can become exploitable when combined with reachable input control or adjacent weaknesses.",
        ),
        _ => String::from(
            "The identified sinks require manual triage to determine exploitability, but they represent concrete attack-surface expansion that warrants remediation.",
        ),
    }
}

fn suggested_mitigation(findings: &[&StructuredFinding]) -> String {
    let mut mitigations = findings
        .iter()
        .filter_map(|finding| finding.remediation.as_deref())
        .collect::<Vec<_>>();
    mitigations.sort_unstable();
    mitigations.dedup();

    if mitigations.is_empty() {
        String::from("Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.")
    } else {
        mitigations.join(" ")
    }
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
// Python wheel / egg ingestion  (Phase P1-2b)
// ---------------------------------------------------------------------------

/// Extract a Python `.whl` or `.egg` archive into a temporary directory, scan
/// the unpacked payload, and return findings.
fn ingest_whl(path: &Path, corpus_path: Option<&Path>) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open wheel archive {}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).context("failed to parse wheel/egg archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create wheel extraction tmpdir")?;

    let mut metadata_path: Option<PathBuf> = None;
    let mut entry_points_path: Option<PathBuf> = None;
    let mut script_paths = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("failed to read wheel entry {index}"))?;
        let entry_name = entry.name().replace('\\', "/");
        let Some(safe_rel) = sanitize_archive_entry_path(&entry_name) else {
            continue;
        };
        let dest = tmpdir.path().join(&safe_rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create wheel directory {}", dest.display()))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create wheel parent {}", parent.display()))?;
        }

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read wheel file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted wheel file {}", dest.display()))?;

        if entry_name.ends_with("/METADATA") {
            metadata_path = Some(dest.clone());
        } else if entry_name.ends_with("/entry_points.txt") {
            entry_points_path = Some(dest.clone());
        }

        let is_python_script = dest.extension().and_then(|ext| ext.to_str()) == Some("py")
            || buf.starts_with(b"#!/")
                && std::str::from_utf8(&buf[..buf.len().min(128)])
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains("python");
        if is_python_script {
            script_paths.push(dest);
        }
    }

    let mut findings = Vec::new();
    if let Some(metadata_path) = metadata_path.as_deref() {
        let metadata = std::fs::read_to_string(metadata_path)
            .with_context(|| format!("read wheel metadata {}", metadata_path.display()))?;
        if let Some(package_name) = parse_metadata_header(&metadata, "Name") {
            let artifact_label = path.display().to_string();
            if let Some(finding) = slopsquat_artifact_finding(
                &package_name,
                parse_metadata_header(&metadata, "Version").as_deref(),
                corpus_path,
                &artifact_label,
            ) {
                findings.push(finding);
            }
        }
    }

    if let Some(entry_points_path) = entry_points_path.as_deref() {
        let entry_points = std::fs::read_to_string(entry_points_path)
            .with_context(|| format!("read entry_points {}", entry_points_path.display()))?;
        for module in parse_entry_point_modules(&entry_points) {
            if let Some(module_path) = resolve_python_module_path(tmpdir.path(), &module) {
                findings.extend(scan_python_priority_file(
                    &module_path,
                    &relative_to_root(tmpdir.path(), &module_path),
                )?);
            }
        }
    }

    for script_path in &script_paths {
        findings.extend(scan_python_priority_file(
            script_path,
            &relative_to_root(tmpdir.path(), script_path),
        )?);
    }

    findings.extend(scan_directory(tmpdir.path())?);
    Ok(dedup_findings(findings))
}

/// Download a wheel from the official PyPI registry, extract it, and scan the
/// unpacked payload.
fn ingest_pypi(pkg: &str, corpus_path: Option<&Path>) -> anyhow::Result<Vec<StructuredFinding>> {
    let (name, version) = parse_pypi_spec(pkg);
    let version_opt = (!version.is_empty()).then_some(version);
    if let Some(finding) = slopsquat_artifact_finding(name, version_opt, corpus_path, pkg) {
        let mut findings = vec![finding];
        let downloaded = ingest_pypi_download(name, version, corpus_path)?;
        findings.extend(downloaded);
        return Ok(dedup_findings(findings));
    }
    ingest_pypi_download(name, version, corpus_path)
}

fn ingest_pypi_download(
    name: &str,
    version: &str,
    corpus_path: Option<&Path>,
) -> anyhow::Result<Vec<StructuredFinding>> {
    let meta_url = if version.is_empty() {
        format!("https://pypi.org/pypi/{name}/json")
    } else {
        format!("https://pypi.org/pypi/{name}/{version}/json")
    };
    let agent = ureq::Agent::new_with_defaults();
    let meta: serde_json::Value = agent
        .get(&meta_url)
        .call()
        .map_err(|_| anyhow::anyhow!("PyPI metadata fetch failed for {pkg}", pkg = name))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("PyPI metadata response is not valid JSON")?;

    let urls = meta["urls"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("PyPI metadata missing 'urls' array"))?;
    let wheel_url = urls
        .iter()
        .find(|entry| entry["packagetype"].as_str() == Some("bdist_wheel"))
        .or_else(|| {
            urls.iter().find(|entry| {
                entry["filename"]
                    .as_str()
                    .is_some_and(|filename| filename.ends_with(".egg"))
            })
        })
        .and_then(|entry| entry["url"].as_str())
        .ok_or_else(|| anyhow::anyhow!("PyPI artifact set contains no wheel or egg"))?;

    let mut response = agent
        .get(wheel_url)
        .call()
        .map_err(|_| anyhow::anyhow!("PyPI artifact download failed for {name}"))?;
    let tmpdir = tempfile::TempDir::new().context("failed to create PyPI download tmpdir")?;
    let filename = urls
        .iter()
        .find_map(|entry| {
            let url = entry["url"].as_str()?;
            (url == wheel_url)
                .then(|| entry["filename"].as_str())
                .flatten()
        })
        .unwrap_or("package.whl");
    let artifact_path = tmpdir.path().join(filename);
    let mut bytes = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit(PYPI_BODY_LIMIT)
        .reader()
        .read_to_end(&mut bytes)
        .context("failed to read PyPI artifact body")?;
    std::fs::write(&artifact_path, &bytes)
        .with_context(|| format!("write downloaded PyPI artifact {}", artifact_path.display()))?;
    ingest_whl(&artifact_path, corpus_path)
}

fn parse_pypi_spec(pkg: &str) -> (&str, &str) {
    if let Some(at) = pkg.rfind('@') {
        (&pkg[..at], &pkg[at + 1..])
    } else {
        (pkg, "")
    }
}

fn parse_metadata_header(metadata: &str, key: &str) -> Option<String> {
    metadata.lines().find_map(|line| {
        let (left, right) = line.split_once(':')?;
        (left.trim().eq_ignore_ascii_case(key)).then(|| right.trim().to_string())
    })
}

fn parse_entry_point_modules(entry_points: &str) -> Vec<String> {
    entry_points
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('[') || trimmed.starts_with('#') {
                return None;
            }
            let (_, target) = trimmed.split_once('=')?;
            let module = target.trim().split(':').next()?.trim();
            (!module.is_empty()).then(|| module.to_string())
        })
        .collect()
}

fn resolve_python_module_path(root: &Path, module: &str) -> Option<PathBuf> {
    let module_rel = module.replace('.', "/");
    let file_path = root.join(format!("{module_rel}.py"));
    if file_path.exists() {
        return Some(file_path);
    }
    let init_path = root.join(module_rel).join("__init__.py");
    init_path.exists().then_some(init_path)
}

fn scan_python_priority_file(path: &Path, label: &str) -> anyhow::Result<Vec<StructuredFinding>> {
    let source =
        std::fs::read(path).with_context(|| format!("read python file {}", path.display()))?;
    Ok(scan_buffer("py", &source, label, &[]))
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

    // Apply layers in order. Whiteout handling is intentionally omitted in
    // this first iteration so the pipeline can focus on simple layer extraction.
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
// IPA ingestion  (Phase P1-2c)
// ---------------------------------------------------------------------------

/// Extract an iOS `.ipa` bundle into a `tempfile::TempDir`, parse the app
/// `Info.plist` when present, scan the extracted app tree, and return findings.
fn ingest_ipa(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open IPA archive {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("failed to parse IPA archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create IPA extraction tmpdir")?;

    let mut app_root: Option<std::path::PathBuf> = None;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("failed to read IPA entry {i}"))?;
        let entry_name = entry.name().replace('\\', "/");
        if !entry_name.starts_with("Payload/") {
            continue;
        }
        let Some(safe_rel) = sanitize_archive_entry_path(&entry_name) else {
            continue;
        };
        if app_root.is_none() {
            let components = safe_rel.components().collect::<Vec<_>>();
            if components.len() >= 2 {
                let root =
                    components[..2]
                        .iter()
                        .fold(std::path::PathBuf::new(), |mut acc, component| {
                            acc.push(component.as_os_str());
                            acc
                        });
                app_root = Some(tmpdir.path().join(root));
            }
        }

        let dest = tmpdir.path().join(&safe_rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create IPA directory {}", dest.display()))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create IPA parent {}", parent.display()))?;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read IPA file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted IPA file {}", dest.display()))?;
    }

    let scan_root = app_root
        .filter(|root| root.exists())
        .unwrap_or_else(|| tmpdir.path().to_path_buf());
    let info_plist = scan_root.join("Info.plist");
    if info_plist.exists() {
        let _: plist::Value = plist::Value::from_file(&info_plist)
            .with_context(|| format!("failed to parse IPA Info.plist {}", info_plist.display()))?;
    }

    scan_directory(&scan_root)
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

fn is_placeholder_scan_root(scan_root: Option<&Path>, has_explicit_ingest_source: bool) -> bool {
    has_explicit_ingest_source && scan_root == Some(Path::new("."))
}

// ---------------------------------------------------------------------------
// Directory walker (shared by all ingestion paths)
// ---------------------------------------------------------------------------

/// Walk `dir` recursively, run all detectors on every file, and return the
/// unified finding list.  Files > 1 MiB and unreadable files are silently
/// skipped.
fn scan_directory(dir: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let mut all: Vec<StructuredFinding> = Vec::new();
    let mut frontend_routes = Vec::new();

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
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "js" | "jsx" | "ts" | "tsx") {
            continue;
        }
        let source = match std::fs::read(file_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();
        frontend_routes.extend(forge::authz::extract_frontend_routes_from_source(
            ext, &source, rel_path,
        ));
    }

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

        all.extend(scan_buffer(ext, &source, &rel_path, &frontend_routes));
    }

    Ok(dedup_findings(all))
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

fn scan_buffer(
    ext: &str,
    source: &[u8],
    label: &str,
    frontend_routes: &[forge::authz::FrontendRoute],
) -> Vec<StructuredFinding> {
    let unit = ParsedUnit::unparsed(source);
    let mut findings = find_slop(ext, &unit)
        .into_iter()
        .map(|finding| {
            let line = byte_to_line(source, finding.start_byte);
            let rule_id = extract_rule_id(&finding.description);
            let mut structured = StructuredFinding {
                id: rule_id.clone(),
                file: Some(label.to_string()),
                line: Some(line),
                fingerprint: fingerprint_finding(source, finding.start_byte, finding.end_byte),
                severity: Some(format!("{:?}", finding.severity)),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
            };
            if rule_id == "security:dom_xss_innerHTML" || rule_id.contains("prototype_pollution") {
                let mut witness =
                    forge::exploitability::browser_sink_witness(label, &rule_id, line);
                if let Some(route) =
                    forge::authz::match_frontend_route_for_file(frontend_routes, label)
                {
                    witness.route_path = Some(route.route_path.clone());
                }
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            }
            structured
        })
        .collect::<Vec<_>>();
    findings.extend(forge::idor::scan_source(ext, source, label));
    findings
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

fn relative_to_root(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn dedup_findings(findings: Vec<StructuredFinding>) -> Vec<StructuredFinding> {
    let mut deduped = Vec::with_capacity(findings.len());
    let mut seen = std::collections::BTreeSet::new();
    for finding in findings {
        let key = (
            finding.id.clone(),
            finding.file.clone().unwrap_or_default(),
            finding.line.unwrap_or_default(),
            finding.fingerprint.clone(),
        );
        if seen.insert(key) {
            deduped.push(finding);
        }
    }
    deduped
}

fn slopsquat_artifact_finding(
    package_name: &str,
    version: Option<&str>,
    corpus_path: Option<&Path>,
    artifact_label: &str,
) -> Option<StructuredFinding> {
    let normalized = normalize_package_name(package_name);
    if normalized.is_empty() {
        return None;
    }
    let corpus = load_effective_slopsquat_corpus(corpus_path).ok()?;
    let mut matched: Option<(&str, bool)> = None;
    for known in &corpus.package_names {
        let known_normalized = normalize_package_name(known);
        if known_normalized == normalized {
            matched = Some((known.as_str(), true));
            break;
        }
        if bounded_levenshtein(&normalized, &known_normalized, 1).is_some() {
            matched = Some((known.as_str(), false));
            break;
        }
    }
    let (matched_name, exact) = matched?;
    let version_suffix = version
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("@{value}"))
        .unwrap_or_default();
    let relation = if exact {
        "matches"
    } else {
        "is a one-edit near miss of"
    };
    Some(StructuredFinding {
        id: "security:slopsquat_injection".to_string(),
        file: Some(artifact_label.to_string()),
        line: Some(1),
        fingerprint: blake3::hash(format!("{normalized}:{matched_name}").as_bytes())
            .to_hex()
            .to_string(),
        severity: Some("Critical".to_string()),
        remediation: Some(format!(
            "PyPI artifact `{package_name}{version_suffix}` {relation} slopsquat corpus entry `{matched_name}`. Reject the artifact, verify provenance, and require an explicitly reviewed package allowlist before ingestion."
        )),
        docs_url: None,
        exploit_witness: None,
    })
}

fn load_effective_slopsquat_corpus(corpus_path: Option<&Path>) -> anyhow::Result<SlopsquatCorpus> {
    if let Some(path) = corpus_path {
        if let Some(corpus) = common::wisdom::load_slopsquat_corpus(path) {
            return Ok(corpus);
        }
        anyhow::bail!("failed to load slopsquat corpus from {}", path.display());
    }

    let archived = rkyv::access::<ArchivedSlopsquatCorpus, rkyv::rancor::Error>(EMBEDDED_SLOPSQUAT)
        .context("embedded slopsquat corpus is corrupt")?;
    rkyv::deserialize::<SlopsquatCorpus, rkyv::rancor::Error>(archived)
        .context("embedded slopsquat corpus failed to deserialize")
}

fn normalize_package_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn bounded_levenshtein(left: &str, right: &str, max_distance: usize) -> Option<usize> {
    if left == right {
        return Some(0);
    }
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let length_delta = left_chars.len().abs_diff(right_chars.len());
    if length_delta > max_distance {
        return None;
    }

    let mut prev = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; right_chars.len() + 1];
    for (i, left_char) in left_chars.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];
        for (j, right_char) in right_chars.iter().enumerate() {
            let substitution = usize::from(left_char != right_char);
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + substitution);
            row_min = row_min.min(curr[j + 1]);
        }
        if row_min > max_distance {
            return None;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    (prev[right_chars.len()] <= max_distance).then_some(prev[right_chars.len()])
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

    #[test]
    fn placeholder_scan_root_is_ignored_when_explicit_source_present() {
        assert!(is_placeholder_scan_root(Some(Path::new(".")), true));
        assert!(!is_placeholder_scan_root(Some(Path::new(".")), false));
        assert!(!is_placeholder_scan_root(Some(Path::new("./target")), true));
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

    fn build_whl(metadata_name: &str, python_source: &[u8]) -> tempfile::TempDir {
        let tmp = tempfile::TempDir::new().unwrap();
        let whl_path = tmp.path().join("sample.whl");
        let file = std::fs::File::create(&whl_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("pkg/__init__.py", options).unwrap();
        zip.write_all(python_source).unwrap();
        zip.start_file("demo-1.0.0.dist-info/METADATA", options)
            .unwrap();
        zip.write_all(
            format!("Metadata-Version: 2.1\nName: {metadata_name}\nVersion: 1.0.0\n").as_bytes(),
        )
        .unwrap();
        zip.start_file("demo-1.0.0.dist-info/entry_points.txt", options)
            .unwrap();
        zip.write_all(b"[console_scripts]\ndemo = pkg:main\n")
            .unwrap();
        zip.start_file("demo-1.0.0.data/scripts/demo", options)
            .unwrap();
        zip.write_all(b"#!/usr/bin/env python3\nfrom pkg import main\nmain()\n")
            .unwrap();
        zip.finish().unwrap();
        tmp
    }

    #[test]
    fn wheel_ingest_flags_slopsquat_package_name_immediately() {
        let wheel = build_whl("djago", b"def main():\n    return 0\n");
        let corpus_dir = tempfile::TempDir::new().unwrap();
        let corpus_path = corpus_dir.path().join("slopsquat_corpus.rkyv");
        let corpus = common::wisdom::SlopsquatCorpus {
            package_names: vec!["djago".to_string()],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus).unwrap();
        std::fs::write(&corpus_path, bytes.as_slice()).unwrap();

        let findings = ingest_whl(&wheel.path().join("sample.whl"), Some(&corpus_path)).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "security:slopsquat_injection"),
            "wheel metadata name in the slopsquat corpus must trigger an immediate Critical finding"
        );
    }

    #[test]
    fn wheel_ingest_surfaces_idor_in_extracted_python_handler() {
        let wheel = build_whl(
            "safe-demo",
            br#"
@app.get("/users/<int:user_id>")
def main(user_id):
    record = db.session.query(User).filter_by(id=user_id).first()
    return jsonify(record)
"#,
        );
        let findings = ingest_whl(&wheel.path().join("sample.whl"), None).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "security:missing_ownership_check"),
            "wheel-extracted python route without an ownership check must trigger the IDOR detector"
        );
    }

    #[test]
    fn bugcrowd_formatter_emits_required_headers() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("static/app.js".to_string()),
            line: Some(42),
            fingerprint: "abc123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some(
                "Replace innerHTML with textContent or a vetted sanitizer.".to_string(),
            ),
            docs_url: None,
            exploit_witness: None,
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(report.contains(
            "**Summary Title:** Multiple instances of security:dom_xss_innerHTML in target"
        ));
        assert!(report.contains("**VRT Category:**"));
        assert!(report.contains("**Vulnerability Details:**"));
        assert!(report.contains("**Business Impact:**"));
        assert!(report.contains("**Proof of Concept:**"));
        assert!(report.contains(
            "No automated reproduction command generated. See vulnerable source lines above."
        ));
        assert!(report.contains(
            "**Suggested Mitigation:** Replace innerHTML with textContent or a vetted sanitizer."
        ));
    }

    #[test]
    fn bugcrowd_formatter_injects_exploit_witness_repro_into_poc() {
        let finding = StructuredFinding {
            id: "security:unsafe_deserialization".to_string(),
            file: Some("api/handler.py".to_string()),
            line: Some(17),
            fingerprint: "deser123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some("Replace `pickle.loads` with a safe codec.".to_string()),
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "handler".to_string(),
                source_label: "param:data".to_string(),
                sink_function: "pickle.loads".to_string(),
                sink_label: "sink:unsafe_deserialization".to_string(),
                call_chain: vec!["handler".to_string(), "pickle.loads".to_string()],
                repro_cmd: Some(
                    "python3 -c \"import base64,pickle; pickle.loads(base64.b64decode('Y29zCnN5c3RlbQooUydlY2hvIEpBTklUT1JfUFJPQkUnCnRSLg=='))\""
                        .to_string(),
                ),
                route_path: None,
                http_method: None,
                auth_requirement: None,
            }),
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(report.contains("**Proof of Concept:**\n```text"));
        assert!(report.contains("pickle.loads(base64.b64decode"));
        assert!(!report.contains(
            "No automated reproduction command generated. See vulnerable source lines above."
        ));
    }

    #[test]
    fn bugcrowd_filter_can_reduce_findings_before_rendering() {
        let findings = vec![
            StructuredFinding {
                id: "security:dom_xss_innerHTML".to_string(),
                file: Some("captcha.js".to_string()),
                line: Some(46),
                fingerprint: "xss1".to_string(),
                severity: Some("Critical".to_string()),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
            },
            StructuredFinding {
                id: "security:hardcoded_secret".to_string(),
                file: Some("config.js".to_string()),
                line: Some(7),
                fingerprint: "secret1".to_string(),
                severity: Some("Critical".to_string()),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
            },
        ];

        let filtered = apply_jaq_filter(
            ".[] | select(.id == \"security:dom_xss_innerHTML\")",
            serde_json::to_value(&findings).unwrap(),
        )
        .unwrap();
        let filtered_findings: Vec<StructuredFinding> = serde_json::from_value(filtered).unwrap();
        let report = format_bugcrowd_report(&filtered_findings);

        assert!(report.contains("security:dom_xss_innerHTML"));
        assert!(!report.contains("security:hardcoded_secret"));
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
    // IPA extraction round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn ipa_ingest_extracts_payload_and_scans_web_bundle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ipa_path = tmp.path().join("sample.ipa");
        let file = std::fs::File::create(&ipa_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();

        zip.add_directory("Payload/Demo.app/", options).unwrap();
        zip.start_file("Payload/Demo.app/Info.plist", options)
            .unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.demo</string>
</dict>
</plist>"#,
        )
        .unwrap();
        zip.start_file("Payload/Demo.app/www/app.js", options)
            .unwrap();
        zip.write_all(b"const key = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n")
            .unwrap();
        zip.finish().unwrap();

        let findings = ingest_ipa(&ipa_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "IPA-extracted web bundle with AWS key must produce a credential finding"
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
