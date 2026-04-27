//! Compiled artifact triage for native import tables.
//!
//! This lane uses `goblin` to parse ELF, PE, and Mach-O binaries without
//! executing them. It emits structured findings when import tables reference
//! native APIs that commonly bridge attacker-controlled data into process
//! execution or memory corruption sinks.

use common::slop::StructuredFinding;
use goblin::Object;

const DANGEROUS_NATIVE_SINKS: &[&str] = &[
    "system",
    "execve",
    "popen",
    "strcpy",
    "gets",
    "LoadLibraryA",
    "WinExec",
];

/// Analyze a compiled artifact for dangerous operating-system level imports.
///
/// Supports ELF, PE, and Mach-O objects through `goblin::Object::parse`.
/// Unsupported or malformed inputs fail closed to an empty finding set.
pub fn analyze_binary(bytes: &[u8], file_name: &str) -> Vec<StructuredFinding> {
    let mut imports = Vec::new();
    let Ok(object) = Object::parse(bytes) else {
        return Vec::new();
    };

    match object {
        Object::Elf(elf) => {
            for symbol in elf.dynsyms.iter().filter(|symbol| symbol.st_shndx == 0) {
                if let Some(name) = elf.dynstrtab.get_at(symbol.st_name) {
                    imports.push(name.to_string());
                }
            }
        }
        Object::PE(pe) => {
            for import in pe.imports {
                imports.push(import.name.to_string());
            }
        }
        Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => {
                collect_macho_imports(&macho, &mut imports);
            }
            goblin::mach::Mach::Fat(fat) => {
                for arch in fat.iter_arches().flatten() {
                    let arch_bytes = arch.slice(bytes);
                    if let Ok(macho) = goblin::mach::MachO::parse(arch_bytes, 0) {
                        collect_macho_imports(&macho, &mut imports);
                    }
                }
            }
        },
        Object::Archive(_) | Object::Unknown(_) => {}
        #[allow(unreachable_patterns)]
        _ => {}
    }

    dangerous_import_findings(imports.iter().map(String::as_str), file_name)
}

fn collect_macho_imports(macho: &goblin::mach::MachO<'_>, imports: &mut Vec<String>) {
    if let Ok(macho_imports) = macho.imports() {
        imports.extend(
            macho_imports
                .into_iter()
                .map(|import| import.name.to_string()),
        );
    }
}

fn dangerous_import_findings<'a>(
    imports: impl IntoIterator<Item = &'a str>,
    file_name: &str,
) -> Vec<StructuredFinding> {
    imports
        .into_iter()
        .filter_map(|import| {
            let sink = dangerous_sink_for_import(import)?;
            let fingerprint_material = format!("{file_name}:{sink}:{import}");
            Some(StructuredFinding {
                id: "security:dangerous_native_import".to_string(),
                file: Some(file_name.to_string()),
                line: None,
                fingerprint: blake3::hash(fingerprint_material.as_bytes())
                    .to_hex()
                    .to_string(),
                severity: Some("Critical".to_string()),
                remediation: Some(format!(
                    "Compiled artifact imports dangerous native sink `{sink}` via symbol `{import}`. Audit the call path, constrain attacker-controlled input, and replace the sink with a bounded API."
                )),
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent: false,
                ..Default::default()
            })
        })
        .collect()
}

fn dangerous_sink_for_import(import: &str) -> Option<&'static str> {
    let normalized = normalize_import_symbol(import);
    DANGEROUS_NATIVE_SINKS
        .iter()
        .copied()
        .find(|sink| normalized.eq_ignore_ascii_case(sink))
}

fn normalize_import_symbol(import: &str) -> &str {
    let thunk_stripped = import
        .strip_prefix("__imp_")
        .or_else(|| import.strip_prefix("_imp_"))
        .unwrap_or(import);
    let trimmed = thunk_stripped.trim_start_matches('_');
    let version_stripped = trimmed.split('@').next().unwrap_or(trimmed);
    version_stripped
        .split('$')
        .next()
        .unwrap_or(version_stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_matching_flags_dangerous_native_sinks() {
        let findings = dangerous_import_findings(
            [
                "__imp_LoadLibraryA",
                "_system",
                "memcpy",
                "execve@GLIBC_2.2.5",
            ],
            "bin/plugin.so",
        );

        assert_eq!(findings.len(), 3);
        assert!(findings
            .iter()
            .all(|finding| finding.id == "security:dangerous_native_import"));
        assert!(findings
            .iter()
            .all(|finding| finding.severity.as_deref() == Some("Critical")));
        assert!(findings.iter().any(|finding| finding
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("LoadLibraryA")));
        assert!(findings.iter().any(|finding| finding
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("system")));
        assert!(findings.iter().any(|finding| finding
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("execve")));
    }

    #[test]
    fn malformed_binary_returns_no_findings() {
        assert!(analyze_binary(b"not-a-native-object", "blob.bin").is_empty());
    }

    #[test]
    fn strcpy_import_triggers_dangerous_native_import_finding() {
        // Validates that the classic buffer-overflow sink `strcpy` is flagged at
        // Critical severity when extracted from a binary import table.
        let findings = dangerous_import_findings(["strcpy"], "lib/target.so");
        assert_eq!(findings.len(), 1, "strcpy must produce exactly one finding");
        assert_eq!(findings[0].id, "security:dangerous_native_import");
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("Critical"),
            "strcpy import must be Critical severity"
        );
        assert!(
            findings[0]
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("strcpy"),
            "remediation message must name the dangerous sink"
        );
    }
}
