//! Deterministic, bounded payload normalization for staged exploit strings.
//!
//! This module intentionally handles only small, local transforms used by
//! obfuscated sink payloads: wrapped base64 decoders, concatenated string
//! literals, hex strings, and simple hex byte arrays. All transforms are capped
//! at 4 KiB to preserve the Janitor's bounded-memory hot path.

use base64::Engine as _;

/// Maximum decoded payload size admitted by the deobfuscation spine.
pub const MAX_NORMALIZED_BYTES: usize = 4096;

/// Return `true` when `bytes` begins with a Windows PE (`MZ`) or ELF binary magic signature.
///
/// Used by the Steganographic Shield to flag compiled executables smuggled inside
/// base64/hex-encoded string literals.
pub fn is_binary_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7FELF")
}

/// Normalize a staged payload into its bounded decoded form.
///
/// Recognized forms:
/// - quoted base64 strings
/// - `atob("...")`, `b64decode("...")`, `base64.b64decode("...")`
/// - concatenated string literals such as `"YWJj" + "ZA=="`
/// - hex strings such as `"636f6465"`
/// - hex byte arrays such as `[0x63, 0x6f, 0x64, 0x65]`
///
/// Returns `None` when the input is too large, unsupported, or does not
/// normalize into a materially different bounded payload.
pub fn normalize_payload(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() > MAX_NORMALIZED_BYTES {
        return None;
    }

    let trimmed = trim_ascii(raw);
    if trimmed.is_empty() || trimmed.len() > MAX_NORMALIZED_BYTES {
        return None;
    }

    if let Some(inner) = unwrap_decoder_call(trimmed) {
        return normalize_payload(inner);
    }

    if let Some(concat) = join_string_literals(trimmed) {
        return normalize_scalar_bytes(&concat);
    }

    normalize_scalar_bytes(trimmed)
}

fn normalize_scalar_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    let scalar = strip_quotes(trim_ascii(raw));
    if scalar.is_empty() || scalar.len() > MAX_NORMALIZED_BYTES {
        return None;
    }

    if let Some(decoded) = decode_base64_scalar(scalar) {
        return Some(decoded);
    }

    if let Some(decoded) = decode_hex_scalar(scalar) {
        return Some(decoded);
    }

    if let Some(decoded) = decode_hex_array(trim_ascii(raw)) {
        return Some(decoded);
    }

    if scalar != raw {
        return Some(scalar.to_vec());
    }

    None
}

fn unwrap_decoder_call(raw: &[u8]) -> Option<&[u8]> {
    for prefix in [b"atob(".as_slice(), b"b64decode(", b"base64.b64decode("] {
        if raw.starts_with(prefix) && raw.ends_with(b")") {
            let inner = &raw[prefix.len()..raw.len() - 1];
            return first_argument(inner);
        }
    }
    None
}

fn first_argument(raw: &[u8]) -> Option<&[u8]> {
    let mut depth = 0_u32;
    let mut quote = None;
    for (idx, byte) in raw.iter().enumerate() {
        match (quote, *byte) {
            (Some(q), b) if b == q && raw.get(idx.wrapping_sub(1)) != Some(&b'\\') => quote = None,
            (Some(_), _) => {}
            (None, b) if matches!(b, b'\'' | b'"' | b'`') => quote = Some(b),
            (None, b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            (None, b')' | b']' | b'}') => depth = depth.saturating_sub(1),
            (None, b',') if depth == 0 => return Some(trim_ascii(&raw[..idx])),
            _ => {}
        }
    }
    Some(trim_ascii(raw))
}

fn join_string_literals(raw: &[u8]) -> Option<Vec<u8>> {
    let mut idx = 0usize;
    let mut out = Vec::new();
    let mut saw_literal = false;

    while idx < raw.len() {
        idx += raw[idx..]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(raw.len() - idx);
        if idx >= raw.len() {
            break;
        }

        let quote = raw[idx];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            return None;
        }
        idx += 1;
        let start = idx;
        while idx < raw.len() {
            if raw[idx] == quote && raw.get(idx.wrapping_sub(1)) != Some(&b'\\') {
                out.extend_from_slice(&raw[start..idx]);
                idx += 1;
                saw_literal = true;
                break;
            }
            idx += 1;
        }
        if !saw_literal || out.len() > MAX_NORMALIZED_BYTES {
            return None;
        }

        idx += raw[idx..]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(raw.len() - idx);
        if idx >= raw.len() {
            break;
        }
        if raw[idx] != b'+' {
            return None;
        }
        idx += 1;
    }

    saw_literal.then_some(out)
}

fn decode_base64_scalar(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 8 || raw.len() > MAX_NORMALIZED_BYTES {
        return None;
    }
    if raw
        .iter()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')))
    {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(raw).ok())?;
    if decoded.is_empty() || decoded.len() > MAX_NORMALIZED_BYTES {
        return None;
    }
    Some(decoded)
}

fn decode_hex_scalar(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 4 || !raw.len().is_multiple_of(2) || raw.len() > MAX_NORMALIZED_BYTES * 2 {
        return None;
    }
    if !raw.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut idx = 0usize;
    while idx < raw.len() {
        out.push((hex_nibble(raw[idx])? << 4) | hex_nibble(raw[idx + 1])?);
        idx += 2;
    }
    Some(out)
}

fn decode_hex_array(raw: &[u8]) -> Option<Vec<u8>> {
    let raw = strip_brackets(trim_ascii(raw))?;
    let mut out = Vec::new();
    for part in raw.split(|b| *b == b',') {
        let token = trim_ascii(part);
        let token = token
            .strip_prefix(b"0x")
            .or_else(|| token.strip_prefix(b"0X"))?;
        if token.len() != 2 || out.len() >= MAX_NORMALIZED_BYTES {
            return None;
        }
        out.push((hex_nibble(token[0])? << 4) | hex_nibble(token[1])?);
    }
    (!out.is_empty()).then_some(out)
}

fn strip_brackets(raw: &[u8]) -> Option<&[u8]> {
    if raw.starts_with(b"[") && raw.ends_with(b"]") && raw.len() >= 2 {
        Some(trim_ascii(&raw[1..raw.len() - 1]))
    } else {
        None
    }
}

fn strip_quotes(raw: &[u8]) -> &[u8] {
    if raw.len() >= 2 {
        let first = raw[0];
        let last = raw[raw.len() - 1];
        if matches!(first, b'\'' | b'"' | b'`') && first == last {
            return &raw[1..raw.len() - 1];
        }
    }
    raw
}

fn trim_ascii(raw: &[u8]) -> &[u8] {
    let start = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &raw[start..end]
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_payload;

    #[test]
    fn decodes_wrapped_base64_payload() {
        let decoded = normalize_payload(br#"atob("Y29uc29sZS5sb2coJ2hhY2tlZCcp")"#).unwrap();
        assert_eq!(decoded, b"console.log('hacked')");
    }

    #[test]
    fn joins_concatenated_literals_before_decoding() {
        let decoded = normalize_payload(br#""Y29u" + "c29sZS5sb2coJ2hhY2tlZCcp""#).unwrap();
        assert_eq!(decoded, b"console.log('hacked')");
    }

    #[test]
    fn decodes_hex_arrays() {
        let decoded = normalize_payload(br#"[0x63, 0x6f, 0x64, 0x65]"#).unwrap();
        assert_eq!(decoded, b"code");
    }

    #[test]
    fn is_binary_magic_detects_pe_header() {
        assert!(super::is_binary_magic(b"MZ\x90\x00\x03\x00\x00\x00"));
    }

    #[test]
    fn is_binary_magic_detects_elf_header() {
        assert!(super::is_binary_magic(b"\x7FELF\x02\x01\x01\x00"));
    }

    #[test]
    fn is_binary_magic_rejects_plain_text() {
        assert!(!super::is_binary_magic(b"console.log('hello')"));
    }
}
