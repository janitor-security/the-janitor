use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Provenance {
    analysis_duration_ms: u64,
    source_bytes_processed: u64,
    egress_bytes_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BounceLogEntry {
    #[serde(default)]
    pr_number: Option<u64>,
    #[serde(default)]
    author: Option<String>,
    timestamp: String,
    slop_score: u32,
    dead_symbols_added: u32,
    logic_clones_found: u32,
    zombie_symbols_added: u32,
    #[serde(default)]
    unlinked_pr: u32,
    #[serde(default)]
    antipatterns: Vec<String>,
    #[serde(default)]
    comment_violations: Vec<String>,
    #[serde(default)]
    min_hashes: Vec<u64>,
    #[serde(default)]
    zombie_deps: Vec<String>,
    #[serde(default)]
    state: String,
    #[serde(default)]
    is_bot: bool,
    #[serde(default)]
    repo_slug: String,
    #[serde(default)]
    suppressed_by_domain: u32,
    #[serde(default)]
    collided_pr_numbers: Vec<u32>,
    #[serde(default)]
    necrotic_flag: Option<String>,
    #[serde(default)]
    commit_sha: String,
    #[serde(default)]
    policy_hash: String,
    #[serde(default)]
    version_silos: Vec<String>,
    #[serde(default)]
    agentic_pct: f64,
    #[serde(default)]
    ci_energy_saved_kwh: f64,
    #[serde(default)]
    provenance: Provenance,
    #[serde(default)]
    governor_status: Option<String>,
    #[serde(default)]
    pqc_sig: Option<String>,
    #[serde(default)]
    pqc_slh_sig: Option<String>,
    #[serde(default)]
    transparency_log: Option<InclusionProof>,
    #[serde(default)]
    cognition_surrender_index: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InclusionProof {
    sequence_index: u64,
    chained_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisTokenRequest {
    repo: String,
    pr: u64,
    head_sha: String,
    #[serde(default)]
    installation_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisTokenResponse<'a> {
    token: &'a str,
    mode: &'a str,
    expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum GovLogEvent {
    Report {
        entry: Box<BounceLogEntry>,
        inclusion_proof: InclusionProof,
    },
    AnalysisToken {
        request: AnalysisTokenRequest,
    },
}

#[derive(Debug, Default)]
struct Blake3HashChain {
    last_hash: [u8; 32],
    next_index: u64,
}

impl Blake3HashChain {
    fn append(&mut self, new_cbom_signature: &str) -> InclusionProof {
        let mut payload = Vec::with_capacity(self.last_hash.len() + new_cbom_signature.len());
        payload.extend_from_slice(&self.last_hash);
        payload.extend_from_slice(new_cbom_signature.as_bytes());
        let digest = blake3::hash(&payload);
        self.last_hash = *digest.as_bytes();
        let proof = InclusionProof {
            sequence_index: self.next_index,
            chained_hash: digest.to_hex().to_string(),
        };
        self.next_index = self.next_index.saturating_add(1);
        proof
    }
}

fn transparency_log() -> &'static Mutex<Blake3HashChain> {
    static LOG: OnceLock<Mutex<Blake3HashChain>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Blake3HashChain::default()))
}

fn main() -> anyhow::Result<()> {
    let bind_addr = resolve_bind_addr();
    let listener = TcpListener::bind(&bind_addr)
        .with_context(|| format!("binding janitor-gov to {bind_addr}"))?;
    eprintln!("janitor-gov listening on http://{bind_addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| {
                    if let Err(err) = handle_connection(stream) {
                        eprintln!("janitor-gov request failed: {err}");
                    }
                });
            }
            Err(err) => eprintln!("janitor-gov accept failed: {err}"),
        }
    }

    Ok(())
}

fn resolve_bind_addr() -> String {
    if let Ok(addr) = std::env::var("JANITOR_GOV_ADDR") {
        let trimmed = addr.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let port = std::env::var("JANITOR_GOV_PORT")
        .ok()
        .or_else(|| std::env::var("PORT").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "3000".to_string());
    format!("127.0.0.1:{port}")
}

fn handle_connection(mut stream: TcpStream) -> anyhow::Result<()> {
    let request = read_http_request(&mut stream)?;
    let response = route_request(&request);
    write_http_response(&mut stream, response.status, &response.body)?;
    Ok(())
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("reading request line")?;
    if request_line.trim().is_empty() {
        anyhow::bail!("empty request line");
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        anyhow::bail!("malformed request line");
    }

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).context("reading header")?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; content_length];
    reader
        .read_exact(&mut body)
        .context("reading request body")?;

    Ok(HttpRequest { method, path, body })
}

fn route_request(request: &HttpRequest) -> HttpResponse {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/report") => match serde_json::from_slice::<BounceLogEntry>(&request.body) {
            Ok(entry) => {
                let signature_material = report_signature_material(&entry);
                let proof = match transparency_log().lock() {
                    Ok(mut chain) => chain.append(&signature_material),
                    Err(err) => {
                        return json_response(
                            500,
                            serde_json::json!({
                                "error": format!("transparency log poisoned: {err}"),
                            }),
                        )
                    }
                };
                emit_event(&GovLogEvent::Report {
                    entry: Box::new(entry),
                    inclusion_proof: proof.clone(),
                });
                json_response(
                    200,
                    serde_json::json!({
                        "status": "accepted",
                        "mode": "stub",
                        "inclusion_proof": proof,
                    }),
                )
            }
            Err(err) => json_response(
                400,
                serde_json::json!({
                    "error": format!("invalid report payload: {err}"),
                }),
            ),
        },
        ("POST", "/v1/analysis-token") => {
            match serde_json::from_slice::<AnalysisTokenRequest>(&request.body) {
                Ok(req) => {
                    emit_event(&GovLogEvent::AnalysisToken { request: req });
                    json_response(
                        200,
                        serde_json::to_value(AnalysisTokenResponse {
                            token: "stub-analysis-token",
                            mode: "stub",
                            expires_in_secs: 300,
                        })
                        .unwrap_or_else(|_| {
                            serde_json::json!({
                                "token": "stub-analysis-token",
                                "mode": "stub",
                                "expires_in_secs": 300_u64,
                            })
                        }),
                    )
                }
                Err(err) => json_response(
                    400,
                    serde_json::json!({
                        "error": format!("invalid analysis-token payload: {err}"),
                    }),
                ),
            }
        }
        _ => json_response(
            404,
            serde_json::json!({
                "error": "not found",
            }),
        ),
    }
}

fn emit_event(event: &GovLogEvent) {
    match serde_json::to_string(event) {
        Ok(line) => println!("{line}"),
        Err(err) => eprintln!("janitor-gov serialization failed: {err}"),
    }
}

fn report_signature_material(entry: &BounceLogEntry) -> String {
    let mut parts = Vec::new();
    if let Some(sig) = entry.pqc_sig.as_deref() {
        parts.push(sig);
    }
    if let Some(sig) = entry.pqc_slh_sig.as_deref() {
        parts.push(sig);
    }
    parts.join("|")
}

fn json_response(status: u16, value: serde_json::Value) -> HttpResponse {
    let body =
        serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    HttpResponse { status, body }
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .context("writing response header")?;
    stream.write_all(body).context("writing response body")?;
    stream.flush().context("flushing response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry() -> BounceLogEntry {
        BounceLogEntry {
            pr_number: Some(42),
            author: Some("security".to_string()),
            timestamp: "2026-04-06T00:00:00Z".to_string(),
            slop_score: 150,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: vec!["security:compiled_payload_anomaly".to_string()],
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: "open".to_string(),
            is_bot: false,
            repo_slug: "owner/repo".to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: "abc123".to_string(),
            policy_hash: String::new(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.1,
            provenance: Provenance::default(),
            governor_status: None,
            pqc_sig: Some("mlsig".to_string()),
            pqc_slh_sig: Some("slhsig".to_string()),
            transparency_log: None,
            cognition_surrender_index: 0.0,
        }
    }

    #[test]
    fn hash_chain_appends_deterministically() {
        let mut chain = Blake3HashChain::default();
        let first = chain.append("sig-a");
        let second = chain.append("sig-b");
        assert_eq!(first.sequence_index, 0);
        assert_eq!(second.sequence_index, 1);
        assert_ne!(first.chained_hash, second.chained_hash);
    }

    #[test]
    fn report_route_returns_inclusion_proof() {
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/v1/report".to_string(),
            body: serde_json::to_vec(&make_entry()).expect("entry JSON must serialize"),
        };
        let response = route_request(&req);
        assert_eq!(response.status, 200);
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("response body must be JSON");
        assert_eq!(body["status"], "accepted");
        assert!(body["inclusion_proof"]["sequence_index"].as_u64().is_some());
        assert!(body["inclusion_proof"]["chained_hash"].as_str().is_some());
    }
}
