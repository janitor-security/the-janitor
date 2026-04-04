use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

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
    cognition_surrender_index: f64,
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
    Report { entry: Box<BounceLogEntry> },
    AnalysisToken { request: AnalysisTokenRequest },
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
                emit_event(&GovLogEvent::Report {
                    entry: Box::new(entry),
                });
                json_response(
                    200,
                    serde_json::json!({
                        "status": "accepted",
                        "mode": "stub",
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
