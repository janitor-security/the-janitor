use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use common::receipt::{DecisionReceipt, SignedDecisionReceipt};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

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
    wisdom_hash: Option<String>,
    #[serde(default)]
    wasm_policy_receipts: Vec<common::wasm_receipt::WasmPolicyReceipt>,
    #[serde(default)]
    capsule_hash: Option<String>,
    #[serde(default)]
    decision_receipt: Option<SignedDecisionReceipt>,
    #[serde(default)]
    cognition_surrender_index: f64,
    /// Analysis token that authorized this report submission.
    ///
    /// The Governor extracts the `role` claim from this token and enforces
    /// RBAC: `auditor` tokens are rejected with HTTP 403.
    #[serde(default)]
    analysis_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InclusionProof {
    sequence_index: u64,
    chained_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportResponse {
    status: String,
    mode: String,
    inclusion_proof: InclusionProof,
    decision_receipt: SignedDecisionReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisTokenRequest {
    repo: String,
    pr: u64,
    head_sha: String,
    #[serde(default)]
    installation_id: u64,
    /// SHA-256 hash of the canonical policy fields (from `JanitorPolicy::content_hash`).
    ///
    /// When `JANITOR_GOV_EXPECTED_POLICY` is set in the Governor environment, the
    /// hash MUST match or the token request is rejected with HTTP 403
    /// `policy_drift_detected`.
    #[serde(default)]
    policy_hash: String,
    /// Role claim to embed in the issued token.
    ///
    /// Valid values: `"admin"`, `"ci-writer"`, `"auditor"`.
    /// Defaults to `"ci-writer"` when absent (minimum-privilege default for CI runners).
    #[serde(default = "AnalysisTokenRequest::default_role")]
    role: String,
}

impl AnalysisTokenRequest {
    fn default_role() -> String {
        "ci-writer".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisTokenResponse {
    /// Stub token string encoding the issued role and installation binding.
    token: String,
    mode: String,
    expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifySuppressionsRequest {
    suppression_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VerifySuppressionsResponse {
    approved_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum GovLogEvent {
    Report {
        entry: Box<BounceLogEntry>,
        inclusion_proof: InclusionProof,
        source_ip: String,
    },
    AnalysisToken {
        request: AnalysisTokenRequest,
        source_ip: String,
    },
    GithubInstallation {
        action: String,
        installation_id: u64,
        source_ip: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditFormat {
    Ndjson,
    Cef,
    Syslog,
}

impl AuditFormat {
    fn from_env() -> anyhow::Result<Self> {
        match std::env::var("JANITOR_GOV_AUDIT_FORMAT")
            .ok()
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            None => Ok(Self::Ndjson),
            Some("ndjson") | Some("NDJSON") | Some("Ndjson") => Ok(Self::Ndjson),
            Some("cef") | Some("CEF") | Some("Cef") => Ok(Self::Cef),
            Some("syslog") | Some("SYSLOG") | Some("Syslog") => Ok(Self::Syslog),
            Some(other) => anyhow::bail!(
                "JANITOR_GOV_AUDIT_FORMAT must be one of ndjson, cef, or syslog; got {other}"
            ),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SealedAuditRecord {
    hmac: String,
    payload: String,
}

#[derive(Debug)]
struct AuditSink {
    format: AuditFormat,
    hostname: String,
    file: Option<Mutex<File>>,
    hmac_key: Option<Vec<u8>>,
}

impl AuditSink {
    fn from_env() -> anyhow::Result<Self> {
        let format = AuditFormat::from_env()?;
        let hostname = resolve_hostname();
        let file_path = std::env::var("JANITOR_GOV_AUDIT_LOG")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let hmac_key = std::env::var("JANITOR_GOV_AUDIT_HMAC_KEY")
            .ok()
            .map(|value| parse_hmac_hex_key("JANITOR_GOV_AUDIT_HMAC_KEY", &value))
            .transpose()?;

        let file = if let Some(path) = file_path {
            if hmac_key.is_none() {
                anyhow::bail!(
                    "JANITOR_GOV_AUDIT_HMAC_KEY must be set when JANITOR_GOV_AUDIT_LOG is configured"
                );
            }
            Some(Mutex::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .with_context(|| format!("opening JANITOR_GOV_AUDIT_LOG at {path}"))?,
            ))
        } else {
            None
        };

        Ok(Self {
            format,
            hostname,
            file,
            hmac_key,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GithubInstallationWebhook {
    action: String,
    installation: GithubInstallation,
}

#[derive(Debug, Deserialize)]
struct GithubInstallation {
    id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct GithubWebhookResponse {
    status: String,
    installation_id: u64,
}

/// FIPS 140-3 compliant transparency log hash chain.
///
/// Replaces the prior BLAKE3 implementation.  NIST SP 800-92 requires
/// audit log integrity mechanisms to use NIST-approved algorithms;
/// SHA-384 (FIPS 180-4) satisfies this requirement.  Each `append`
/// produces a 96-character hex string (`chained_hash` in `InclusionProof`).
#[derive(Debug)]
struct Sha384HashChain {
    last_hash: [u8; 48],
    next_index: u64,
}

impl Default for Sha384HashChain {
    fn default() -> Self {
        Self {
            last_hash: [0u8; 48],
            next_index: 0,
        }
    }
}

impl Sha384HashChain {
    fn append(&mut self, new_cbom_signature: &str) -> InclusionProof {
        let mut payload = Vec::with_capacity(self.last_hash.len() + new_cbom_signature.len());
        payload.extend_from_slice(&self.last_hash);
        payload.extend_from_slice(new_cbom_signature.as_bytes());
        let digest = Sha384::digest(&payload);
        self.last_hash.copy_from_slice(&digest);
        let proof = InclusionProof {
            sequence_index: self.next_index,
            chained_hash: hex::encode(self.last_hash),
        };
        self.next_index = self.next_index.saturating_add(1);
        proof
    }
}

#[derive(Clone, Default)]
struct AppState {
    active_installations: Arc<DashMap<u64, ()>>,
    github_webhook_secret: Option<Arc<Vec<u8>>>,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}

fn transparency_log() -> &'static Mutex<Sha384HashChain> {
    static LOG: OnceLock<Mutex<Sha384HashChain>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Sha384HashChain::default()))
}

fn audit_sink() -> anyhow::Result<&'static AuditSink> {
    static SINK: OnceLock<anyhow::Result<AuditSink>> = OnceLock::new();
    SINK.get_or_init(AuditSink::from_env)
        .as_ref()
        .map_err(|err| anyhow::anyhow!("{err}"))
}

fn governor_signing_key() -> anyhow::Result<&'static SigningKey> {
    static SIGNING_KEY: OnceLock<anyhow::Result<SigningKey>> = OnceLock::new();
    SIGNING_KEY
        .get_or_init(|| {
            let seed_hex = std::env::var("JANITOR_GOV_SIGNING_KEY_HEX").map_err(|_| {
                anyhow::anyhow!(
                    "JANITOR_GOV_SIGNING_KEY_HEX is not set; janitor-gov cannot countersign decision receipts"
                )
            })?;
            let trimmed = seed_hex.trim();
            if trimmed.len() != 64 {
                anyhow::bail!(
                    "JANITOR_GOV_SIGNING_KEY_HEX must be exactly 64 hex characters (32-byte Ed25519 seed)"
                );
            }
            let mut seed = [0u8; 32];
            for (idx, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
                let part = std::str::from_utf8(chunk)
                    .map_err(|e| anyhow::anyhow!("invalid Governor key hex: {e}"))?;
                seed[idx] = u8::from_str_radix(part, 16)
                    .map_err(|e| anyhow::anyhow!("invalid Governor key hex: {e}"))?;
            }
            Ok(SigningKey::from_bytes(&seed))
        })
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = audit_sink()?;
    let bind_addr = resolve_bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding janitor-gov to {bind_addr}"))?;
    let app = build_router(AppState {
        active_installations: Arc::new(DashMap::new()),
        github_webhook_secret: resolve_github_webhook_secret().map(Arc::new),
    });
    eprintln!("janitor-gov listening on http://{bind_addr}");
    axum::serve(listener, app)
        .await
        .context("serving janitor-gov")?;
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

fn resolve_github_webhook_secret() -> Option<Vec<u8>> {
    std::env::var("GITHUB_WEBHOOK_SECRET")
        .ok()
        .map(|value| value.trim().as_bytes().to_vec())
        .filter(|value| !value.is_empty())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/report", post(report_handler))
        .route("/v1/analysis-token", post(analysis_token_handler))
        .route("/v1/verify-suppressions", post(verify_suppressions_handler))
        .route("/v1/github/webhook", post(github_webhook_handler))
        .with_state(state)
}

async fn report_handler(
    headers: HeaderMap,
    Json(entry): Json<BounceLogEntry>,
) -> Result<Json<ReportResponse>, AppError> {
    if let Some(token) = &entry.analysis_token {
        if extract_role_from_token(token) == "auditor" {
            return Err(AppError::forbidden(
                "forbidden: auditor tokens cannot post bounce reports — use a ci-writer or admin token",
            ));
        }
    }

    let signature_material = report_signature_material(&entry);
    let proof = match transparency_log().lock() {
        Ok(mut chain) => chain.append(&signature_material),
        Err(err) => {
            return Err(AppError::internal(format!(
                "transparency log poisoned: {err}"
            )));
        }
    };
    let decision_receipt = build_signed_receipt(&entry, &proof)
        .map_err(|err| AppError::internal(format!("failed to sign decision receipt: {err}")))?;

    emit_event(&GovLogEvent::Report {
        entry: Box::new(entry),
        inclusion_proof: proof.clone(),
        source_ip: extract_source_ip(&headers),
    });

    Ok(Json(ReportResponse {
        status: "accepted".to_string(),
        mode: "stub".to_string(),
        inclusion_proof: proof,
        decision_receipt,
    }))
}

async fn analysis_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AnalysisTokenRequest>,
) -> Result<Json<AnalysisTokenResponse>, AppError> {
    if let Ok(expected) = std::env::var("JANITOR_GOV_EXPECTED_POLICY") {
        let expected = expected.trim();
        if !expected.is_empty() && req.policy_hash != expected {
            return Err(AppError::forbidden(
                "policy_drift_detected: policy_hash in request does not match JANITOR_GOV_EXPECTED_POLICY — token denied",
            ));
        }
    }

    if req.installation_id != 0
        && !state
            .active_installations
            .contains_key(&req.installation_id)
    {
        return Err(AppError::forbidden(format!(
            "inactive_installation: installation_id {} is not provisioned",
            req.installation_id
        )));
    }

    let role = normalize_role(&req.role);
    let token = format!(
        "stub-token:role={role};installation_id={}",
        req.installation_id
    );

    emit_event(&GovLogEvent::AnalysisToken {
        request: req,
        source_ip: extract_source_ip(&headers),
    });

    Ok(Json(AnalysisTokenResponse {
        token,
        mode: "stub".to_string(),
        expires_in_secs: 300,
    }))
}

async fn verify_suppressions_handler(
    Json(req): Json<VerifySuppressionsRequest>,
) -> Result<Json<VerifySuppressionsResponse>, AppError> {
    let approved_ids: Vec<String> = req
        .suppression_ids
        .into_iter()
        .filter(|id| approved_suppression_ids().contains(id.as_str()))
        .collect();
    Ok(Json(VerifySuppressionsResponse { approved_ids }))
}

async fn github_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<GithubWebhookResponse>, AppError> {
    verify_github_webhook_request(&state, &headers, &body)?;

    let payload: GithubInstallationWebhook = serde_json::from_slice(&body)
        .map_err(|err| AppError::bad_request(format!("invalid github webhook payload: {err}")))?;

    let installation_id = payload.installation.id;
    match payload.action.as_str() {
        "created" => {
            state.active_installations.insert(installation_id, ());
        }
        "deleted" => {
            state.active_installations.remove(&installation_id);
        }
        _ => {}
    }

    emit_event(&GovLogEvent::GithubInstallation {
        action: payload.action.clone(),
        installation_id,
        source_ip: extract_source_ip(&headers),
    });

    Ok(Json(GithubWebhookResponse {
        status: "accepted".to_string(),
        installation_id,
    }))
}

fn verify_github_webhook_request(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), AppError> {
    let secret = state
        .github_webhook_secret
        .as_deref()
        .ok_or_else(|| AppError::unauthorized("github webhook secret is not configured"))?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing x-hub-signature-256 header"))?;

    if verify_github_signature(secret.as_slice(), body, signature) {
        Ok(())
    } else {
        Err(AppError::unauthorized(
            "github webhook authentication failed: signature mismatch",
        ))
    }
}

fn verify_github_signature(secret: &[u8], payload: &[u8], signature_header: &str) -> bool {
    let expected = match signature_header.strip_prefix("sha256=") {
        Some(expected) => expected,
        None => return false,
    };
    let expected_bytes = match hex::decode(expected) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(payload);
    mac.verify_slice(&expected_bytes).is_ok()
}

fn normalize_role(role: &str) -> &str {
    match role {
        "admin" | "ci-writer" | "auditor" => role,
        _ => "ci-writer",
    }
}

fn approved_suppression_ids() -> &'static HashSet<&'static str> {
    static IDS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| HashSet::from(["waive-eval", "approved-ruby-sqli", "approved-php-sqli"]))
}

fn build_signed_receipt(
    entry: &BounceLogEntry,
    proof: &InclusionProof,
) -> anyhow::Result<SignedDecisionReceipt> {
    let receipt = DecisionReceipt {
        policy_hash: entry.policy_hash.clone(),
        wisdom_hash: entry.wisdom_hash.clone().unwrap_or_default(),
        commit_sha: entry.commit_sha.clone(),
        repo_slug: entry.repo_slug.clone(),
        slop_score: entry.slop_score,
        transparency_anchor: format!("{}:{}", proof.sequence_index, proof.chained_hash),
        cbom_signature: if let Some(sig) = entry.pqc_sig.as_deref() {
            sig.to_string()
        } else if let Some(sig) = entry.pqc_slh_sig.as_deref() {
            sig.to_string()
        } else {
            String::new()
        },
        capsule_hash: entry.capsule_hash.clone().unwrap_or_default(),
        wasm_policy_receipts: entry.wasm_policy_receipts.clone(),
    };
    SignedDecisionReceipt::sign(receipt, governor_signing_key()?)
}

fn emit_event(event: &GovLogEvent) {
    let sink = match audit_sink() {
        Ok(sink) => sink,
        Err(err) => {
            eprintln!("janitor-gov audit sink initialization failed: {err}");
            return;
        }
    };

    let payload = render_audit_event(event, sink.format, &sink.hostname, &utc_now_iso8601());
    println!("{payload}");

    if let (Some(file), Some(key)) = (&sink.file, sink.hmac_key.as_deref()) {
        match seal_audit_payload(payload.as_str(), key).and_then(|record| {
            serde_json::to_string(&record).context("serializing sealed audit record")
        }) {
            Ok(line) => {
                if let Ok(mut guard) = file.lock() {
                    if writeln!(guard, "{line}").is_err() {
                        eprintln!("janitor-gov audit log append failed");
                    }
                } else {
                    eprintln!("janitor-gov audit log mutex poisoned");
                }
            }
            Err(err) => eprintln!("janitor-gov audit record sealing failed: {err}"),
        }
    }
}

fn render_audit_event(
    event: &GovLogEvent,
    format: AuditFormat,
    hostname: &str,
    default_timestamp: &str,
) -> String {
    match format {
        AuditFormat::Ndjson => serde_json::to_string(event).unwrap_or_else(|err| {
            format!("{{\"event\":\"serialization_failed\",\"error\":\"{err}\"}}")
        }),
        AuditFormat::Cef => render_cef_event(event),
        AuditFormat::Syslog => render_syslog_event(event, hostname, default_timestamp),
    }
}

fn render_cef_event(event: &GovLogEvent) -> String {
    let header = format!(
        "CEF:0|JanitorSecurity|Governor|1.0|{}|{}|{}",
        event.cef_event_id(),
        escape_cef_value(event.cef_name()),
        event.cef_severity()
    );
    let extension = match event {
        GovLogEvent::Report {
            entry,
            inclusion_proof,
            source_ip,
        } => format!(
            "src={} cs1Label=repo cs1={} cs2Label=commit cs2={} cs3Label=sequence_index cs3={} cs4Label=policy_hash cs4={} cn1Label=slop_score cn1={} suser={} outcome=accepted",
            escape_cef_value(source_ip),
            escape_cef_value(&entry.repo_slug),
            escape_cef_value(&entry.commit_sha),
            inclusion_proof.sequence_index,
            escape_cef_value(&entry.policy_hash),
            entry.slop_score,
            escape_cef_value(entry.author.as_deref().unwrap_or("unknown")),
        ),
        GovLogEvent::AnalysisToken { request, source_ip } => format!(
            "src={} cs1Label=repo cs1={} cs2Label=head_sha cs2={} cs3Label=installation_id cs3={} cs4Label=role cs4={} cn1Label=pr cn1={} outcome=issued",
            escape_cef_value(source_ip),
            escape_cef_value(&request.repo),
            escape_cef_value(&request.head_sha),
            request.installation_id,
            escape_cef_value(&request.role),
            request.pr,
        ),
        GovLogEvent::GithubInstallation {
            action,
            installation_id,
            source_ip,
        } => format!(
            "src={} cs1Label=action cs1={} cs2Label=installation_id cs2={} outcome=accepted",
            escape_cef_value(source_ip),
            escape_cef_value(action),
            installation_id,
        ),
    };
    format!("{header}|{extension}")
}

fn render_syslog_event(event: &GovLogEvent, hostname: &str, default_timestamp: &str) -> String {
    let pri = 16 * 8 + event.syslog_severity_code();
    let timestamp = event.event_timestamp().unwrap_or(default_timestamp);
    let structured_data = match event {
        GovLogEvent::Report {
            entry,
            inclusion_proof,
            source_ip,
        } => format!(
            "[janitorGov src=\"{}\" repo=\"{}\" commit=\"{}\" seq=\"{}\" policy_hash=\"{}\" slop_score=\"{}\"]",
            escape_syslog_value(source_ip),
            escape_syslog_value(&entry.repo_slug),
            escape_syslog_value(&entry.commit_sha),
            inclusion_proof.sequence_index,
            escape_syslog_value(&entry.policy_hash),
            entry.slop_score,
        ),
        GovLogEvent::AnalysisToken { request, source_ip } => format!(
            "[janitorGov src=\"{}\" repo=\"{}\" head_sha=\"{}\" installation_id=\"{}\" role=\"{}\" pr=\"{}\"]",
            escape_syslog_value(source_ip),
            escape_syslog_value(&request.repo),
            escape_syslog_value(&request.head_sha),
            request.installation_id,
            escape_syslog_value(&request.role),
            request.pr,
        ),
        GovLogEvent::GithubInstallation {
            action,
            installation_id,
            source_ip,
        } => format!(
            "[janitorGov src=\"{}\" action=\"{}\" installation_id=\"{}\"]",
            escape_syslog_value(source_ip),
            escape_syslog_value(action),
            installation_id,
        ),
    };
    format!(
        "<{pri}>1 {timestamp} {hostname} janitor-gov - {} - {structured_data} {}",
        event.cef_event_id(),
        event.syslog_message()
    )
}

fn seal_audit_payload(payload: &str, key: &[u8]) -> anyhow::Result<SealedAuditRecord> {
    let mut mac = HmacSha384::new_from_slice(key)
        .map_err(|err| anyhow::anyhow!("initializing audit HMAC failed: {err}"))?;
    mac.update(payload.as_bytes());
    Ok(SealedAuditRecord {
        hmac: hex::encode(mac.finalize().into_bytes()),
        payload: payload.to_string(),
    })
}

fn parse_hmac_hex_key(var_name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = value.trim();
    let key = hex::decode(trimmed)
        .with_context(|| format!("{var_name} must be valid lowercase or uppercase hex"))?;
    if key.is_empty() {
        anyhow::bail!("{var_name} must not be empty");
    }
    Ok(key)
}

fn resolve_hostname() -> String {
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "localhost".to_string()
}

fn extract_source_ip(headers: &HeaderMap) -> String {
    for header_name in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
        {
            if let Some(ip) = value
                .split(',')
                .next()
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
            {
                return ip.to_string();
            }
        }
    }
    "unknown".to_string()
}

fn utc_now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = (secs / 86400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn escape_cef_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', "\\n")
}

fn escape_syslog_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

impl GovLogEvent {
    fn cef_event_id(&self) -> &'static str {
        match self {
            Self::Report { .. } => "gov.report",
            Self::AnalysisToken { .. } => "gov.analysis_token",
            Self::GithubInstallation { .. } => "gov.github_installation",
        }
    }

    fn cef_name(&self) -> &'static str {
        match self {
            Self::Report { .. } => "bounce_report",
            Self::AnalysisToken { .. } => "analysis_token_issued",
            Self::GithubInstallation { .. } => "github_installation_webhook",
        }
    }

    fn cef_severity(&self) -> u8 {
        match self {
            Self::Report { entry, .. } if entry.slop_score >= 100 => 10,
            Self::Report { entry, .. } if entry.slop_score > 0 => 7,
            Self::Report { .. } => 4,
            Self::AnalysisToken { .. } => 5,
            Self::GithubInstallation { .. } => 4,
        }
    }

    fn syslog_severity_code(&self) -> u8 {
        match self.cef_severity() {
            9 | 10 => 2,
            7 | 8 => 3,
            5 | 6 => 4,
            _ => 6,
        }
    }

    fn event_timestamp(&self) -> Option<&str> {
        match self {
            Self::Report { entry, .. } => Some(entry.timestamp.as_str()),
            Self::AnalysisToken { .. } | Self::GithubInstallation { .. } => None,
        }
    }

    fn syslog_message(&self) -> String {
        match self {
            Self::Report { entry, .. } => format!(
                "report accepted repo={} commit={} slop_score={}",
                entry.repo_slug, entry.commit_sha, entry.slop_score
            ),
            Self::AnalysisToken { request, .. } => format!(
                "analysis token issued repo={} installation_id={} role={}",
                request.repo, request.installation_id, request.role
            ),
            Self::GithubInstallation {
                action,
                installation_id,
                ..
            } => format!(
                "github installation webhook action={} installation_id={installation_id}",
                action
            ),
        }
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

/// Extracts the role claim from a stub token string
/// (`"stub-token:role=<role>;installation_id=<id>"`).
///
/// Returns `"ci-writer"` (minimum-privilege default) when the token is
/// absent, malformed, or contains an unrecognised role value.
fn extract_role_from_token(token: &str) -> &str {
    token
        .strip_prefix("stub-token:role=")
        .and_then(|claims| claims.split(';').next())
        .filter(|role| matches!(*role, "admin" | "ci-writer" | "auditor"))
        .unwrap_or("ci-writer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::util::ServiceExt;

    const TEST_GOVERNOR_SIGNING_KEY_SEED: [u8; 32] = [
        0x23, 0x70, 0xde, 0x11, 0x87, 0xe8, 0xd5, 0x7e, 0x42, 0x3d, 0x3e, 0xe0, 0x38, 0x64, 0x2c,
        0x41, 0x3e, 0x27, 0x23, 0x36, 0xd4, 0x26, 0x5c, 0x1b, 0xc4, 0x1c, 0x6c, 0x22, 0x9a, 0xc4,
        0xeb, 0xe5,
    ];

    fn set_test_signing_key() {
        let hex = TEST_GOVERNOR_SIGNING_KEY_SEED
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::set_var("JANITOR_GOV_SIGNING_KEY_HEX", hex);
    }

    fn sample_entry() -> BounceLogEntry {
        BounceLogEntry {
            pr_number: Some(7),
            author: Some("agent".to_string()),
            timestamp: "2026-04-06T00:00:00Z".to_string(),
            slop_score: 150,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: vec!["security:test".to_string()],
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: "open".to_string(),
            is_bot: false,
            repo_slug: "owner/repo".to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: "deadbeef".to_string(),
            policy_hash: "policy".to_string(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.1,
            provenance: Provenance::default(),
            governor_status: None,
            pqc_sig: Some("mlsig".to_string()),
            pqc_slh_sig: None,
            transparency_log: None,
            wisdom_hash: Some("wisdom".to_string()),
            wasm_policy_receipts: Vec::new(),
            capsule_hash: Some("capsule".to_string()),
            decision_receipt: None,
            cognition_surrender_index: 0.0,
            analysis_token: None,
        }
    }

    fn sample_report_event(source_ip: &str) -> GovLogEvent {
        GovLogEvent::Report {
            entry: Box::new(sample_entry()),
            inclusion_proof: InclusionProof {
                sequence_index: 42,
                chained_hash: "abcd".repeat(24),
            },
            source_ip: source_ip.to_string(),
        }
    }

    fn test_app() -> Router {
        build_router(AppState {
            active_installations: Arc::new(DashMap::new()),
            github_webhook_secret: Some(Arc::new(b"dummy-webhook-secret".to_vec())),
        })
    }

    fn sign_payload(secret: &[u8], payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    async fn response_body(response: Response) -> Vec<u8> {
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn policy_drift_detected_returns_403() {
        std::env::set_var("JANITOR_GOV_EXPECTED_POLICY", "expected-hash-abc123");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 1,
                    "head_sha": "deadbeef",
                    "policy_hash": "wrong-hash",
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload["error"],
            "policy_drift_detected: policy_hash in request does not match JANITOR_GOV_EXPECTED_POLICY — token denied"
        );
        std::env::remove_var("JANITOR_GOV_EXPECTED_POLICY");
    }

    #[tokio::test]
    async fn matching_policy_hash_returns_token() {
        std::env::set_var("JANITOR_GOV_EXPECTED_POLICY", "correct-hash");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 2,
                    "head_sha": "cafebabe",
                    "policy_hash": "correct-hash",
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload["token"],
            "stub-token:role=ci-writer;installation_id=0"
        );
        std::env::remove_var("JANITOR_GOV_EXPECTED_POLICY");
    }

    #[test]
    fn hash_chain_appends_deterministically() {
        let mut chain = Sha384HashChain::default();
        let first = chain.append("sig-a");
        let second = chain.append("sig-b");
        assert_eq!(first.sequence_index, 0);
        assert_eq!(second.sequence_index, 1);
        assert_ne!(first.chained_hash, second.chained_hash);
        // SHA-384 produces a 48-byte digest = 96 hex chars.
        assert_eq!(first.chained_hash.len(), 96);
        assert_eq!(second.chained_hash.len(), 96);
    }

    #[test]
    fn cef_formatter_renders_exact_string() {
        let rendered = render_cef_event(&sample_report_event("198.51.100.7"));
        assert_eq!(
            rendered,
            "CEF:0|JanitorSecurity|Governor|1.0|gov.report|bounce_report|10|src=198.51.100.7 cs1Label=repo cs1=owner/repo cs2Label=commit cs2=deadbeef cs3Label=sequence_index cs3=42 cs4Label=policy_hash cs4=policy cn1Label=slop_score cn1=150 suser=agent outcome=accepted"
        );
    }

    #[test]
    fn syslog_formatter_renders_exact_string() {
        let rendered = render_syslog_event(
            &sample_report_event("198.51.100.7"),
            "janitor-host",
            "2026-04-13T00:00:00Z",
        );
        assert_eq!(
            rendered,
            "<130>1 2026-04-06T00:00:00Z janitor-host janitor-gov - gov.report - [janitorGov src=\"198.51.100.7\" repo=\"owner/repo\" commit=\"deadbeef\" seq=\"42\" policy_hash=\"policy\" slop_score=\"150\"] report accepted repo=owner/repo commit=deadbeef slop_score=150"
        );
    }

    #[tokio::test]
    async fn report_route_returns_inclusion_proof() {
        set_test_signing_key();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/report")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&sample_entry()).unwrap()))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: ReportResponse =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert!(payload.inclusion_proof.sequence_index < 1_000);
        assert!(!payload.inclusion_proof.chained_hash.is_empty());
        payload.decision_receipt.verify().unwrap();
        assert_eq!(payload.decision_receipt.receipt.repo_slug, "owner/repo");
    }

    #[test]
    fn extract_role_from_token_returns_correct_role() {
        assert_eq!(
            extract_role_from_token("stub-token:role=admin;installation_id=99"),
            "admin"
        );
        assert_eq!(
            extract_role_from_token("stub-token:role=ci-writer;installation_id=7"),
            "ci-writer"
        );
        assert_eq!(
            extract_role_from_token("stub-token:role=auditor;installation_id=1"),
            "auditor"
        );
        assert_eq!(
            extract_role_from_token("stub-token:role=superuser;installation_id=4"),
            "ci-writer"
        );
        assert_eq!(extract_role_from_token("stub-analysis-token"), "ci-writer");
        assert_eq!(extract_role_from_token(""), "ci-writer");
    }

    #[tokio::test]
    async fn auditor_token_cannot_post_report_returns_403() {
        set_test_signing_key();
        let mut entry = sample_entry();
        entry.analysis_token = Some("stub-token:role=auditor;installation_id=0".to_string());
        let request = Request::builder()
            .method("POST")
            .uri("/v1/report")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&entry).unwrap()))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload["error"],
            "forbidden: auditor tokens cannot post bounce reports — use a ci-writer or admin token"
        );
    }

    #[tokio::test]
    async fn ci_writer_token_can_post_report_returns_200() {
        set_test_signing_key();
        let mut entry = sample_entry();
        entry.analysis_token = Some("stub-token:role=ci-writer;installation_id=0".to_string());
        let request = Request::builder()
            .method("POST")
            .uri("/v1/report")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&entry).unwrap()))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn analysis_token_endpoint_embeds_role_in_token() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 3,
                    "head_sha": "deadbeef",
                    "role": "auditor",
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload["token"],
            "stub-token:role=auditor;installation_id=0"
        );
    }

    #[tokio::test]
    async fn analysis_token_defaults_to_ci_writer_when_role_absent() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 4,
                    "head_sha": "cafecafe",
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload["token"],
            "stub-token:role=ci-writer;installation_id=0"
        );
    }

    #[tokio::test]
    async fn verify_suppressions_returns_only_authorized_ids() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-suppressions")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifySuppressionsRequest {
                    suppression_ids: vec![
                        "waive-eval".to_string(),
                        "rogue-waiver".to_string(),
                        "approved-php-sqli".to_string(),
                    ],
                })
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: VerifySuppressionsResponse =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(
            payload.approved_ids,
            vec!["waive-eval".to_string(), "approved-php-sqli".to_string()]
        );
    }

    #[tokio::test]
    async fn github_webhook_accepts_valid_signature_and_registers_installation() {
        let state = AppState {
            active_installations: Arc::new(DashMap::new()),
            github_webhook_secret: Some(Arc::new(b"dummy-webhook-secret".to_vec())),
        };
        let app = build_router(state.clone());
        let payload = serde_json::to_vec(&serde_json::json!({
            "action": "created",
            "installation": {
                "id": 4242
            }
        }))
        .unwrap();
        let signature = sign_payload(b"dummy-webhook-secret", &payload);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/github/webhook")
            .header("content-type", "application/json")
            .header("x-hub-signature-256", signature)
            .body(Body::from(payload))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.active_installations.contains_key(&4242));
    }

    #[tokio::test]
    async fn github_webhook_rejects_bad_signature_with_401() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "action": "created",
            "installation": {
                "id": 999
            }
        }))
        .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/github/webhook")
            .header("content-type", "application/json")
            .header("x-hub-signature-256", "sha256=deadbeef")
            .body(Body::from(payload))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn analysis_token_rejects_unprovisioned_installation() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 5,
                    "head_sha": "feedface",
                    "installation_id": 12345,
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
