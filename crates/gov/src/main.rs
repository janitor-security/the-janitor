use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use base64::Engine as _;
use common::receipt::{DecisionReceipt, SignedDecisionReceipt};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::future::{ready, Future};
use std::io::Write;
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

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
    #[serde(default = "default_execution_tier")]
    execution_tier: String,
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
    /// Cryptographic signature provenance verdict for the commit under analysis.
    ///
    /// One of: `"verified"`, `"unsigned"`, `"invalid"`, `"mismatched_identity"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    git_signature_status: Option<String>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClientIdentity {
    #[serde(default)]
    common_name: Option<String>,
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

#[derive(Clone, Debug, Default)]
struct MutualTlsIdentity(Option<ClientIdentity>);

impl<S> FromRequestParts<S> for MutualTlsIdentity
where
    S: Send + Sync,
{
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(Ok(parts
            .extensions
            .get::<ClientIdentity>()
            .cloned()
            .or_else(|| extract_client_identity_from_headers(&parts.headers))
            .map(Some)
            .map(Self)
            .unwrap_or_default()))
    }
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
    let app = build_router(AppState {
        active_installations: Arc::new(DashMap::new()),
        github_webhook_secret: resolve_github_webhook_secret().map(Arc::new),
    });
    if let Some(tls) = resolve_rustls_config().await? {
        eprintln!("janitor-gov listening on https://{bind_addr}");
        axum_server::bind(bind_addr.parse()?)
            .acceptor(GovernorTlsAcceptor::new(tls))
            .serve(app.into_make_service())
            .await
            .context("serving janitor-gov over rustls")?;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("binding janitor-gov to {bind_addr}"))?;
        eprintln!("janitor-gov listening on http://{bind_addr}");
        axum::serve(listener, app)
            .await
            .context("serving janitor-gov")?;
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

fn resolve_github_webhook_secret() -> Option<Vec<u8>> {
    std::env::var("GITHUB_WEBHOOK_SECRET")
        .ok()
        .map(|value| value.trim().as_bytes().to_vec())
        .filter(|value| !value.is_empty())
}

async fn resolve_rustls_config() -> anyhow::Result<Option<RustlsConfig>> {
    let cert_path = std::env::var("JANITOR_GOV_TLS_CERT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let key_path = std::env::var("JANITOR_GOV_TLS_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(cert_path) = cert_path else {
        if key_path.is_some() {
            anyhow::bail!("JANITOR_GOV_TLS_KEY provided without JANITOR_GOV_TLS_CERT");
        }
        return Ok(None);
    };
    let Some(key_path) = key_path else {
        anyhow::bail!("JANITOR_GOV_TLS_CERT provided without JANITOR_GOV_TLS_KEY");
    };

    let server_config = build_server_tls_config(&cert_path, &key_path)
        .await
        .with_context(|| format!("building rustls config from {cert_path} and {key_path}"))?;
    Ok(Some(RustlsConfig::from_config(Arc::new(server_config))))
}

async fn build_server_tls_config(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<rustls::ServerConfig> {
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("reading JANITOR_GOV_TLS_CERT from {cert_path}"))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("reading JANITOR_GOV_TLS_KEY from {key_path}"))?;

    let cert_chain = load_certificate_chain(&cert_pem)?;
    let private_key = load_private_key(&key_pem)?;

    let builder = rustls::ServerConfig::builder();
    let client_ca = std::env::var("JANITOR_GOV_CLIENT_CA")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut server_config = if let Some(client_ca_path) = client_ca {
        let verifier = build_client_verifier(&client_ca_path)
            .await
            .with_context(|| format!("loading JANITOR_GOV_CLIENT_CA from {client_ca_path}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)
            .context("building rustls server config with client auth")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("building rustls server config")?
    };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
}

fn load_certificate_chain(cert_pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("certificate PEM contained no certificates");
    }
    Ok(certs)
}

fn load_private_key(key_pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(key_pem);
    rustls_pemfile::private_key(&mut reader)
        .context("failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("private key PEM contained no private key"))
}

async fn build_client_verifier(
    client_ca_path: &str,
) -> anyhow::Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let ca_pem = tokio::fs::read(client_ca_path)
        .await
        .with_context(|| format!("reading CA bundle from {client_ca_path}"))?;
    let mut reader = std::io::BufReader::new(ca_pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse client CA PEM")?;
    if certs.is_empty() {
        anyhow::bail!("client CA PEM contained no certificates");
    }
    let mut roots = RootCertStore::empty();
    let (_added, rejected) = roots.add_parsable_certificates(certs);
    if rejected != 0 {
        anyhow::bail!("client CA PEM contained unparsable certificates");
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| anyhow::anyhow!("building client cert verifier: {err}"))
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
        let role = if is_jwt(token) {
            // Real EdDSA JWT: validate signature, issuer, and expiry (NIST IA-2, AC-3).
            validate_jwt(token)
                .map_err(|_| AppError::unauthorized("invalid or expired analysis token"))?
        } else {
            // Legacy stub token: parse role without crypto (backward compat).
            extract_role_from_token(token).to_string()
        };
        if role == "auditor" {
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
    mtls_identity: MutualTlsIdentity,
    headers: HeaderMap,
    Json(mut req): Json<AnalysisTokenRequest>,
) -> Result<Json<AnalysisTokenResponse>, AppError> {
    if req.installation_id == 0 && state.github_webhook_secret.is_none() {
        req.installation_id = installation_id_from_mtls_identity(&mtls_identity.0)
            .ok_or_else(|| {
                AppError::forbidden(
                    "installation_id missing: provide installation_id or present an mTLS client certificate with a Common Name",
                )
            })?;
    }

    if let Ok(expected) = std::env::var("JANITOR_GOV_EXPECTED_POLICY") {
        let expected = expected.trim();
        if !expected.is_empty() && req.policy_hash != expected {
            return Err(AppError::forbidden(
                "policy_drift_detected: policy_hash in request does not match JANITOR_GOV_EXPECTED_POLICY — token denied",
            ));
        }
    }

    if state.github_webhook_secret.is_some()
        && req.installation_id != 0
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
    let token = issue_jwt(&req.repo, role)
        .map_err(|err| AppError::internal(format!("JWT issuance failed: {err}")))?;

    emit_event(&GovLogEvent::AnalysisToken {
        request: req,
        source_ip: extract_source_ip(&headers),
    });

    Ok(Json(AnalysisTokenResponse {
        token,
        mode: "jwt".to_string(),
        expires_in_secs: 300,
    }))
}

fn installation_id_from_mtls_identity(identity: &Option<ClientIdentity>) -> Option<u64> {
    identity
        .as_ref()
        .and_then(|identity| identity.common_name.as_deref())
        .and_then(|cn| cn.parse::<u64>().ok())
}

#[derive(Clone)]
struct GovernorTlsAcceptor {
    inner: RustlsAcceptor,
}

impl GovernorTlsAcceptor {
    fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<I, S> Accept<I, S> for GovernorTlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, ClientIdentity>;
    type Future =
        Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let client_identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| extract_client_identity_from_der(cert.as_ref()))
                .unwrap_or_default();
            Ok((stream, axum::Extension(client_identity).layer(service)))
        })
    }
}

fn extract_client_identity_from_headers(headers: &HeaderMap) -> Option<ClientIdentity> {
    headers
        .get("x-janitor-client-cert")
        .and_then(|value| value.to_str().ok())
        .and_then(decode_client_cert_header)
        .and_then(|der| extract_client_identity_from_der(&der))
}

fn decode_client_cert_header(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
}

fn extract_client_identity_from_der(der: &[u8]) -> Option<ClientIdentity> {
    extract_common_name_from_certificate(der).map(|common_name| ClientIdentity {
        common_name: Some(common_name),
    })
}

fn extract_common_name_from_certificate(der: &[u8]) -> Option<String> {
    let (certificate, _) = parse_der_tlv(der)?;
    if certificate.tag != 0x30 {
        return None;
    }
    let mut cert_children = parse_der_children(certificate.value)?;
    let tbs = cert_children.next()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut tbs_children = parse_der_children(tbs.value)?;
    let first = tbs_children.next()?;
    let serial = if first.tag == 0xa0 {
        tbs_children.next()?
    } else {
        first
    };
    if serial.tag != 0x02 {
        return None;
    }
    let _signature = tbs_children.next()?;
    let _issuer = tbs_children.next()?;
    let _validity = tbs_children.next()?;
    let subject = tbs_children.next()?;
    if subject.tag != 0x30 {
        return None;
    }
    extract_common_name_from_subject(subject.value)
}

fn extract_common_name_from_subject(subject_der: &[u8]) -> Option<String> {
    let rdns = parse_der_children(subject_der)?;
    for rdn in rdns {
        if rdn.tag != 0x31 {
            continue;
        }
        for attr in parse_der_children(rdn.value)? {
            if attr.tag != 0x30 {
                continue;
            }
            let mut pair = parse_der_children(attr.value)?;
            let oid = pair.next()?;
            let value = pair.next()?;
            if oid.value == [0x55, 0x04, 0x03] {
                return parse_directory_string(value);
            }
        }
    }
    None
}

fn parse_directory_string(value: DerTlv<'_>) -> Option<String> {
    match value.tag {
        0x0c | 0x13 | 0x16 => str::from_utf8(value.value).ok().map(ToOwned::to_owned),
        0x1e => {
            if !value.value.len().is_multiple_of(2) {
                return None;
            }
            let utf16 = value
                .value
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&utf16).ok()
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct DerTlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_der_children(mut input: &[u8]) -> Option<impl Iterator<Item = DerTlv<'_>> + '_> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (item, rest) = parse_der_tlv(input)?;
        items.push(item);
        input = rest;
    }
    Some(items.into_iter())
}

fn parse_der_tlv(input: &[u8]) -> Option<(DerTlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (len, rest) = parse_der_length(rest)?;
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    Some((DerTlv { tag, value }, rest))
}

fn parse_der_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), rest));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > std::mem::size_of::<usize>() || rest.len() < octets {
        return None;
    }
    let mut len = 0usize;
    for &byte in &rest[..octets] {
        len = (len << 8) | usize::from(byte);
    }
    Some((len, &rest[octets..]))
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

fn default_execution_tier() -> String {
    "Community".to_string()
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
        execution_tier: entry.execution_tier.clone(),
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

/// Extracts the role claim from a legacy stub token string
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

/// Claims embedded in issued EdDSA JWTs.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    /// Subject: `repo` or installation binding.
    sub: String,
    /// Role claim: `"admin"`, `"ci-writer"`, or `"auditor"`.
    role: String,
    /// Issuer: always `"janitor-governor"`.
    iss: String,
    /// Issued-at epoch seconds (UTC).
    iat: u64,
    /// Expiry epoch seconds (UTC); tokens expire in 300 seconds.
    exp: u64,
}

/// Returns `true` when `token` begins with a JWT header segment (`eyJ`),
/// indicating it should be validated as an EdDSA JWT rather than a legacy
/// stub token.
fn is_jwt(token: &str) -> bool {
    token.starts_with("eyJ")
}

/// Constructs a PKCS#8 v0 DER blob for an Ed25519 private key (RFC 8410)
/// and base64-encodes it into PEM form (`-----BEGIN PRIVATE KEY-----`).
///
/// The 48-byte DER layout is:
/// `SEQUENCE { INTEGER(0), SEQUENCE{OID 1.3.101.112}, OCTET_STRING{OCTET_STRING{seed}} }`
fn ed25519_seed_to_pkcs8_pem(seed: &[u8; 32]) -> String {
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&[
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER version = 0
        0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (id-Ed25519)
        0x04, 0x22, // OCTET STRING (34 bytes, OneAsymmetricKey.privateKey)
        0x04, 0x20, // OCTET STRING (32 bytes, CurvePrivateKey)
    ]);
    der[16..].copy_from_slice(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// Constructs a SubjectPublicKeyInfo DER blob for an Ed25519 public key
/// (RFC 8410) and base64-encodes it into PEM form (`-----BEGIN PUBLIC KEY-----`).
///
/// The 44-byte DER layout is:
/// `SEQUENCE { SEQUENCE{OID 1.3.101.112}, BIT_STRING{0x00, pub_bytes} }`
fn ed25519_pub_to_spki_pem(pub_bytes: &[u8; 32]) -> String {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&[
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (id-Ed25519)
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // 0 padding bits
    ]);
    der[12..].copy_from_slice(pub_bytes);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

/// Returns the `EncodingKey` derived from the Governor's Ed25519 signing key.
/// Initialised once; subsequent calls return the cached key.
fn jwt_encoding_key() -> anyhow::Result<&'static EncodingKey> {
    static KEY: OnceLock<anyhow::Result<EncodingKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        let signing_key = governor_signing_key()?;
        let seed = signing_key.to_bytes();
        let pem = ed25519_seed_to_pkcs8_pem(&seed);
        EncodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("JWT EdDSA encoding key: {e}"))
    })
    .as_ref()
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Returns the `DecodingKey` derived from the Governor's Ed25519 verifying key.
/// Initialised once; subsequent calls return the cached key.
fn jwt_decoding_key() -> anyhow::Result<&'static DecodingKey> {
    static KEY: OnceLock<anyhow::Result<DecodingKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        let signing_key = governor_signing_key()?;
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let pem = ed25519_pub_to_spki_pem(&pub_bytes);
        DecodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("JWT EdDSA decoding key: {e}"))
    })
    .as_ref()
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Issues a signed EdDSA JWT with a 300-second TTL.
///
/// Claims: `sub` (repo slug), `role`, `iss` (`"janitor-governor"`), `iat`, `exp`.
fn issue_jwt(sub: &str, role: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock error: {e}"))?
        .as_secs();
    let claims = JwtClaims {
        sub: sub.to_string(),
        role: normalize_role(role).to_string(),
        iss: "janitor-governor".to_string(),
        iat: now,
        exp: now + 300,
    };
    encode(&Header::new(Algorithm::EdDSA), &claims, jwt_encoding_key()?)
        .map_err(|e| anyhow::anyhow!("JWT encoding failed: {e}"))
}

/// Validates an EdDSA JWT and returns the `role` claim on success.
///
/// Verifies: EdDSA signature, `iss == "janitor-governor"`, and `exp > now`.
/// Returns `Err` for any invalid, expired, or tampered token.
fn validate_jwt(token: &str) -> anyhow::Result<String> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["janitor-governor"]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    let data = decode::<JwtClaims>(token, jwt_decoding_key()?, &validation)
        .map_err(|e| anyhow::anyhow!("JWT validation failed: {e}"))?;
    Ok(data.claims.role)
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
            execution_tier: "Community".to_string(),
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
            git_signature_status: None,
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

    fn sample_client_cert_der(common_name: &str) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(value.len() + 4);
            out.push(tag);
            if value.len() < 128 {
                out.push(value.len() as u8);
            } else {
                let len_bytes = (value.len() as u16).to_be_bytes();
                out.push(0x82);
                out.extend_from_slice(&len_bytes);
            }
            out.extend_from_slice(value);
            out
        }

        let version = tlv(0xa0, &[0x02, 0x01, 0x02]);
        let serial = tlv(0x02, &[0x01]);
        let algorithm = tlv(0x30, &[0x06, 0x03, 0x2a, 0x03, 0x04]);
        let issuer = tlv(0x30, &[]);
        let validity = tlv(0x30, &[]);
        let cn_attr = {
            let mut attr = Vec::new();
            attr.extend_from_slice(&tlv(0x06, &[0x55, 0x04, 0x03]));
            attr.extend_from_slice(&tlv(0x0c, common_name.as_bytes()));
            tlv(0x31, &tlv(0x30, &attr))
        };
        let subject = tlv(0x30, &cn_attr);
        let spki = tlv(0x30, &[]);

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&algorithm);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);

        let signature_algorithm = algorithm.clone();
        let signature_value = tlv(0x03, &[0x00]);

        let mut cert = Vec::new();
        cert.extend_from_slice(&tlv(0x30, &tbs));
        cert.extend_from_slice(&signature_algorithm);
        cert.extend_from_slice(&signature_value);
        tlv(0x30, &cert)
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
    #[serial_test::serial]
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
    #[serial_test::serial]
    async fn matching_policy_hash_returns_token() {
        set_test_signing_key();
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
        // Token must be a real EdDSA JWT, not a stub string.
        let token = payload["token"].as_str().unwrap();
        assert!(is_jwt(token), "issued token must be a JWT");
        // Decode and verify claims without expiry check (testing structure only).
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["janitor-governor"]);
        v.set_required_spec_claims(&["exp", "iss", "sub"]);
        let claims = decode::<JwtClaims>(token, jwt_decoding_key().unwrap(), &v)
            .expect("issued JWT must be valid")
            .claims;
        assert_eq!(claims.role, "ci-writer", "default role must be ci-writer");
        assert_eq!(
            claims.iss, "janitor-governor",
            "issuer must be janitor-governor"
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
    #[serial_test::serial]
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
    #[serial_test::serial]
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
    #[serial_test::serial]
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
    #[serial_test::serial]
    async fn analysis_token_endpoint_embeds_role_in_token() {
        set_test_signing_key();
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
        let token = payload["token"].as_str().unwrap();
        assert!(is_jwt(token), "issued token must be a JWT");
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["janitor-governor"]);
        v.set_required_spec_claims(&["exp", "iss", "sub"]);
        let claims = decode::<JwtClaims>(token, jwt_decoding_key().unwrap(), &v)
            .expect("issued JWT must be valid")
            .claims;
        assert_eq!(claims.role, "auditor", "role claim must be auditor");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn analysis_token_defaults_to_ci_writer_when_role_absent() {
        set_test_signing_key();
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
        let token = payload["token"].as_str().unwrap();
        assert!(is_jwt(token), "issued token must be a JWT");
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["janitor-governor"]);
        v.set_required_spec_claims(&["exp", "iss", "sub"]);
        let claims = decode::<JwtClaims>(token, jwt_decoding_key().unwrap(), &v)
            .expect("issued JWT must be valid")
            .claims;
        assert_eq!(
            claims.role, "ci-writer",
            "absent role must default to ci-writer"
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
    #[serial_test::serial]
    async fn expired_jwt_in_report_returns_401() {
        set_test_signing_key();
        // Craft a token whose exp is in the past (UNIX epoch + 1 second).
        let claims = JwtClaims {
            sub: "owner/repo".to_string(),
            role: "ci-writer".to_string(),
            iss: "janitor-governor".to_string(),
            iat: 1,
            exp: 1,
        };
        let expired_token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            jwt_encoding_key().expect("test encoding key must be available"),
        )
        .expect("expired token encoding must succeed");

        let mut entry = sample_entry();
        entry.analysis_token = Some(expired_token);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/report")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&entry).unwrap()))
            .unwrap();

        let response = test_app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let payload: serde_json::Value =
            serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(payload["error"], "invalid or expired analysis token");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn valid_jwt_with_auditor_role_cannot_post_report_returns_403() {
        set_test_signing_key();
        let auditor_token = issue_jwt("owner/repo", "auditor").expect("JWT issuance must succeed");
        let mut entry = sample_entry();
        entry.analysis_token = Some(auditor_token);
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

    #[test]
    fn extract_common_name_from_certificate_reads_subject_cn() {
        let cert = sample_client_cert_der("4242");
        assert_eq!(
            extract_common_name_from_certificate(&cert).as_deref(),
            Some("4242")
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn analysis_token_uses_mtls_common_name_for_on_prem_installation_id() {
        set_test_signing_key();
        let app = build_router(AppState {
            active_installations: Arc::new(DashMap::new()),
            github_webhook_secret: None,
        });
        let cert = sample_client_cert_der("4242");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/analysis-token")
            .header("content-type", "application/json")
            .header(
                "x-janitor-client-cert",
                base64::engine::general_purpose::STANDARD.encode(cert),
            )
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "repo": "owner/repo",
                    "pr": 6,
                    "head_sha": "abc123",
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
