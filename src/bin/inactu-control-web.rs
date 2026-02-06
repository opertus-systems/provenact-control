use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::Path as FsPath,
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use inactu_control::{hash_payload_sha256, verify_manifest_value, verify_receipt_value};
use inactu_verifier::parse_manifest_json;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{error, info, Level};

#[derive(Clone, Debug)]
struct AppState {
    service_name: &'static str,
    service_version: &'static str,
    database_enabled: bool,
    db_pool: Option<PgPool>,
    api_auth_secret: Option<String>,
    max_requests_per_minute: usize,
    replay_cache: Arc<Mutex<HashMap<String, i64>>>,
    request_windows: Arc<Mutex<HashMap<String, VecDeque<i64>>>>,
}

#[derive(Debug)]
struct RequestCtx {
    pool: PgPool,
    owner_id: String,
    user_id: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    database_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyManifestRequest {
    manifest: Value,
    policy: Option<Value>,
}

#[derive(Debug, Serialize)]
struct VerifyManifestResponse {
    schema_version: String,
    name: String,
    version: String,
    artifact: String,
    capability_ceiling_ok: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyReceiptRequest {
    receipt: Value,
}

#[derive(Debug, Serialize)]
struct VerifyReceiptResponse {
    schema_version: String,
    artifact: String,
    receipt_hash: String,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct HashRequest {
    payload: String,
}

#[derive(Debug, Serialize)]
struct HashResponse {
    digest: String,
}

#[derive(Debug, Serialize)]
struct PackageSummary {
    id: String,
    name: String,
    visibility: String,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListPackagesResponse {
    packages: Vec<PackageSummary>,
}

#[derive(Debug, Deserialize)]
struct CreatePackageRequest {
    name: String,
    visibility: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreatePackageResponse {
    package: PackageSummary,
}

#[derive(Debug, Deserialize)]
struct PublishPackageVersionRequest {
    manifest: Value,
}

#[derive(Debug, Serialize)]
struct PublishPackageVersionResponse {
    package: String,
    version: String,
    artifact_digest: String,
}

#[derive(Debug, Serialize)]
struct PackageVersionSummary {
    version: String,
    artifact_digest: String,
    published_at: String,
    deprecated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListPackageVersionsResponse {
    package: String,
    versions: Vec<PackageVersionSummary>,
}

#[derive(Debug, Serialize)]
struct DeprecatePackageVersionResponse {
    package: String,
    version: String,
    deprecated_at: String,
}

#[derive(Debug, Serialize)]
struct ContextSummary {
    id: String,
    status: String,
    region: String,
    started_at: String,
    ended_at: Option<String>,
    package: Option<String>,
    version: Option<String>,
    last_activity: String,
}

#[derive(Debug, Serialize)]
struct ListContextsResponse {
    contexts: Vec<ContextSummary>,
}

#[derive(Debug, Deserialize)]
struct CreateContextRequest {
    status: String,
    region: String,
    package: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateContextResponse {
    context: ContextSummary,
}

#[derive(Debug, Serialize)]
struct GetContextResponse {
    context: ContextSummary,
}

#[derive(Debug, Deserialize)]
struct UpdateContextRequest {
    status: String,
}

#[derive(Debug, Serialize)]
struct UpdateContextResponse {
    context: ContextSummary,
}

#[derive(Debug, Serialize)]
struct ContextLogEntry {
    id: i64,
    ts: String,
    severity: String,
    message: String,
    metadata_json: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ListContextLogsResponse {
    context_id: String,
    logs: Vec<ContextLogEntry>,
    next_before_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AppendContextLogRequest {
    severity: String,
    message: String,
    metadata_json: Option<Value>,
}

#[derive(Debug, Serialize)]
struct AppendContextLogResponse {
    context_id: String,
    log: ContextLogEntry,
}

#[derive(Debug, Deserialize)]
struct ListContextsQuery {
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ListContextLogsQuery {
    severity: Option<String>,
    q: Option<String>,
    before_id: Option<i64>,
    limit: Option<i64>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BridgeTokenClaims {
    sub: String,
    exp: usize,
    iat: usize,
    nbf: Option<usize>,
    jti: Option<String>,
    iss: Option<String>,
    aud: Option<String>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        let detail = message.into();
        error!(error = %detail, "internal API error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
        }));
        (self.status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let pool = init_postgres().await?;
    let state = AppState {
        service_name: "inactu-control",
        service_version: env!("CARGO_PKG_VERSION"),
        database_enabled: pool.is_some(),
        db_pool: pool,
        api_auth_secret: std::env::var("INACTU_API_AUTH_SECRET").ok(),
        max_requests_per_minute: std::env::var("INACTU_MAX_REQUESTS_PER_MINUTE")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(120),
        replay_cache: Arc::new(Mutex::new(HashMap::new())),
        request_windows: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = router(state.clone());
    let bind_addr = bind_address()?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    info!(%bind_addr, "starting service");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

fn bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let value = std::env::var("INACTU_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    SocketAddr::from_str(&value).map_err(|err| format!("invalid INACTU_CONTROL_BIND: {err}").into())
}

async fn init_postgres() -> Result<Option<PgPool>, Box<dyn std::error::Error>> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let migrator = sqlx::migrate::Migrator::new(FsPath::new("./migrations")).await?;
    migrator.run(&pool).await?;
    info!("database connected and migrations applied");
    Ok(Some(pool))
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/verify/manifest", post(verify_manifest))
        .route("/v1/verify/receipt", post(verify_receipt))
        .route("/v1/hash/sha256", post(hash_sha256))
        .route("/v1/packages", get(list_packages).post(create_package))
        .route("/v1/contexts", get(list_contexts).post(create_context))
        .route(
            "/v1/contexts/:context_id",
            get(get_context).patch(update_context),
        )
        .route(
            "/v1/contexts/:context_id/logs",
            get(list_context_logs).post(append_context_log),
        )
        .route(
            "/v1/packages/:package/versions",
            get(list_package_versions).post(publish_package_version),
        )
        .route(
            "/v1/packages/:package/versions/:version/deprecate",
            post(deprecate_package_version),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: state.service_name,
        version: state.service_version,
        database_enabled: state.database_enabled,
    })
}

async fn verify_manifest(
    Json(request): Json<VerifyManifestRequest>,
) -> Result<Json<VerifyManifestResponse>, ApiError> {
    let verified = verify_manifest_value(&request.manifest, request.policy.as_ref())
        .map_err(ApiError::bad_request)?;
    Ok(Json(VerifyManifestResponse {
        schema_version: verified.schema_version,
        name: verified.name,
        version: verified.version,
        artifact: verified.artifact,
        capability_ceiling_ok: verified.capability_ceiling_ok,
    }))
}

async fn verify_receipt(
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<Json<VerifyReceiptResponse>, ApiError> {
    let verified = verify_receipt_value(&request.receipt).map_err(ApiError::bad_request)?;
    Ok(Json(VerifyReceiptResponse {
        schema_version: verified.schema_version,
        artifact: verified.artifact,
        receipt_hash: verified.receipt_hash,
        valid: verified.valid,
    }))
}

async fn hash_sha256(Json(request): Json<HashRequest>) -> Json<HashResponse> {
    Json(HashResponse {
        digest: hash_payload_sha256(&request.payload),
    })
}

fn require_database(state: &AppState) -> Result<PgPool, ApiError> {
    state
        .db_pool
        .clone()
        .ok_or_else(|| ApiError::service_unavailable("database is not configured"))
}

async fn request_ctx(headers: &HeaderMap, state: &AppState) -> Result<RequestCtx, ApiError> {
    let pool = require_database(state)?;
    let user_id = current_user_id(headers, state)?;
    enforce_rate_limit(state, &user_id)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    Ok(RequestCtx {
        pool,
        owner_id,
        user_id,
    })
}

fn current_user_id(headers: &HeaderMap, state: &AppState) -> Result<String, ApiError> {
    let secret = state
        .api_auth_secret
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("api auth secret is not configured"))?;
    let auth_value = headers
        .get("authorization")
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid authorization header"))?;

    let token = auth_value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("authorization must be a bearer token"))?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["inactu-control"]);
    validation.set_issuer(&["inactu-web"]);
    let decoded = decode::<BridgeTokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::unauthorized("invalid or expired auth token"))?;

    let claims = decoded.claims;
    if claims.sub.is_empty() {
        return Err(ApiError::unauthorized("invalid auth token subject"));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = claims.exp as i64;
    let iat = claims.iat as i64;
    if exp <= now {
        return Err(ApiError::unauthorized("expired auth token"));
    }
    if iat > now + 60 {
        return Err(ApiError::unauthorized("auth token issued in the future"));
    }
    if let Some(nbf) = claims.nbf {
        let nbf = nbf as i64;
        if nbf > now + 60 {
            return Err(ApiError::unauthorized("auth token not yet valid"));
        }
    }
    let jti = claims
        .jti
        .as_deref()
        .ok_or_else(|| ApiError::unauthorized("missing auth token id"))?;
    if jti.trim().is_empty() {
        return Err(ApiError::unauthorized("invalid auth token id"));
    }
    guard_replay(state, jti, exp)?;
    let _ = claims.iss;
    let _ = claims.aud;
    Ok(claims.sub)
}

fn guard_replay(state: &AppState, jti: &str, exp: i64) -> Result<(), ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut cache = state
        .replay_cache
        .lock()
        .map_err(|_| ApiError::internal("failed to lock replay cache"))?;
    cache.retain(|_, token_exp| *token_exp > now);
    if cache.contains_key(jti) {
        return Err(ApiError::unauthorized("replayed auth token"));
    }
    cache.insert(jti.to_string(), exp);
    Ok(())
}

fn enforce_rate_limit(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let window_start = now - 60;
    let mut windows = state
        .request_windows
        .lock()
        .map_err(|_| ApiError::internal("failed to lock request windows"))?;
    let user_window = windows.entry(user_id.to_string()).or_default();
    while let Some(ts) = user_window.front() {
        if *ts < window_start {
            user_window.pop_front();
        } else {
            break;
        }
    }
    if user_window.len() >= state.max_requests_per_minute {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: format!(
                "rate limit exceeded: max {} requests/minute",
                state.max_requests_per_minute
            ),
        });
    }
    user_window.push_back(now);
    Ok(())
}

async fn owner_id_for_user(pool: &PgPool, user_id: &str) -> Result<String, ApiError> {
    let row = sqlx::query("SELECT id::text FROM owners WHERE kind = 'user' AND user_id = $1::uuid")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|err| ApiError::internal(format!("failed owner lookup: {err}")))?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized("user owner mapping not found"));
    };
    Ok(row.get::<String, _>("id"))
}

async fn package_id_for_owner(
    pool: &PgPool,
    owner_id: &str,
    package: &str,
) -> Result<String, ApiError> {
    let package_row =
        sqlx::query("SELECT id::text FROM packages WHERE owner_id = $1::uuid AND name = $2")
            .bind(owner_id)
            .bind(package)
            .fetch_optional(pool)
            .await
            .map_err(|err| ApiError::internal(format!("failed package lookup: {err}")))?;

    let Some(package_row) = package_row else {
        return Err(ApiError::not_found("package not found"));
    };
    Ok(package_row.get("id"))
}

fn normalize_visibility(value: Option<String>) -> Result<String, ApiError> {
    match value.as_deref().unwrap_or("private") {
        "private" => Ok("private".to_string()),
        "public" => Ok("public".to_string()),
        _ => Err(ApiError::bad_request(
            "visibility must be 'private' or 'public'",
        )),
    }
}

fn normalize_context_status(value: Option<String>) -> Result<Option<String>, ApiError> {
    match value.as_deref() {
        None => Ok(None),
        Some("starting") | Some("running") | Some("stopped") | Some("failed") => Ok(value),
        _ => Err(ApiError::bad_request(
            "status must be one of: starting, running, stopped, failed",
        )),
    }
}

fn normalize_context_status_required(value: &str) -> Result<String, ApiError> {
    match value {
        "starting" | "running" | "stopped" | "failed" => Ok(value.to_string()),
        _ => Err(ApiError::bad_request(
            "status must be one of: starting, running, stopped, failed",
        )),
    }
}

fn normalize_limit(value: Option<i64>, default: i64, max: i64) -> i64 {
    value.unwrap_or(default).clamp(1, max)
}

fn normalize_log_severity(value: &str) -> Result<String, ApiError> {
    match value {
        "debug" | "info" | "warn" | "error" => Ok(value.to_string()),
        _ => Err(ApiError::bad_request(
            "severity must be one of: debug, info, warn, error",
        )),
    }
}

fn audit_severity_for_context_status(status: &str) -> &'static str {
    match status {
        "failed" => "error",
        "stopped" => "warn",
        _ => "info",
    }
}

fn normalize_rfc3339_timestamp(
    field_name: &str,
    value: Option<String>,
) -> Result<Option<String>, ApiError> {
    let Some(raw) = value else {
        return Ok(None);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let parsed = OffsetDateTime::parse(trimmed, &Rfc3339).map_err(|_| {
        ApiError::bad_request(format!(
            "{field_name} must be a valid RFC3339 timestamp (e.g. 2026-02-06T12:30:00Z)"
        ))
    })?;

    parsed
        .format(&Rfc3339)
        .map(Some)
        .map_err(|_| ApiError::internal("failed to normalize timestamp"))
}

async fn list_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListPackagesResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;

    let rows = sqlx::query(
        "SELECT id::text, name, visibility::text AS visibility, description \
         FROM packages WHERE owner_id = $1::uuid ORDER BY name",
    )
    .bind(&ctx.owner_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to list packages: {err}")))?;

    let packages = rows
        .into_iter()
        .map(|row| PackageSummary {
            id: row.get("id"),
            name: row.get("name"),
            visibility: row.get("visibility"),
            description: row.get("description"),
        })
        .collect();

    Ok(Json(ListPackagesResponse { packages }))
}

async fn create_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePackageRequest>,
) -> Result<Json<CreatePackageResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let visibility = normalize_visibility(request.visibility)?;
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("package name is required"));
    }

    let result = sqlx::query(
        "INSERT INTO packages (owner_id, name, visibility, description) \
         VALUES ($1::uuid, $2, $3::package_visibility, $4) \
         RETURNING id::text, name, visibility::text AS visibility, description",
    )
    .bind(&ctx.owner_id)
    .bind(name)
    .bind(visibility)
    .bind(request.description)
    .fetch_one(&ctx.pool)
    .await;

    let row = match result {
        Ok(row) => row,
        Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
            return Err(ApiError::conflict("package already exists for owner"));
        }
        Err(err) => {
            return Err(ApiError::internal(format!(
                "failed to create package: {err}"
            )))
        }
    };

    Ok(Json(CreatePackageResponse {
        package: PackageSummary {
            id: row.get("id"),
            name: row.get("name"),
            visibility: row.get("visibility"),
            description: row.get("description"),
        },
    }))
}

async fn publish_package_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(package): Path<String>,
    Json(request): Json<PublishPackageVersionRequest>,
) -> Result<Json<PublishPackageVersionResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;

    let manifest_bytes = serde_json::to_vec(&request.manifest)
        .map_err(|err| ApiError::bad_request(format!("manifest serialization failed: {err}")))?;
    let manifest = parse_manifest_json(&manifest_bytes)
        .map_err(|err| ApiError::bad_request(format!("invalid manifest: {err}")))?;

    if manifest.name != package {
        return Err(ApiError::bad_request(
            "manifest name must match package path parameter",
        ));
    }

    let package_id = package_id_for_owner(&ctx.pool, &ctx.owner_id, &package).await?;

    let version_insert = sqlx::query(
        "INSERT INTO package_versions (package_id, version, artifact_digest, manifest_json, published_by_user_id) \
         VALUES ($1::uuid, $2, $3, $4::jsonb, $5::uuid)",
    )
    .bind(&package_id)
    .bind(&manifest.version)
    .bind(&manifest.artifact)
    .bind(request.manifest)
    .bind(&ctx.user_id)
    .execute(&ctx.pool)
    .await;

    match version_insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
            return Err(ApiError::conflict("package version already exists"));
        }
        Err(err) => {
            return Err(ApiError::internal(format!(
                "failed to publish version: {err}"
            )))
        }
    }

    Ok(Json(PublishPackageVersionResponse {
        package,
        version: manifest.version,
        artifact_digest: manifest.artifact,
    }))
}

async fn list_package_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(package): Path<String>,
) -> Result<Json<ListPackageVersionsResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let package_id = package_id_for_owner(&ctx.pool, &ctx.owner_id, &package).await?;

    let rows = sqlx::query(
        "SELECT version, artifact_digest, published_at::text, deprecated_at::text \
         FROM package_versions WHERE package_id = $1::uuid ORDER BY published_at DESC",
    )
    .bind(package_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to list package versions: {err}")))?;

    let versions = rows
        .into_iter()
        .map(|row| PackageVersionSummary {
            version: row.get("version"),
            artifact_digest: row.get("artifact_digest"),
            published_at: row.get("published_at"),
            deprecated_at: row.get("deprecated_at"),
        })
        .collect();

    Ok(Json(ListPackageVersionsResponse { package, versions }))
}

async fn deprecate_package_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((package, version)): Path<(String, String)>,
) -> Result<Json<DeprecatePackageVersionResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let package_id = package_id_for_owner(&ctx.pool, &ctx.owner_id, &package).await?;

    let row = sqlx::query(
        "UPDATE package_versions \
         SET deprecated_at = COALESCE(deprecated_at, now()) \
         WHERE package_id = $1::uuid AND version = $2 \
         RETURNING deprecated_at::text",
    )
    .bind(package_id)
    .bind(&version)
    .fetch_optional(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to deprecate package version: {err}")))?;

    let Some(row) = row else {
        return Err(ApiError::not_found("package version not found"));
    };

    Ok(Json(DeprecatePackageVersionResponse {
        package,
        version,
        deprecated_at: row.get("deprecated_at"),
    }))
}

async fn list_contexts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListContextsQuery>,
) -> Result<Json<ListContextsResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let status = normalize_context_status(query.status)?;
    let limit = normalize_limit(query.limit, 50, 200);

    let rows = sqlx::query(
        "SELECT
            c.id::text,
            c.status::text AS status,
            c.region,
            c.started_at::text AS started_at,
            c.ended_at::text AS ended_at,
            p.name AS package_name,
            pv.version AS package_version,
            COALESCE(
                (SELECT MAX(l.ts)::text FROM context_logs l WHERE l.context_id = c.id),
                c.started_at::text
            ) AS last_activity
         FROM contexts c
         LEFT JOIN package_versions pv ON pv.id = c.package_version_id
         LEFT JOIN packages p ON p.id = pv.package_id
         WHERE c.owner_id = $1::uuid
           AND ($2::context_status IS NULL OR c.status = $2::context_status)
         ORDER BY c.started_at DESC
         LIMIT $3",
    )
    .bind(&ctx.owner_id)
    .bind(status.as_deref())
    .bind(limit)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to list contexts: {err}")))?;

    let contexts = rows
        .into_iter()
        .map(|row| ContextSummary {
            id: row.get("id"),
            status: row.get("status"),
            region: row.get("region"),
            started_at: row.get("started_at"),
            ended_at: row.get("ended_at"),
            package: row.get("package_name"),
            version: row.get("package_version"),
            last_activity: row.get("last_activity"),
        })
        .collect();

    Ok(Json(ListContextsResponse { contexts }))
}

async fn create_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateContextRequest>,
) -> Result<Json<CreateContextResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let status = normalize_context_status_required(request.status.trim())?;
    let region = request.region.trim();
    if region.is_empty() {
        return Err(ApiError::bad_request("region is required"));
    }

    let package_version_id = match (
        request.package.as_deref().map(str::trim),
        request.version.as_deref().map(str::trim),
    ) {
        (None, None) => None,
        (Some(package), Some(version)) if !package.is_empty() && !version.is_empty() => {
            let row = sqlx::query(
                "SELECT pv.id::text
                 FROM package_versions pv
                 JOIN packages p ON p.id = pv.package_id
                 WHERE p.owner_id = $1::uuid AND p.name = $2 AND pv.version = $3
                 LIMIT 1",
            )
            .bind(&ctx.owner_id)
            .bind(package)
            .bind(version)
            .fetch_optional(&ctx.pool)
            .await
            .map_err(|err| ApiError::internal(format!("failed package version lookup: {err}")))?;

            let Some(row) = row else {
                return Err(ApiError::not_found("package version not found"));
            };
            Some(row.get::<String, _>("id"))
        }
        _ => {
            return Err(ApiError::bad_request(
                "package and version must either both be set or both be omitted",
            ));
        }
    };

    let row = sqlx::query(
        "INSERT INTO contexts (owner_id, package_version_id, status, region)
         VALUES ($1::uuid, $2::uuid, $3::context_status, $4)
         RETURNING id::text, status::text AS status, region, started_at::text AS started_at, ended_at::text AS ended_at",
    )
    .bind(&ctx.owner_id)
    .bind(package_version_id.as_deref())
    .bind(&status)
    .bind(region)
    .fetch_one(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to create context: {err}")))?;

    Ok(Json(CreateContextResponse {
        context: ContextSummary {
            id: row.get("id"),
            status: row.get("status"),
            region: row.get("region"),
            started_at: row.get("started_at"),
            ended_at: row.get("ended_at"),
            package: request.package,
            version: request.version,
            last_activity: row.get("started_at"),
        },
    }))
}

async fn get_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(context_id): Path<String>,
) -> Result<Json<GetContextResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;

    let row = sqlx::query(
        "SELECT
            c.id::text,
            c.status::text AS status,
            c.region,
            c.started_at::text AS started_at,
            c.ended_at::text AS ended_at,
            p.name AS package_name,
            pv.version AS package_version,
            COALESCE(
                (SELECT MAX(l.ts)::text FROM context_logs l WHERE l.context_id = c.id),
                c.started_at::text
            ) AS last_activity
         FROM contexts c
         LEFT JOIN package_versions pv ON pv.id = c.package_version_id
         LEFT JOIN packages p ON p.id = pv.package_id
         WHERE c.owner_id = $1::uuid AND c.id = $2::uuid",
    )
    .bind(&ctx.owner_id)
    .bind(&context_id)
    .fetch_optional(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to load context: {err}")))?;

    let Some(row) = row else {
        return Err(ApiError::not_found("context not found"));
    };

    Ok(Json(GetContextResponse {
        context: ContextSummary {
            id: row.get("id"),
            status: row.get("status"),
            region: row.get("region"),
            started_at: row.get("started_at"),
            ended_at: row.get("ended_at"),
            package: row.get("package_name"),
            version: row.get("package_version"),
            last_activity: row.get("last_activity"),
        },
    }))
}

async fn update_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(context_id): Path<String>,
    Json(request): Json<UpdateContextRequest>,
) -> Result<Json<UpdateContextResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let status = normalize_context_status_required(request.status.trim())?;
    let mut tx = ctx
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::internal(format!("failed to start transaction: {err}")))?;

    let current = sqlx::query("SELECT status::text AS status FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid FOR UPDATE")
        .bind(&context_id)
        .bind(&ctx.owner_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| ApiError::internal(format!("failed to load context before update: {err}")))?;

    let Some(current) = current else {
        return Err(ApiError::not_found("context not found"));
    };
    let previous_status: String = current.get("status");

    sqlx::query(
        "UPDATE contexts
         SET status = $3::context_status,
             ended_at = CASE
               WHEN $3::context_status IN ('stopped', 'failed') THEN COALESCE(ended_at, now())
               ELSE NULL
             END
         WHERE id = $1::uuid AND owner_id = $2::uuid",
    )
    .bind(&context_id)
    .bind(&ctx.owner_id)
    .bind(&status)
    .execute(&mut *tx)
    .await
    .map_err(|err| ApiError::internal(format!("failed to update context: {err}")))?;

    if previous_status != status {
        let severity = audit_severity_for_context_status(&status);
        let message = format!("context status changed: {previous_status} -> {status}");
        let metadata = serde_json::json!({
            "event": "context.status_changed",
            "from": previous_status,
            "to": status,
            "actor_user_id": ctx.user_id,
            "source": "control-plane",
        });

        sqlx::query(
            "INSERT INTO context_logs (context_id, severity, message, metadata_json)
             VALUES ($1::uuid, $2, $3, $4::jsonb)",
        )
        .bind(&context_id)
        .bind(severity)
        .bind(message)
        .bind(metadata)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            ApiError::internal(format!("failed to write status-change audit log: {err}"))
        })?;
    }

    let row = sqlx::query(
        "SELECT
            c.id::text,
            c.status::text AS status,
            c.region,
            c.started_at::text AS started_at,
            c.ended_at::text AS ended_at,
            p.name AS package_name,
            pv.version AS package_version,
            COALESCE(
                (SELECT MAX(l.ts)::text FROM context_logs l WHERE l.context_id = c.id),
                c.started_at::text
            ) AS last_activity
         FROM contexts c
         LEFT JOIN package_versions pv ON pv.id = c.package_version_id
         LEFT JOIN packages p ON p.id = pv.package_id
         WHERE c.owner_id = $1::uuid AND c.id = $2::uuid",
    )
    .bind(&ctx.owner_id)
    .bind(&context_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| ApiError::internal(format!("failed to load updated context: {err}")))?;

    tx.commit()
        .await
        .map_err(|err| ApiError::internal(format!("failed to commit context update: {err}")))?;

    Ok(Json(UpdateContextResponse {
        context: ContextSummary {
            id: row.get("id"),
            status: row.get("status"),
            region: row.get("region"),
            started_at: row.get("started_at"),
            ended_at: row.get("ended_at"),
            package: row.get("package_name"),
            version: row.get("package_version"),
            last_activity: row.get("last_activity"),
        },
    }))
}

async fn list_context_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(context_id): Path<String>,
    Query(query): Query<ListContextLogsQuery>,
) -> Result<Json<ListContextLogsResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let limit = normalize_limit(query.limit, 50, 200);
    let from = normalize_rfc3339_timestamp("from", query.from)?;
    let to = normalize_rfc3339_timestamp("to", query.to)?;

    let context_exists =
        sqlx::query("SELECT 1 FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid LIMIT 1")
            .bind(&context_id)
            .bind(&ctx.owner_id)
            .fetch_optional(&ctx.pool)
            .await
            .map_err(|err| {
                ApiError::internal(format!("failed to verify context ownership: {err}"))
            })?;

    if context_exists.is_none() {
        return Err(ApiError::not_found("context not found"));
    }

    let rows = sqlx::query(
        "SELECT id, ts::text AS ts, severity, message, metadata_json
         FROM context_logs
         WHERE context_id = $1::uuid
           AND ($2::text IS NULL OR severity = $2)
           AND ($3::text IS NULL OR message ILIKE ('%' || $3 || '%'))
           AND ($4::bigint IS NULL OR id < $4)
           AND ($5::timestamptz IS NULL OR ts >= $5::timestamptz)
           AND ($6::timestamptz IS NULL OR ts <= $6::timestamptz)
         ORDER BY id DESC
         LIMIT $7",
    )
    .bind(&context_id)
    .bind(query.severity.as_deref())
    .bind(query.q.as_deref())
    .bind(query.before_id)
    .bind(from.as_deref())
    .bind(to.as_deref())
    .bind(limit)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to list context logs: {err}")))?;

    let logs: Vec<ContextLogEntry> = rows
        .into_iter()
        .map(|row| ContextLogEntry {
            id: row.get("id"),
            ts: row.get("ts"),
            severity: row.get("severity"),
            message: row.get("message"),
            metadata_json: row.get("metadata_json"),
        })
        .collect();
    let next_before_id = next_before_id_from_logs(&logs);

    Ok(Json(ListContextLogsResponse {
        context_id,
        logs,
        next_before_id,
    }))
}

async fn append_context_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(context_id): Path<String>,
    Json(request): Json<AppendContextLogRequest>,
) -> Result<Json<AppendContextLogResponse>, ApiError> {
    let ctx = request_ctx(&headers, &state).await?;
    let severity = normalize_log_severity(request.severity.trim())?;
    let message = request.message.trim();
    if message.is_empty() {
        return Err(ApiError::bad_request("message is required"));
    }

    let context_exists =
        sqlx::query("SELECT 1 FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid LIMIT 1")
            .bind(&context_id)
            .bind(&ctx.owner_id)
            .fetch_optional(&ctx.pool)
            .await
            .map_err(|err| {
                ApiError::internal(format!("failed to verify context ownership: {err}"))
            })?;

    if context_exists.is_none() {
        return Err(ApiError::not_found("context not found"));
    }

    let row = sqlx::query(
        "INSERT INTO context_logs (context_id, severity, message, metadata_json)
         VALUES ($1::uuid, $2, $3, $4::jsonb)
         RETURNING id, ts::text AS ts, severity, message, metadata_json",
    )
    .bind(&context_id)
    .bind(&severity)
    .bind(message)
    .bind(request.metadata_json)
    .fetch_one(&ctx.pool)
    .await
    .map_err(|err| ApiError::internal(format!("failed to append context log: {err}")))?;

    Ok(Json(AppendContextLogResponse {
        context_id,
        log: ContextLogEntry {
            id: row.get("id"),
            ts: row.get("ts"),
            severity: row.get("severity"),
            message: row.get("message"),
            metadata_json: row.get("metadata_json"),
        },
    }))
}

fn next_before_id_from_logs(logs: &[ContextLogEntry]) -> Option<i64> {
    logs.last().map(|entry| entry.id)
}

const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;

#[cfg(test)]
#[path = "../main_tests.rs"]
mod main_tests;
