use std::{net::SocketAddr, path::Path as FsPath, str::FromStr};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use inactu_verifier::{
    enforce_capability_ceiling, parse_manifest_json, parse_manifest_v1_draft_json,
    parse_policy_document, parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed,
    verify_receipt_hash,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{info, Level};

#[derive(Clone, Debug)]
struct AppState {
    service_name: &'static str,
    service_version: &'static str,
    database_enabled: bool,
    db_pool: Option<PgPool>,
    api_auth_secret: Option<String>,
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
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
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
    let manifest_bytes = serde_json::to_vec(&request.manifest)
        .map_err(|err| ApiError::bad_request(format!("manifest serialization failed: {err}")))?;
    let (schema_version, name, version, artifact, capabilities) =
        match schema_version(&request.manifest) {
            Some(EXPERIMENTAL_SCHEMA_VERSION) => {
                let manifest = parse_manifest_v1_draft_json(&manifest_bytes)
                    .map_err(|err| ApiError::bad_request(format!("invalid manifest: {err}")))?;
                (
                    EXPERIMENTAL_SCHEMA_VERSION.to_string(),
                    manifest.name.unwrap_or(manifest.id),
                    manifest.version,
                    manifest.artifact,
                    manifest.capabilities,
                )
            }
            Some(version) => {
                return Err(ApiError::bad_request(format!(
                    "invalid manifest: unsupported manifest schema version: {version}"
                )));
            }
            None => {
                let manifest = parse_manifest_json(&manifest_bytes)
                    .map_err(|err| ApiError::bad_request(format!("invalid manifest: {err}")))?;
                (
                    V0_SCHEMA_VERSION.to_string(),
                    manifest.name,
                    manifest.version,
                    manifest.artifact,
                    manifest.capabilities,
                )
            }
        };

    let capability_ceiling_ok = if let Some(policy_value) = request.policy {
        let policy_bytes = serde_json::to_vec(&policy_value)
            .map_err(|err| ApiError::bad_request(format!("policy serialization failed: {err}")))?;
        let policy = parse_policy_document(&policy_bytes)
            .map_err(|err| ApiError::bad_request(format!("invalid policy: {err}")))?;
        enforce_capability_ceiling(&capabilities, &policy)
            .map_err(|err| ApiError::bad_request(format!("capability check failed: {err}")))?;
        true
    } else {
        false
    };

    Ok(Json(VerifyManifestResponse {
        schema_version,
        name,
        version,
        artifact,
        capability_ceiling_ok,
    }))
}

async fn verify_receipt(
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<Json<VerifyReceiptResponse>, ApiError> {
    let receipt_bytes = serde_json::to_vec(&request.receipt)
        .map_err(|err| ApiError::bad_request(format!("receipt serialization failed: {err}")))?;
    match schema_version(&request.receipt) {
        Some(EXPERIMENTAL_SCHEMA_VERSION) => {
            let receipt = parse_receipt_v1_draft_json(&receipt_bytes)
                .map_err(|err| ApiError::bad_request(format!("invalid receipt: {err}")))?;
            Ok(Json(VerifyReceiptResponse {
                schema_version: EXPERIMENTAL_SCHEMA_VERSION.to_string(),
                artifact: receipt.artifact,
                receipt_hash: receipt.receipt_hash,
                valid: true,
            }))
        }
        Some(version) => Err(ApiError::bad_request(format!(
            "invalid receipt: unsupported receipt schema version: {version}"
        ))),
        None => {
            let receipt = parse_receipt_json(&receipt_bytes)
                .map_err(|err| ApiError::bad_request(format!("invalid receipt: {err}")))?;
            verify_receipt_hash(&receipt).map_err(|err| {
                ApiError::bad_request(format!("receipt verification failed: {err}"))
            })?;

            Ok(Json(VerifyReceiptResponse {
                schema_version: V0_SCHEMA_VERSION.to_string(),
                artifact: receipt.artifact,
                receipt_hash: receipt.receipt_hash,
                valid: true,
            }))
        }
    }
}

async fn hash_sha256(Json(request): Json<HashRequest>) -> Json<HashResponse> {
    Json(HashResponse {
        digest: sha256_prefixed(request.payload.as_bytes()),
    })
}

fn require_database(state: &AppState) -> Result<PgPool, ApiError> {
    state
        .db_pool
        .clone()
        .ok_or_else(|| ApiError::service_unavailable("database is not configured"))
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
    let _ = claims.exp;
    let _ = claims.iat;
    let _ = claims.iss;
    let _ = claims.aud;
    Ok(claims.sub)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;

    let rows = sqlx::query(
        "SELECT id::text, name, visibility::text AS visibility, description \
         FROM packages WHERE owner_id = $1::uuid ORDER BY name",
    )
    .bind(owner_id)
    .fetch_all(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
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
    .bind(owner_id)
    .bind(name)
    .bind(visibility)
    .bind(request.description)
    .fetch_one(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;

    let manifest_bytes = serde_json::to_vec(&request.manifest)
        .map_err(|err| ApiError::bad_request(format!("manifest serialization failed: {err}")))?;
    let manifest = parse_manifest_json(&manifest_bytes)
        .map_err(|err| ApiError::bad_request(format!("invalid manifest: {err}")))?;

    if manifest.name != package {
        return Err(ApiError::bad_request(
            "manifest name must match package path parameter",
        ));
    }

    let package_id = package_id_for_owner(&pool, &owner_id, &package).await?;

    let version_insert = sqlx::query(
        "INSERT INTO package_versions (package_id, version, artifact_digest, manifest_json, published_by_user_id) \
         VALUES ($1::uuid, $2, $3, $4::jsonb, $5::uuid)",
    )
    .bind(&package_id)
    .bind(&manifest.version)
    .bind(&manifest.artifact)
    .bind(request.manifest)
    .bind(&user_id)
    .execute(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    let package_id = package_id_for_owner(&pool, &owner_id, &package).await?;

    let rows = sqlx::query(
        "SELECT version, artifact_digest, published_at::text, deprecated_at::text \
         FROM package_versions WHERE package_id = $1::uuid ORDER BY published_at DESC",
    )
    .bind(package_id)
    .fetch_all(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    let package_id = package_id_for_owner(&pool, &owner_id, &package).await?;

    let row = sqlx::query(
        "UPDATE package_versions \
         SET deprecated_at = COALESCE(deprecated_at, now()) \
         WHERE package_id = $1::uuid AND version = $2 \
         RETURNING deprecated_at::text",
    )
    .bind(package_id)
    .bind(&version)
    .fetch_optional(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
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
    .bind(owner_id)
    .bind(status.as_deref())
    .bind(limit)
    .fetch_all(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
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
            .bind(&owner_id)
            .bind(package)
            .bind(version)
            .fetch_optional(&pool)
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
    .bind(&owner_id)
    .bind(package_version_id.as_deref())
    .bind(&status)
    .bind(region)
    .fetch_one(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;

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
    .bind(owner_id)
    .bind(&context_id)
    .fetch_optional(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    let status = normalize_context_status_required(request.status.trim())?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| ApiError::internal(format!("failed to start transaction: {err}")))?;

    let current = sqlx::query("SELECT status::text AS status FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid FOR UPDATE")
        .bind(&context_id)
        .bind(&owner_id)
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
    .bind(&owner_id)
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
            "actor_user_id": user_id,
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
    .bind(&owner_id)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    let limit = normalize_limit(query.limit, 50, 200);
    let from = normalize_rfc3339_timestamp("from", query.from)?;
    let to = normalize_rfc3339_timestamp("to", query.to)?;

    let context_exists =
        sqlx::query("SELECT 1 FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid LIMIT 1")
            .bind(&context_id)
            .bind(&owner_id)
            .fetch_optional(&pool)
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
    .fetch_all(&pool)
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
    let pool = require_database(&state)?;
    let user_id = current_user_id(&headers, &state)?;
    let owner_id = owner_id_for_user(&pool, &user_id).await?;
    let severity = normalize_log_severity(request.severity.trim())?;
    let message = request.message.trim();
    if message.is_empty() {
        return Err(ApiError::bad_request("message is required"));
    }

    let context_exists =
        sqlx::query("SELECT 1 FROM contexts WHERE id = $1::uuid AND owner_id = $2::uuid LIMIT 1")
            .bind(&context_id)
            .bind(&owner_id)
            .fetch_optional(&pool)
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
    .fetch_one(&pool)
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

const EXPERIMENTAL_SCHEMA_VERSION: &str = "1.0.0-draft";
const V0_SCHEMA_VERSION: &str = "0";

fn schema_version(value: &Value) -> Option<&str> {
    value.get("schema_version").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn test_state_with_database() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/inactu_control")
            .expect("connect_lazy should accept a valid postgres url");

        AppState {
            service_name: "inactu-control",
            service_version: "test",
            database_enabled: true,
            db_pool: Some(pool),
            api_auth_secret: Some("test-secret".to_string()),
        }
    }

    fn test_state_without_database() -> AppState {
        AppState {
            service_name: "inactu-control",
            service_version: "test",
            database_enabled: false,
            db_pool: None,
            api_auth_secret: Some("test-secret".to_string()),
        }
    }

    async fn json_error_message(response: Response) -> String {
        let value = json_body(response).await;
        value
            .get("error")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_string()
    }

    async fn json_body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&bytes).expect("response body should be json")
    }

    #[tokio::test]
    async fn verify_manifest_accepts_v0() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/manifest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"manifest":{"name":"echo.minimal","version":"0.1.0","entrypoint":"run","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capabilities":[],"signers":["alice.dev"]}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value.get("schema_version").and_then(Value::as_str),
            Some("0")
        );
        assert_eq!(
            value.get("name").and_then(Value::as_str),
            Some("echo.minimal")
        );
    }

    #[tokio::test]
    async fn verify_manifest_accepts_v1_draft() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/manifest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"manifest":{"schema_version":"1.0.0-draft","id":"echo.minimal","version":"0.2.0","entrypoint":"run","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inputs_schema":{"type":"object"},"outputs_schema":{"type":"object"},"capabilities":[],"signers":["alice.dev"]}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value.get("schema_version").and_then(Value::as_str),
            Some("1.0.0-draft")
        );
        assert_eq!(
            value.get("name").and_then(Value::as_str),
            Some("echo.minimal")
        );
    }

    #[tokio::test]
    async fn verify_manifest_rejects_unknown_schema_version() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/manifest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"manifest":{"schema_version":"9.9.9","name":"echo.minimal","version":"0.1.0","entrypoint":"run","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capabilities":[],"signers":["alice.dev"]}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let message = json_error_message(response).await;
        assert!(message.contains("unsupported manifest schema version"));
    }

    #[tokio::test]
    async fn verify_receipt_accepts_v0() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/receipt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"receipt":{"artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","caps_used":["env:HOME"],"timestamp":1738600999,"receipt_hash":"sha256:ba1b6579a010096532ca31c2680f7345bda8beb5dd290a427d101e3b584c50e7"}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value.get("schema_version").and_then(Value::as_str),
            Some("0")
        );
        assert_eq!(value.get("valid").and_then(Value::as_bool), Some(true));
    }

    #[tokio::test]
    async fn verify_receipt_accepts_v1_draft() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/receipt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"receipt":{"schema_version":"1.0.0-draft","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","policy_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222","bundle_hash":"sha256:abababababababababababababababababababababababababababababababab","inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_version_digest":"sha256:1212121212121212121212121212121212121212121212121212121212121212","result_digest":"sha256:3434343434343434343434343434343434343434343434343434343434343434","caps_requested":["env:HOME"],"caps_granted":["env:HOME"],"caps_used":["env:HOME"],"result":{"status":"success","code":"ok"},"runtime":{"name":"inactu","version":"0.1.0","profile":"v1-draft"},"started_at":1738600000,"finished_at":1738600999,"timestamp_strategy":"local_untrusted_unix_seconds","receipt_hash":"sha256:3333333333333333333333333333333333333333333333333333333333333333"}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value.get("schema_version").and_then(Value::as_str),
            Some("1.0.0-draft")
        );
        assert_eq!(value.get("valid").and_then(Value::as_bool), Some(true));
    }

    #[tokio::test]
    async fn verify_receipt_rejects_unknown_schema_version() {
        let app = router(test_state_without_database());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/receipt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"receipt":{"schema_version":"9.9.9","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","caps_used":["env:HOME"],"timestamp":1738600999,"receipt_hash":"sha256:ba1b6579a010096532ca31c2680f7345bda8beb5dd290a427d101e3b584c50e7"}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let message = json_error_message(response).await;
        assert!(message.contains("unsupported receipt schema version"));
    }

    #[tokio::test]
    async fn contexts_endpoints_require_bearer_auth() {
        let app = router(test_state_with_database());

        let contexts_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/contexts")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(contexts_response.status(), StatusCode::UNAUTHORIZED);

        let context_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/contexts/00000000-0000-0000-0000-000000000000")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(context_response.status(), StatusCode::UNAUTHORIZED);

        let patch_context_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/contexts/00000000-0000-0000-0000-000000000000")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"status":"running"}"#.to_string()))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(patch_context_response.status(), StatusCode::UNAUTHORIZED);

        let logs_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/contexts/00000000-0000-0000-0000-000000000000/logs")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(logs_response.status(), StatusCode::UNAUTHORIZED);

        let create_context_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/contexts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"status":"running","region":"local-dev"}"#.to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(create_context_response.status(), StatusCode::UNAUTHORIZED);

        let append_log_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/contexts/00000000-0000-0000-0000-000000000000/logs")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"severity":"info","message":"hello"}"#.to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
        assert_eq!(append_log_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn contexts_endpoints_reject_non_bearer_authorization() {
        let app = router(test_state_with_database());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/contexts")
                    .header("authorization", "Basic abc123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let message = json_error_message(response).await;
        assert_eq!(message, "authorization must be a bearer token");
    }

    #[tokio::test]
    async fn contexts_endpoints_require_database_configuration() {
        let app = router(test_state_without_database());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/contexts")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let message = json_error_message(response).await;
        assert_eq!(message, "database is not configured");
    }

    #[test]
    fn create_context_requires_valid_status() {
        let result = normalize_context_status_required("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn append_log_requires_valid_severity() {
        let result = normalize_log_severity("trace");
        assert!(result.is_err());
    }

    #[test]
    fn audit_severity_for_context_status_maps_failed_to_error() {
        assert_eq!(audit_severity_for_context_status("failed"), "error");
    }

    #[test]
    fn audit_severity_for_context_status_maps_stopped_to_warn() {
        assert_eq!(audit_severity_for_context_status("stopped"), "warn");
    }

    #[test]
    fn audit_severity_for_context_status_defaults_to_info() {
        assert_eq!(audit_severity_for_context_status("running"), "info");
    }

    #[test]
    fn normalize_rfc3339_timestamp_accepts_valid_values() {
        let value = normalize_rfc3339_timestamp("from", Some("2026-02-06T12:30:00Z".to_string()))
            .expect("timestamp should parse");
        assert_eq!(value.as_deref(), Some("2026-02-06T12:30:00Z"));
    }

    #[test]
    fn normalize_rfc3339_timestamp_rejects_invalid_values() {
        let result = normalize_rfc3339_timestamp("to", Some("not-a-timestamp".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn next_before_id_uses_oldest_log_id_in_page() {
        let logs = vec![
            ContextLogEntry {
                id: 120,
                ts: "2026-02-06T00:00:00Z".to_string(),
                severity: "info".to_string(),
                message: "newest".to_string(),
                metadata_json: None,
            },
            ContextLogEntry {
                id: 101,
                ts: "2026-02-05T23:59:00Z".to_string(),
                severity: "warn".to_string(),
                message: "oldest".to_string(),
                metadata_json: None,
            },
        ];

        assert_eq!(next_before_id_from_logs(&logs), Some(101));
    }

    #[test]
    fn next_before_id_is_none_for_empty_page() {
        let logs: Vec<ContextLogEntry> = vec![];
        assert_eq!(next_before_id_from_logs(&logs), None);
    }
}
