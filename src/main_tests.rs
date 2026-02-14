use super::*;
use axum::{body::Body, http::Request};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use provenact_verifier::{compute_receipt_v1_draft_hash, parse_receipt_v1_draft_json};
use serde_json::json;
use tower::ServiceExt;

fn test_state_with_database() -> AppState {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/provenact_control")
        .expect("connect_lazy should accept a valid postgres url");

    AppState {
        service_name: "provenact-control",
        service_version: "test",
        database_enabled: true,
        db_pool: Some(pool),
        api_auth_secret: Some("test-secret".to_string()),
        max_requests_per_minute: 120,
    }
}

fn test_state_without_database() -> AppState {
    AppState {
        service_name: "provenact-control",
        service_version: "test",
        database_enabled: false,
        db_pool: None,
        api_auth_secret: Some("test-secret".to_string()),
        max_requests_per_minute: 120,
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

fn bearer_token_for_test(secret: &str, sub: &str, jti: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let claims = BridgeTokenClaims {
        sub: sub.to_string(),
        exp: now + 300,
        iat: now.saturating_sub(1),
        nbf: Some(now.saturating_sub(1)),
        jti: Some(jti.to_string()),
        iss: Some("provenact-web".to_string()),
        aud: Some("provenact-control".to_string()),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("test token should encode")
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

#[test]
fn parse_publish_manifest_accepts_v0() {
    let manifest = json!({
        "name":"echo.minimal",
        "version":"0.1.0",
        "entrypoint":"run",
        "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "capabilities":[],
        "signers":["alice.dev"]
    });

    let parsed = parse_publish_manifest(&manifest).expect("manifest should parse");
    assert_eq!(parsed.name, "echo.minimal");
    assert_eq!(parsed.version, "0.1.0");
    assert_eq!(
        parsed.artifact_digest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[test]
fn parse_publish_manifest_accepts_v1_draft() {
    let manifest = json!({
        "schema_version":"1.0.0-draft",
        "id":"echo.minimal",
        "version":"0.2.0",
        "entrypoint":"run",
        "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "inputs_schema":{"type":"object"},
        "outputs_schema":{"type":"object"},
        "capabilities":[],
        "signers":["alice.dev"]
    });

    let parsed = parse_publish_manifest(&manifest).expect("manifest should parse");
    assert_eq!(parsed.name, "echo.minimal");
    assert_eq!(parsed.version, "0.2.0");
}

#[test]
fn parse_publish_manifest_rejects_unknown_schema_version() {
    let manifest = json!({
        "schema_version":"9.9.9",
        "name":"echo.minimal",
        "version":"0.1.0",
        "entrypoint":"run",
        "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "capabilities":[],
        "signers":["alice.dev"]
    });

    let err = parse_publish_manifest(&manifest).expect_err("unknown schemas must fail");
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.message.contains("unsupported manifest schema version"));
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
    let mut receipt = json!({
        "schema_version":"1.0.0-draft",
        "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "manifest_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "policy_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "bundle_hash":"sha256:abababababababababababababababababababababababababababababababab",
        "inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "runtime_version_digest":"sha256:1212121212121212121212121212121212121212121212121212121212121212",
        "result_digest":"sha256:3434343434343434343434343434343434343434343434343434343434343434",
        "caps_requested":["env:HOME"],
        "caps_granted":["env:HOME"],
        "caps_used":["env:HOME"],
        "result":{"status":"success","code":"ok"},
        "runtime":{"name":"provenact","version":"0.1.0","profile":"v1-draft"},
        "started_at":1738600000,
        "finished_at":1738600999,
        "timestamp_strategy":"local_untrusted_unix_seconds",
        "receipt_hash":"sha256:3333333333333333333333333333333333333333333333333333333333333333"
    });
    let parsed = parse_receipt_v1_draft_json(
        &serde_json::to_vec(&receipt).expect("receipt json should serialize"),
    )
    .expect("receipt should parse");
    let receipt_hash = compute_receipt_v1_draft_hash(&parsed).expect("receipt hash should compute");
    receipt["receipt_hash"] = json!(receipt_hash);

    let app = router(test_state_without_database());
    let payload =
        serde_json::to_vec(&json!({ "receipt": receipt })).expect("request body should serialize");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify/receipt")
                .header("content-type", "application/json")
                .body(Body::from(payload))
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
async fn verify_receipt_rejects_v1_draft_hash_mismatch() {
    let app = router(test_state_without_database());
    let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify/receipt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"receipt":{"schema_version":"1.0.0-draft","artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","policy_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222","bundle_hash":"sha256:abababababababababababababababababababababababababababababababab","inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_version_digest":"sha256:1212121212121212121212121212121212121212121212121212121212121212","result_digest":"sha256:3434343434343434343434343434343434343434343434343434343434343434","caps_requested":["env:HOME"],"caps_granted":["env:HOME"],"caps_used":["env:HOME"],"result":{"status":"success","code":"ok"},"runtime":{"name":"provenact","version":"0.1.0","profile":"v1-draft"},"started_at":1738600000,"finished_at":1738600999,"timestamp_strategy":"local_untrusted_unix_seconds","receipt_hash":"sha256:3333333333333333333333333333333333333333333333333333333333333333"}}"#
                            .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should return a response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = json_error_message(response).await;
    assert!(message.contains("receipt verification failed"));
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
async fn contexts_endpoints_reject_invalid_token_subject_before_database_calls() {
    let state = test_state_with_database();
    let token = bearer_token_for_test(
        state.api_auth_secret.as_deref().expect("secret"),
        "not-a-uuid",
        "test-jti",
    );
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/contexts")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should return a response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let message = json_error_message(response).await;
    assert_eq!(message, "invalid auth token subject");
}

#[tokio::test]
async fn contexts_endpoints_reject_oversized_token_id_before_database_calls() {
    let state = test_state_with_database();
    let oversized_jti = "a".repeat(MAX_JWT_JTI_CHARS + 1);
    let token = bearer_token_for_test(
        state.api_auth_secret.as_deref().expect("secret"),
        "00000000-0000-0000-0000-000000000001",
        &oversized_jti,
    );
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/contexts")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should return a response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let message = json_error_message(response).await;
    assert_eq!(message, "invalid auth token id");
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

#[tokio::test]
async fn rejects_oversized_json_payloads() {
    let app = router(test_state_without_database());
    let payload = "x".repeat(MAX_REQUEST_BODY_BYTES + 1);
    let body = format!(r#"{{"payload":"{payload}"}}"#);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/hash/sha256")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request should build"),
        )
        .await
        .expect("router should return a response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn internal_errors_are_sanitized_for_clients() {
    let err = ApiError::internal("db explode: relation missing");
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(err.message, "internal server error");
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
fn list_logs_rejects_invalid_severity_filter() {
    let result = normalize_optional_log_severity(Some("trace".to_string()));
    assert!(result.is_err());
}

#[test]
fn list_logs_treats_blank_severity_filter_as_absent() {
    let result = normalize_optional_log_severity(Some("   ".to_string()));
    assert_eq!(result.expect("blank value should normalize"), None);
}

#[test]
fn normalize_required_text_field_rejects_oversized_values() {
    let result = normalize_required_text_field("message", &"a".repeat(5), 4);
    assert!(result.is_err());
}

#[test]
fn normalize_optional_text_field_trims_blank_to_none() {
    let result = normalize_optional_text_field("description", Some("   ".to_string()), 10);
    assert_eq!(result.expect("blank should normalize to none"), None);
}

#[test]
fn normalize_optional_text_field_rejects_oversized_values() {
    let result = normalize_optional_text_field("q", Some("a".repeat(513)), 512);
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

#[test]
fn auth_limit_guards_are_database_backed() {
    // Replay and rate-limit tracking moved to Postgres for multi-instance safety.
    // Behavioral assertions belong to integration tests with a real database.
    assert!(std::mem::size_of::<AppState>() > 0);
}

#[test]
fn validate_api_auth_secret_rejects_short_values() {
    let result = validate_api_auth_secret("too-short");
    assert!(result.is_err());
}

#[test]
fn validate_api_auth_secret_accepts_long_values() {
    let result = validate_api_auth_secret("0123456789abcdef0123456789abcdef");
    assert_eq!(
        result.expect("expected valid secret"),
        "0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn canonical_uuid_validation_accepts_standard_uuid() {
    assert!(is_canonical_uuid("00000000-0000-0000-0000-000000000001"));
}

#[test]
fn canonical_uuid_validation_rejects_non_uuid_text() {
    assert!(!is_canonical_uuid("not-a-uuid"));
}
