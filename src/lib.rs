use inactu_verifier::{
    enforce_capability_ceiling, parse_manifest_json, parse_manifest_v1_draft_json,
    parse_policy_document, parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed,
    verify_receipt_hash,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const V0_SCHEMA_VERSION: &str = "0";
pub const EXPERIMENTAL_SCHEMA_VERSION: &str = "1.0.0-draft";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestVerification {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub artifact: String,
    pub capability_ceiling_ok: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptVerification {
    pub schema_version: String,
    pub artifact: String,
    pub receipt_hash: String,
    pub valid: bool,
}

pub fn hash_payload_sha256(payload: &str) -> String {
    sha256_prefixed(payload.as_bytes())
}

pub fn verify_manifest_value(
    manifest: &Value,
    policy: Option<&Value>,
) -> Result<ManifestVerification, String> {
    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|err| format!("manifest serialization failed: {err}"))?;
    let (schema_version, name, version, artifact, capabilities) = match schema_version(manifest) {
        Some(EXPERIMENTAL_SCHEMA_VERSION) => {
            let parsed = parse_manifest_v1_draft_json(&manifest_bytes)
                .map_err(|err| format!("invalid manifest: {err}"))?;
            (
                EXPERIMENTAL_SCHEMA_VERSION.to_string(),
                parsed.name.unwrap_or(parsed.id),
                parsed.version,
                parsed.artifact,
                parsed.capabilities,
            )
        }
        Some(version) => {
            return Err(format!(
                "invalid manifest: unsupported manifest schema version: {version}"
            ));
        }
        None => {
            let parsed = parse_manifest_json(&manifest_bytes)
                .map_err(|err| format!("invalid manifest: {err}"))?;
            (
                V0_SCHEMA_VERSION.to_string(),
                parsed.name,
                parsed.version,
                parsed.artifact,
                parsed.capabilities,
            )
        }
    };

    let capability_ceiling_ok = if let Some(policy_value) = policy {
        let policy_bytes = serde_json::to_vec(policy_value)
            .map_err(|err| format!("policy serialization failed: {err}"))?;
        let policy =
            parse_policy_document(&policy_bytes).map_err(|err| format!("invalid policy: {err}"))?;
        enforce_capability_ceiling(&capabilities, &policy)
            .map_err(|err| format!("capability check failed: {err}"))?;
        true
    } else {
        false
    };

    Ok(ManifestVerification {
        schema_version,
        name,
        version,
        artifact,
        capability_ceiling_ok,
    })
}

pub fn verify_receipt_value(receipt: &Value) -> Result<ReceiptVerification, String> {
    let receipt_bytes = serde_json::to_vec(receipt)
        .map_err(|err| format!("receipt serialization failed: {err}"))?;
    match schema_version(receipt) {
        Some(EXPERIMENTAL_SCHEMA_VERSION) => {
            let parsed = parse_receipt_v1_draft_json(&receipt_bytes)
                .map_err(|err| format!("invalid receipt: {err}"))?;
            Ok(ReceiptVerification {
                schema_version: EXPERIMENTAL_SCHEMA_VERSION.to_string(),
                artifact: parsed.artifact,
                receipt_hash: parsed.receipt_hash,
                valid: true,
            })
        }
        Some(version) => Err(format!(
            "invalid receipt: unsupported receipt schema version: {version}"
        )),
        None => {
            let parsed = parse_receipt_json(&receipt_bytes)
                .map_err(|err| format!("invalid receipt: {err}"))?;
            verify_receipt_hash(&parsed)
                .map_err(|err| format!("receipt verification failed: {err}"))?;
            Ok(ReceiptVerification {
                schema_version: V0_SCHEMA_VERSION.to_string(),
                artifact: parsed.artifact,
                receipt_hash: parsed.receipt_hash,
                valid: true,
            })
        }
    }
}

fn schema_version(value: &Value) -> Option<&str> {
    value.get("schema_version").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_is_stable() {
        assert_eq!(
            hash_payload_sha256("abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_manifest_v0_works() {
        let manifest = json!({
            "name":"echo.minimal",
            "version":"0.1.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[],
            "signers":["alice.dev"]
        });
        let out = verify_manifest_value(&manifest, None).expect("manifest should verify");
        assert_eq!(out.schema_version, V0_SCHEMA_VERSION);
        assert_eq!(out.name, "echo.minimal");
        assert!(!out.capability_ceiling_ok);
    }

    #[test]
    fn verify_receipt_v0_works() {
        let receipt = json!({
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "caps_used":["env:HOME"],
            "timestamp":1738600999,
            "receipt_hash":"sha256:ba1b6579a010096532ca31c2680f7345bda8beb5dd290a427d101e3b584c50e7"
        });
        let out = verify_receipt_value(&receipt).expect("receipt should verify");
        assert_eq!(out.schema_version, V0_SCHEMA_VERSION);
        assert!(out.valid);
    }
}
