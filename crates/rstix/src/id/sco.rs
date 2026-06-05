//! SCO deterministic ID derivation.

use crate::core::{ScoKind, StixId};
use crate::id::{JcsError, jcs_canonicalize};

/// STIX namespace UUID for SCO deterministic IDs.
pub const STIX_SCO_NAMESPACE: uuid::Uuid = uuid::uuid!("00abedb4-aa42-466c-9c01-fed23315a9b7");

/// Errors for deterministic SCO ID generation.
#[derive(Debug, thiserror::Error)]
pub enum DeterministicIdError {
    /// SCO type was not recognized.
    #[error("unknown SCO type: {0}")]
    UnknownScoType(String),
    /// Canonicalization failed.
    #[error("JCS serialization failed: {0}")]
    JcsFailed(String),
}

fn clone_field(
    source: &serde_json::Value,
    key: &str,
    target: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_owned(), value.clone());
    }
}

fn pick_preferred_hash(
    source: &serde_json::Value,
    order: &[&str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let hashes = source.get("hashes")?.as_object()?;
    for key in order {
        if let Some(value) = hashes.get(*key) {
            let mut out = serde_json::Map::new();
            out.insert((*key).to_owned(), value.clone());
            return Some(out);
        }
    }
    if hashes.is_empty() {
        None
    } else {
        Some(hashes.clone())
    }
}

/// Select id-contributing properties for an SCO type.
pub fn select_id_contributing_properties(
    sco_type: ScoKind,
    full_value: &serde_json::Value,
) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    match sco_type {
        ScoKind::Artifact => {
            if full_value.get("payload_bin").is_some() {
                clone_field(full_value, "payload_bin", &mut result);
            } else {
                clone_field(full_value, "url", &mut result);
                clone_field(full_value, "hashes", &mut result);
            }
        }
        ScoKind::AutonomousSystem => clone_field(full_value, "number", &mut result),
        ScoKind::Directory => clone_field(full_value, "path", &mut result),
        ScoKind::DomainName => clone_field(full_value, "value", &mut result),
        ScoKind::EmailAddr => clone_field(full_value, "value", &mut result),
        ScoKind::EmailMessage => {
            clone_field(full_value, "from_ref", &mut result);
            clone_field(full_value, "subject", &mut result);
            clone_field(full_value, "date", &mut result);
        }
        ScoKind::File => {
            if let Some(hashes) = pick_preferred_hash(full_value, &["SHA-256", "SHA-1", "MD5"]) {
                result.insert("hashes".to_owned(), serde_json::Value::Object(hashes));
            } else {
                clone_field(full_value, "name", &mut result);
                clone_field(full_value, "parent_directory_ref", &mut result);
            }
        }
        ScoKind::Ipv4Addr | ScoKind::Ipv6Addr | ScoKind::MacAddr | ScoKind::Url => {
            clone_field(full_value, "value", &mut result);
        }
        ScoKind::Mutex => clone_field(full_value, "name", &mut result),
        ScoKind::NetworkTraffic => {
            clone_field(full_value, "dst_ref", &mut result);
            clone_field(full_value, "src_ref", &mut result);
            clone_field(full_value, "dst_port", &mut result);
            clone_field(full_value, "src_port", &mut result);
            clone_field(full_value, "protocols", &mut result);
        }
        ScoKind::Process => {
            clone_field(full_value, "pid", &mut result);
            clone_field(full_value, "command_line", &mut result);
            clone_field(full_value, "image_ref", &mut result);
        }
        ScoKind::Software => {
            clone_field(full_value, "name", &mut result);
            clone_field(full_value, "cpe", &mut result);
            clone_field(full_value, "vendor", &mut result);
            clone_field(full_value, "version", &mut result);
        }
        ScoKind::UserAccount => {
            clone_field(full_value, "account_type", &mut result);
            clone_field(full_value, "user_id", &mut result);
            clone_field(full_value, "account_login", &mut result);
        }
        ScoKind::WindowsRegistryKey => {
            clone_field(full_value, "key", &mut result);
            clone_field(full_value, "values", &mut result);
        }
        ScoKind::X509Certificate => {
            if let Some(hashes) = pick_preferred_hash(full_value, &["SHA-256"]) {
                result.insert("hashes".to_owned(), serde_json::Value::Object(hashes));
            } else {
                clone_field(full_value, "serial_number", &mut result);
                clone_field(full_value, "issuer", &mut result);
            }
        }
    }
    serde_json::Value::Object(result)
}

fn canonicalize_for_id(value: &serde_json::Value) -> Result<Vec<u8>, JcsError> {
    jcs_canonicalize(value)
}

/// Generate deterministic STIX SCO ID.
pub fn generate_sco_id(
    sco_type: ScoKind,
    full_value: &serde_json::Value,
) -> Result<StixId, DeterministicIdError> {
    let selected = select_id_contributing_properties(sco_type, full_value);
    let canonical = canonicalize_for_id(&selected)
        .map_err(|err| DeterministicIdError::JcsFailed(err.to_string()))?;
    let uuid = uuid::Uuid::new_v5(&STIX_SCO_NAMESPACE, &canonical);
    StixId::parse(&format!("{}--{uuid}", sco_type.as_str()))
        .map_err(|_| DeterministicIdError::UnknownScoType(sco_type.as_str().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_prefers_sha256_hash_for_selection() {
        let full = serde_json::json!({
            "hashes": {
                "SHA-256": "abc",
                "MD5": "def"
            },
            "name": "ignored",
            "size": 100
        });
        let selected = select_id_contributing_properties(ScoKind::File, &full);
        assert_eq!(
            selected,
            serde_json::json!({ "hashes": { "SHA-256": "abc" }})
        );
    }

    #[test]
    fn generated_id_has_expected_prefix_and_is_stable() {
        let full = serde_json::json!({ "value": "example.com" });
        let id1 = generate_sco_id(ScoKind::DomainName, &full).expect("id");
        let id2 = generate_sco_id(ScoKind::DomainName, &full).expect("id");
        assert_eq!(id1.as_str(), id2.as_str());
        assert!(id1.as_str().starts_with("domain-name--"));
    }

    #[test]
    fn all_sco_types_generate_prefixed_ids() {
        let cases = [
            (ScoKind::Artifact, serde_json::json!({"payload_bin":"aaa"})),
            (
                ScoKind::AutonomousSystem,
                serde_json::json!({"number": 1337}),
            ),
            (ScoKind::Directory, serde_json::json!({"path": "/tmp"})),
            (
                ScoKind::DomainName,
                serde_json::json!({"value": "example.com"}),
            ),
            (ScoKind::EmailAddr, serde_json::json!({"value": "a@b.test"})),
            (
                ScoKind::EmailMessage,
                serde_json::json!({"subject": "x", "date":"2024-01-01T00:00:00.000Z"}),
            ),
            (
                ScoKind::File,
                serde_json::json!({"hashes":{"SHA-256":"abc"}}),
            ),
            (
                ScoKind::Ipv4Addr,
                serde_json::json!({"value":"203.0.113.1"}),
            ),
            (
                ScoKind::Ipv6Addr,
                serde_json::json!({"value":"2001:db8::1"}),
            ),
            (
                ScoKind::MacAddr,
                serde_json::json!({"value":"AA:BB:CC:DD:EE:FF"}),
            ),
            (ScoKind::Mutex, serde_json::json!({"name":"m"})),
            (
                ScoKind::NetworkTraffic,
                serde_json::json!({"src_port":1,"dst_port":2,"protocols":["tcp"]}),
            ),
            (ScoKind::Process, serde_json::json!({"pid": 123})),
            (
                ScoKind::Software,
                serde_json::json!({"name":"x","version":"1.0"}),
            ),
            (
                ScoKind::Url,
                serde_json::json!({"value":"https://example.com"}),
            ),
            (
                ScoKind::UserAccount,
                serde_json::json!({"account_type":"unix","account_login":"root"}),
            ),
            (
                ScoKind::WindowsRegistryKey,
                serde_json::json!({"key":"HKEY_LOCAL_MACHINE\\\\x"}),
            ),
            (
                ScoKind::X509Certificate,
                serde_json::json!({"serial_number":"01","issuer":"CN=test"}),
            ),
        ];

        for (kind, payload) in cases {
            let generated = generate_sco_id(kind, &payload).expect("must generate id");
            assert!(
                generated
                    .as_str()
                    .starts_with(&format!("{}--", kind.as_str()))
            );
        }
    }
}
