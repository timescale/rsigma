//! SCO deterministic ID derivation.

use crate::core::{ScoKind, StixId};
use crate::id::{JcsError, jcs_canonicalize};

/// STIX namespace UUID for SCO deterministic IDs.
pub const STIX_SCO_NAMESPACE: uuid::Uuid = uuid::uuid!("00abedb4-aa42-466c-9c01-fed23315a9b7");

/// Errors for deterministic SCO ID generation.
#[derive(Debug, thiserror::Error)]
pub enum DeterministicIdError {
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
    // No preferred algorithm is present. STIX 2.1 still requires a single hash to
    // contribute to the ID, so fall back to the lexicographically first hash. This
    // is deterministic regardless of map ordering and matches python-stix2 for the
    // common single-hash case.
    let (key, value) = hashes.iter().min_by(|a, b| a.0.cmp(b.0))?;
    let mut out = serde_json::Map::new();
    out.insert(key.clone(), value.clone());
    Some(out)
}

/// Select id-contributing properties for an SCO type.
pub fn select_id_contributing_properties(
    sco_type: ScoKind,
    full_value: &serde_json::Value,
) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    match sco_type {
        ScoKind::Artifact => {
            clone_field(full_value, "hashes", &mut result);
            clone_field(full_value, "payload_bin", &mut result);
        }
        ScoKind::AutonomousSystem => clone_field(full_value, "number", &mut result),
        ScoKind::Directory => clone_field(full_value, "path", &mut result),
        ScoKind::DomainName => clone_field(full_value, "value", &mut result),
        ScoKind::EmailAddr => clone_field(full_value, "value", &mut result),
        ScoKind::EmailMessage => {
            clone_field(full_value, "from_ref", &mut result);
            clone_field(full_value, "subject", &mut result);
            clone_field(full_value, "body", &mut result);
        }
        ScoKind::File => {
            if let Some(hashes) =
                pick_preferred_hash(full_value, &["MD5", "SHA-1", "SHA-256", "SHA-512"])
            {
                result.insert("hashes".to_owned(), serde_json::Value::Object(hashes));
            }
            clone_field(full_value, "name", &mut result);
            clone_field(full_value, "extensions", &mut result);
            clone_field(full_value, "parent_directory_ref", &mut result);
        }
        ScoKind::Ipv4Addr | ScoKind::Ipv6Addr | ScoKind::MacAddr | ScoKind::Url => {
            clone_field(full_value, "value", &mut result);
        }
        ScoKind::Mutex => clone_field(full_value, "name", &mut result),
        ScoKind::NetworkTraffic => {
            clone_field(full_value, "start", &mut result);
            clone_field(full_value, "end", &mut result);
            clone_field(full_value, "dst_ref", &mut result);
            clone_field(full_value, "src_ref", &mut result);
            clone_field(full_value, "dst_port", &mut result);
            clone_field(full_value, "src_port", &mut result);
            clone_field(full_value, "protocols", &mut result);
            clone_field(full_value, "extensions", &mut result);
        }
        ScoKind::Process => {}
        ScoKind::Software => {
            clone_field(full_value, "name", &mut result);
            clone_field(full_value, "cpe", &mut result);
            clone_field(full_value, "swid", &mut result);
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
            if let Some(hashes) =
                pick_preferred_hash(full_value, &["MD5", "SHA-1", "SHA-256", "SHA-512"])
            {
                result.insert("hashes".to_owned(), serde_json::Value::Object(hashes));
            }
            clone_field(full_value, "serial_number", &mut result);
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
    if sco_type == ScoKind::Process {
        return Ok(StixId::generate(sco_type.as_str()));
    }

    let selected = select_id_contributing_properties(sco_type, full_value);
    if selected == serde_json::Value::Object(serde_json::Map::new()) {
        return Ok(StixId::generate(sco_type.as_str()));
    }

    let canonical = canonicalize_for_id(&selected)
        .map_err(|err| DeterministicIdError::JcsFailed(err.to_string()))?;
    let uuid = uuid::Uuid::new_v5(&STIX_SCO_NAMESPACE, &canonical);
    Ok(StixId::parse(&format!("{}--{uuid}", sco_type.as_str()))
        .expect("internal invariant: SCO type and generated UUID are always valid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_prefers_md5_hash_for_selection() {
        let full = serde_json::json!({
            "hashes": {
                "SHA-256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "MD5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "name": "name.bin",
            "extensions": {"archive-ext": {}},
            "parent_directory_ref": "directory--11111111-1111-4111-8111-111111111111",
            "size": 100
        });
        let selected = select_id_contributing_properties(ScoKind::File, &full);
        assert_eq!(
            selected,
            serde_json::json!({
                "hashes": { "MD5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
                "name": "name.bin",
                "extensions": {"archive-ext": {}},
                "parent_directory_ref": "directory--11111111-1111-4111-8111-111111111111"
            })
        );
    }

    #[test]
    fn generated_id_is_v4_for_process() {
        let full = serde_json::json!({ "pid": 123, "command_line": "cmd" });
        let id1 = generate_sco_id(ScoKind::Process, &full).expect("id");
        let id2 = generate_sco_id(ScoKind::Process, &full).expect("id");
        assert_ne!(id1.as_str(), id2.as_str());
        assert!(id1.as_str().starts_with("process--"));
        assert_eq!(id1.uuid().get_version_num(), 4);
        assert_eq!(id2.uuid().get_version_num(), 4);
    }

    #[test]
    fn generated_id_falls_back_to_v4_when_no_contributing_properties_present() {
        let full = serde_json::json!({ "size": 10 });
        let id1 = generate_sco_id(ScoKind::File, &full).expect("id");
        let id2 = generate_sco_id(ScoKind::File, &full).expect("id");
        assert_ne!(id1.as_str(), id2.as_str());
        assert!(id1.as_str().starts_with("file--"));
        assert_eq!(id1.uuid().get_version_num(), 4);
    }

    #[test]
    fn file_falls_back_to_non_preferred_hash_like_python_stix2() {
        // Only a non-preferred algorithm is present (no MD5/SHA-1/SHA-256/SHA-512).
        // The hash still contributes deterministically; golden value from python-stix2.
        let hash = "c".repeat(64);
        let full = serde_json::json!({ "hashes": { "SHA3-256": hash } });
        let id = generate_sco_id(ScoKind::File, &full).expect("file id");
        assert_eq!(id.as_str(), "file--2550c6b3-e138-5372-aefd-5e65053e724f");
        assert_eq!(id.uuid().get_version_num(), 5);
    }

    #[test]
    fn golden_vectors_match_python_stix2() {
        let artifact = serde_json::json!({
            "payload_bin": "dGVzdA==",
            "hashes": { "SHA-256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        });
        let file = serde_json::json!({
            "name": "foo.txt",
            "parent_directory_ref": "directory--11111111-1111-4111-8111-111111111111",
            "hashes": {
                "MD5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "SHA-256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "extensions": {
                "archive-ext": {
                    "contains_refs": ["file--22222222-2222-4222-8222-222222222222"]
                }
            }
        });
        let email_message = serde_json::json!({
            "from_ref": "email-addr--33333333-3333-4333-8333-333333333333",
            "subject": "hello",
            "body": "body"
        });
        let network_traffic = serde_json::json!({
            "protocols": ["tcp"],
            "src_ref": "ipv4-addr--44444444-4444-4444-8444-444444444444",
            "dst_ref": "ipv4-addr--55555555-5555-4555-8555-555555555555",
            "src_port": 1234,
            "dst_port": 80,
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-01T01:00:00Z",
            "extensions": {
                "http-request-ext": {
                    "request_method": "GET",
                    "request_value": "/"
                }
            }
        });
        let software = serde_json::json!({
            "name": "rstix",
            "cpe": "cpe:2.3:a:example:rstix:1.0:*:*:*:*:*:*:*",
            "swid": "swid-tag",
            "vendor": "example",
            "version": "1.0"
        });
        let x509 = serde_json::json!({
            "serial_number": "01",
            "hashes": {
                "MD5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "SHA-256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        });

        assert_eq!(
            generate_sco_id(ScoKind::Artifact, &artifact)
                .expect("artifact id")
                .as_str(),
            "artifact--e840f44d-fe94-56f3-aa0b-24f147d86ed8"
        );
        assert_eq!(
            generate_sco_id(ScoKind::File, &file)
                .expect("file id")
                .as_str(),
            "file--177e6ddf-e6fb-523d-87ca-58aa8d6fe731"
        );
        assert_eq!(
            generate_sco_id(ScoKind::EmailMessage, &email_message)
                .expect("email-message id")
                .as_str(),
            "email-message--109101d6-220e-537c-b64c-a0ca4bd8778e"
        );
        assert_eq!(
            generate_sco_id(ScoKind::NetworkTraffic, &network_traffic)
                .expect("network-traffic id")
                .as_str(),
            "network-traffic--a276fdf5-1bbf-551d-9882-fd6eaa812bb9"
        );
        assert_eq!(
            generate_sco_id(ScoKind::Software, &software)
                .expect("software id")
                .as_str(),
            "software--3a1bf50b-b60d-5386-8475-7adfa786496d"
        );
        assert_eq!(
            generate_sco_id(ScoKind::X509Certificate, &x509)
                .expect("x509 id")
                .as_str(),
            "x509-certificate--f695533e-97bd-5d44-9444-63bd3354e727"
        );
    }

    #[test]
    fn generated_id_has_expected_prefix_and_is_stable_for_non_process() {
        let full = serde_json::json!({ "value": "example.com" });
        let id1 = generate_sco_id(ScoKind::DomainName, &full).expect("id");
        let id2 = generate_sco_id(ScoKind::DomainName, &full).expect("id");
        assert_eq!(id1.as_str(), id2.as_str());
        assert!(id1.as_str().starts_with("domain-name--"));
        assert_eq!(id1.uuid().get_version_num(), 5);
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
                serde_json::json!({"from_ref":"email-addr--33333333-3333-4333-8333-333333333333","subject":"x","body":"text"}),
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
                serde_json::json!({
                    "src_ref":"ipv4-addr--44444444-4444-4444-8444-444444444444",
                    "dst_ref":"ipv4-addr--55555555-5555-4555-8555-555555555555",
                    "src_port":1,
                    "dst_port":2,
                    "protocols":["tcp"]
                }),
            ),
            (ScoKind::Process, serde_json::json!({"pid": 123})),
            (
                ScoKind::Software,
                serde_json::json!({"name":"x","swid":"swid-1","version":"1.0"}),
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
                serde_json::json!({"serial_number":"01","hashes":{"SHA-256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}),
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
