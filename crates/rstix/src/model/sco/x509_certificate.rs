//! STIX `x509-certificate` objects (STIX §6.18).

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// X.509 v3 extensions block (STIX §6.18.2).
///
/// When present on an [`X509Certificate`], at least one extension property must be set.
#[derive(Clone, Debug, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct X509V3Extensions {
    /// Basic constraints extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub basic_constraints: Option<String>,
    /// Name constraints extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name_constraints: Option<String>,
    /// Policy constraints extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub policy_constraints: Option<String>,
    /// Key usage extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub key_usage: Option<String>,
    /// Extended key usage extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub extended_key_usage: Option<String>,
    /// Subject key identifier extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_key_identifier: Option<String>,
    /// Authority key identifier extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub authority_key_identifier: Option<String>,
    /// Subject alternative name extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_alternative_name: Option<String>,
    /// Issuer alternative name extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub issuer_alternative_name: Option<String>,
    /// Subject directory attributes extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_directory_attributes: Option<String>,
    /// CRL distribution points extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub crl_distribution_points: Option<String>,
    /// Inhibit anyPolicy extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub inhibit_any_policy: Option<String>,
    /// Private key usage period start (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub private_key_usage_period_not_before: Option<StixTimestamp>,
    /// Private key usage period end (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub private_key_usage_period_not_after: Option<StixTimestamp>,
    /// Certificate policies extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub certificate_policies: Option<String>,
    /// Policy mappings extension (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub policy_mappings: Option<String>,
}

impl X509V3Extensions {
    fn has_property(&self) -> bool {
        self.basic_constraints.is_some()
            || self.name_constraints.is_some()
            || self.policy_constraints.is_some()
            || self.key_usage.is_some()
            || self.extended_key_usage.is_some()
            || self.subject_key_identifier.is_some()
            || self.authority_key_identifier.is_some()
            || self.subject_alternative_name.is_some()
            || self.issuer_alternative_name.is_some()
            || self.subject_directory_attributes.is_some()
            || self.crl_distribution_points.is_some()
            || self.inhibit_any_policy.is_some()
            || self.private_key_usage_period_not_before.is_some()
            || self.private_key_usage_period_not_after.is_some()
            || self.certificate_policies.is_some()
            || self.policy_mappings.is_some()
    }
}

/// An X.509 public-key certificate (STIX §6.18).
///
/// At least one type-specific property must be present per STIX §6.18.2. When
/// [`x509_v3_extensions`](Self::x509_v3_extensions) is set, it must contain at least one
/// extension field.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct X509Certificate {
    /// STIX object type (`x509-certificate`).
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_x509_certificate_type"
        )
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Whether the certificate is self-signed (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_self_signed: Option<bool>,
    /// Cryptographic hashes of the DER-encoded certificate (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
    /// Certificate version (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<String>,
    /// Serial number assigned by the issuer (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub serial_number: Option<String>,
    /// Signature algorithm used to sign the certificate (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub signature_algorithm: Option<String>,
    /// Distinguished name of the certificate issuer (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub issuer: Option<String>,
    /// Start of certificate validity period (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub validity_not_before: Option<StixTimestamp>,
    /// End of certificate validity period (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub validity_not_after: Option<StixTimestamp>,
    /// Distinguished name of the certificate subject (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject: Option<String>,
    /// Algorithm used for the subject public key (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_public_key_algorithm: Option<String>,
    /// Modulus of the RSA subject public key (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_public_key_modulus: Option<String>,
    /// Exponent of the RSA subject public key (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject_public_key_exponent: Option<u64>,
    /// X.509 v3 extensions present on the certificate (STIX §6.18.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub x509_v3_extensions: Option<X509V3Extensions>,
}

impl X509Certificate {
    /// STIX type name for X.509 certificates.
    pub const TYPE_NAME: &'static str = "x509-certificate";

    /// Check certificate invariants (at least one property; non-empty extensions block).
    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.has_specific_property() {
            return Err(ModelError::X509CertificateNoProperties);
        }
        if let Some(ext) = &self.x509_v3_extensions
            && !ext.has_property()
        {
            return Err(ModelError::X509V3ExtensionsNoProperties);
        }
        Ok(())
    }

    fn has_specific_property(&self) -> bool {
        self.is_self_signed.is_some()
            || !self.hashes.is_empty()
            || self.version.is_some()
            || self.serial_number.is_some()
            || self.signature_algorithm.is_some()
            || self.issuer.is_some()
            || self.validity_not_before.is_some()
            || self.validity_not_after.is_some()
            || self.subject.is_some()
            || self.subject_public_key_algorithm.is_some()
            || self.subject_public_key_modulus.is_some()
            || self.subject_public_key_exponent.is_some()
            || self.x509_v3_extensions.is_some()
    }
}

#[cfg(feature = "serde")]
fn deserialize_x509_certificate_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, X509Certificate::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for X509Certificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_x509_certificate_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            is_self_signed: Option<bool>,
            #[serde(default)]
            hashes: BTreeMap<String, String>,
            #[serde(default)]
            version: Option<String>,
            #[serde(default)]
            serial_number: Option<String>,
            #[serde(default)]
            signature_algorithm: Option<String>,
            #[serde(default)]
            issuer: Option<String>,
            #[serde(default)]
            validity_not_before: Option<StixTimestamp>,
            #[serde(default)]
            validity_not_after: Option<StixTimestamp>,
            #[serde(default)]
            subject: Option<String>,
            #[serde(default)]
            subject_public_key_algorithm: Option<String>,
            #[serde(default)]
            subject_public_key_modulus: Option<String>,
            #[serde(default)]
            subject_public_key_exponent: Option<u64>,
            #[serde(default)]
            x509_v3_extensions: Option<X509V3Extensions>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            is_self_signed: raw.is_self_signed,
            hashes: raw.hashes,
            version: raw.version,
            serial_number: raw.serial_number,
            signature_algorithm: raw.signature_algorithm,
            issuer: raw.issuer,
            validity_not_before: raw.validity_not_before,
            validity_not_after: raw.validity_not_after,
            subject: raw.subject,
            subject_public_key_algorithm: raw.subject_public_key_algorithm,
            subject_public_key_modulus: raw.subject_public_key_modulus,
            subject_public_key_exponent: raw.subject_public_key_exponent,
            x509_v3_extensions: raw.x509_v3_extensions,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for X509Certificate {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        self.common.spec_version
    }

    fn created(&self) -> Option<&StixTimestamp> {
        None
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["is_self_signed"] => self.is_self_signed.map(QueryValue::Bool),
            ["hashes", key] => self
                .hashes
                .get(*key)
                .map(String::as_str)
                .map(QueryValue::Str),
            ["version"] => self.version.as_deref().map(QueryValue::Str),
            ["serial_number"] => self.serial_number.as_deref().map(QueryValue::Str),
            ["signature_algorithm"] => self.signature_algorithm.as_deref().map(QueryValue::Str),
            ["issuer"] => self.issuer.as_deref().map(QueryValue::Str),
            ["subject"] => self.subject.as_deref().map(QueryValue::Str),
            ["validity_not_before"] => self.validity_not_before.as_ref().map(QueryValue::Timestamp),
            ["validity_not_after"] => self.validity_not_after.as_ref().map(QueryValue::Timestamp),
            ["subject_public_key_algorithm"] => self
                .subject_public_key_algorithm
                .as_deref()
                .map(QueryValue::Str),
            ["subject_public_key_modulus"] => self
                .subject_public_key_modulus
                .as_deref()
                .map(QueryValue::Str),
            ["subject_public_key_exponent"] => self
                .subject_public_key_exponent
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["x509_v3_extensions"] if self.x509_v3_extensions.is_some() => Some(QueryValue::Null),
            ["x509_v3_extensions", field] => {
                self.x509_v3_extensions
                    .as_ref()
                    .and_then(|ext| match *field {
                        "basic_constraints" => {
                            ext.basic_constraints.as_deref().map(QueryValue::Str)
                        }
                        "name_constraints" => ext.name_constraints.as_deref().map(QueryValue::Str),
                        "policy_constraints" => {
                            ext.policy_constraints.as_deref().map(QueryValue::Str)
                        }
                        "key_usage" => ext.key_usage.as_deref().map(QueryValue::Str),
                        "extended_key_usage" => {
                            ext.extended_key_usage.as_deref().map(QueryValue::Str)
                        }
                        "subject_key_identifier" => {
                            ext.subject_key_identifier.as_deref().map(QueryValue::Str)
                        }
                        "authority_key_identifier" => {
                            ext.authority_key_identifier.as_deref().map(QueryValue::Str)
                        }
                        "subject_alternative_name" => {
                            ext.subject_alternative_name.as_deref().map(QueryValue::Str)
                        }
                        "issuer_alternative_name" => {
                            ext.issuer_alternative_name.as_deref().map(QueryValue::Str)
                        }
                        "subject_directory_attributes" => ext
                            .subject_directory_attributes
                            .as_deref()
                            .map(QueryValue::Str),
                        "crl_distribution_points" => {
                            ext.crl_distribution_points.as_deref().map(QueryValue::Str)
                        }
                        "inhibit_any_policy" => {
                            ext.inhibit_any_policy.as_deref().map(QueryValue::Str)
                        }
                        "certificate_policies" => {
                            ext.certificate_policies.as_deref().map(QueryValue::Str)
                        }
                        "policy_mappings" => ext.policy_mappings.as_deref().map(QueryValue::Str),
                        "private_key_usage_period_not_before" => ext
                            .private_key_usage_period_not_before
                            .as_ref()
                            .map(QueryValue::Timestamp),
                        "private_key_usage_period_not_after" => ext
                            .private_key_usage_period_not_after
                            .as_ref()
                            .map(QueryValue::Timestamp),
                        _ => None,
                    })
            }
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<X509Certificate>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `x509-certificate`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/x509-certificate-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<X509Certificate>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
