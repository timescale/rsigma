//! `MmdbEnricher`: look up an IP address in an operator-supplied MaxMind DB
//! (MMDB) file and inject the decoded record.
//!
//! Requires the **`mmdb-enrich`** feature. The database is not bundled: the
//! operator points `db_path` at a GeoLite2, GeoIP2, IP2Location, IP2Proxy,
//! ASN, or any other MMDB file. Records are decoded generically into
//! `serde_json::Value`, optionally projected through the configured `fields`
//! map, so no vendor-specific schema is assumed.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maxminddb::{PathElement, Reader};
use rsigma_eval::EvaluationResult;
use serde_json::Value;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    template::render_template,
};

/// Failure while looking up or decoding an MMDB record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmdbLookupError {
    /// The address could not be looked up (for example an IPv6 address
    /// against an IPv4-only database).
    Lookup(String),
    /// The record was found but could not be decoded or navigated.
    Decode(String),
}

impl std::fmt::Display for MmdbLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MmdbLookupError::Lookup(m) => write!(f, "lookup failed: {m}"),
            MmdbLookupError::Decode(m) => write!(f, "decode failed: {m}"),
        }
    }
}

impl std::error::Error for MmdbLookupError {}

/// One segment of a dotted field path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(usize),
}

impl Segment {
    fn path_element(&self) -> PathElement<'_> {
        match self {
            Segment::Key(key) => PathElement::Key(key.as_str()),
            Segment::Index(index) => PathElement::Index(*index),
        }
    }
}

/// A parsed `fields` map from an enricher config.
///
/// Each value is a dotted path into the MMDB record. A segment made only of
/// ASCII digits is an array index; every other segment is a map key. Parsing
/// rejects empty paths, empty segments, and out-of-range indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmdbFields(BTreeMap<String, Vec<Segment>>);

impl MmdbFields {
    /// Parse a raw `fields` map. The keys are the names written into the
    /// injected object; the values are dotted record paths.
    pub fn parse(raw: &BTreeMap<String, String>) -> Result<Self, String> {
        let mut fields = BTreeMap::new();
        for (name, path) in raw {
            if name.trim().is_empty() {
                return Err("field name must not be empty".to_string());
            }
            fields.insert(name.clone(), parse_segments(path)?);
        }
        Ok(Self(fields))
    }

    fn iter(&self) -> impl Iterator<Item = (&String, &Vec<Segment>)> {
        self.0.iter()
    }
}

fn parse_segments(path: &str) -> Result<Vec<Segment>, String> {
    if path.is_empty() {
        return Err("field path must not be empty".to_string());
    }
    path.split('.')
        .map(|segment| {
            if segment.is_empty() {
                return Err(format!("field path '{path}' has an empty segment"));
            }
            if segment.bytes().all(|b| b.is_ascii_digit()) {
                let index = segment.parse::<usize>().map_err(|_| {
                    format!("field path '{path}' has an out-of-range index '{segment}'")
                })?;
                Ok(Segment::Index(index))
            } else {
                Ok(Segment::Key(segment.to_string()))
            }
        })
        .collect()
}

enum LookupOutcome {
    Hit(Value),
    NoRecord,
    EmptyProjection,
}

/// A loaded MMDB database.
///
/// ```
/// use rsigma_runtime::MmdbDatabase;
///
/// let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mmdb/city-test.mmdb");
/// let db = MmdbDatabase::open(path).unwrap();
/// let record = db.lookup("192.0.2.10".parse().unwrap(), None).unwrap();
/// assert_eq!(record.unwrap()["country"]["iso_code"], "US");
/// ```
pub struct MmdbDatabase {
    path: Option<PathBuf>,
    reader: Reader<Vec<u8>>,
}

impl MmdbDatabase {
    /// Load an MMDB file into memory.
    ///
    /// The file is read eagerly rather than memory-mapped, so rewriting it in
    /// place cannot raise `SIGBUS`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let reader = Reader::open_readfile(&path).map_err(|e| e.to_string())?;
        Ok(Self {
            path: Some(path),
            reader,
        })
    }

    /// Build a database from bytes already in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let reader = Reader::from_source(bytes).map_err(|e| e.to_string())?;
        Ok(Self { path: None, reader })
    }

    /// The file this database was opened from, or `None` for
    /// [`Self::from_bytes`].
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Look up `ip` and decode it.
    ///
    /// Returns `Ok(None)` when the database has no record for `ip`, and also
    /// when `fields` is set but none of its paths exist in the record.
    pub fn lookup(
        &self,
        ip: IpAddr,
        fields: Option<&MmdbFields>,
    ) -> Result<Option<Value>, MmdbLookupError> {
        match self.lookup_outcome(ip, fields)? {
            LookupOutcome::Hit(value) => Ok(Some(value)),
            LookupOutcome::NoRecord | LookupOutcome::EmptyProjection => Ok(None),
        }
    }

    fn lookup_outcome(
        &self,
        ip: IpAddr,
        fields: Option<&MmdbFields>,
    ) -> Result<LookupOutcome, MmdbLookupError> {
        let result = self
            .reader
            .lookup(ip)
            .map_err(|e| MmdbLookupError::Lookup(e.to_string()))?;
        if !result.has_data() {
            return Ok(LookupOutcome::NoRecord);
        }

        let Some(fields) = fields else {
            let value = result
                .decode::<Value>()
                .map_err(|e| MmdbLookupError::Decode(e.to_string()))?;
            return Ok(LookupOutcome::Hit(value.unwrap_or(Value::Null)));
        };

        let mut projected = serde_json::Map::new();
        for (name, segments) in fields.iter() {
            let path: Vec<PathElement<'_>> = segments.iter().map(Segment::path_element).collect();
            let value: Option<Value> = result
                .decode_path(&path)
                .map_err(|e| MmdbLookupError::Decode(e.to_string()))?;
            if let Some(value) = value {
                projected.insert(name.clone(), value);
            }
        }
        if projected.is_empty() {
            Ok(LookupOutcome::EmptyProjection)
        } else {
            Ok(LookupOutcome::Hit(Value::Object(projected)))
        }
    }
}

/// MMDB lookup enricher.
///
/// ```
/// use std::collections::BTreeMap;
/// use std::sync::Arc;
/// use std::time::Duration;
/// use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
/// use rsigma_runtime::{
///     Enricher, EnricherKind, MmdbDatabase, MmdbEnricher, MmdbFields, OnError, Scope,
/// };
///
/// # #[tokio::main]
/// # async fn main() {
/// let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mmdb/city-test.mmdb");
/// let db = Arc::new(MmdbDatabase::open(path).unwrap());
/// let fields = MmdbFields::parse(&BTreeMap::from([(
///     "country".to_string(),
///     "country.iso_code".to_string(),
/// )]))
/// .unwrap();
/// let enricher = MmdbEnricher::new(
///     "geo".to_string(),
///     EnricherKind::Detection,
///     "geo".to_string(),
///     "${detection.fields.SourceIp}".to_string(),
///     Some(fields),
///     None,
///     Duration::from_secs(5),
///     OnError::Skip,
///     Scope::default(),
///     db,
/// );
///
/// let mut result = EvaluationResult {
///     header: RuleHeader {
///         rule_title: "example".to_string(),
///         rule_id: None,
///         level: None,
///         tags: Vec::new(),
///         custom_attributes: Arc::new(std::collections::HashMap::new()),
///         enrichments: None,
///     },
///     body: ResultBody::Detection(DetectionBody {
///         matched_selections: vec!["selection".to_string()],
///         matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!("192.0.2.10"))],
///         event: None,
///     }),
/// };
/// enricher.enrich(&mut result).await.unwrap();
/// assert_eq!(result.header.enrichments.unwrap()["geo"]["country"], "US");
/// # }
/// ```
pub struct MmdbEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    key_template: String,
    fields: Option<MmdbFields>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    db: Arc<MmdbDatabase>,
}

impl MmdbEnricher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        key_template: String,
        fields: Option<MmdbFields>,
        default: Option<Value>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        db: Arc<MmdbDatabase>,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            key_template,
            fields,
            default,
            timeout,
            on_error,
            scope,
            db,
        }
    }

    fn error(&self, kind: EnrichErrorKind) -> EnrichError {
        EnrichError {
            enricher_id: self.id.clone(),
            kind,
        }
    }
}

#[async_trait]
impl Enricher for MmdbEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        &self.inject_field
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let rendered = render_template(&self.key_template, result);
        let key = rendered.trim();
        if key.is_empty() {
            return Err(self.error(EnrichErrorKind::Fetch("key rendered empty".into())));
        }
        let ip: IpAddr = key.parse().map_err(|_| {
            self.error(EnrichErrorKind::Parse(format!(
                "key '{key}' is not an IP address"
            )))
        })?;

        let outcome = self
            .db
            .lookup_outcome(ip, self.fields.as_ref())
            .map_err(|e| match e {
                MmdbLookupError::Lookup(message) => self.error(EnrichErrorKind::Fetch(message)),
                MmdbLookupError::Decode(message) => self.error(EnrichErrorKind::Parse(message)),
            })?;

        match outcome {
            LookupOutcome::Hit(value) => {
                inject_enrichment(result, &self.inject_field, value);
                Ok(())
            }
            LookupOutcome::NoRecord => match &self.default {
                Some(default) => {
                    inject_enrichment(result, &self.inject_field, default.clone());
                    Ok(())
                }
                None => Err(self.error(EnrichErrorKind::Fetch(format!("no record for {ip}")))),
            },
            LookupOutcome::EmptyProjection => match &self.default {
                Some(default) => {
                    inject_enrichment(result, &self.inject_field, default.clone());
                    Ok(())
                }
                None => Err(self.error(EnrichErrorKind::Fetch(format!(
                    "no projected fields for {ip}"
                )))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;

    use super::*;

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/mmdb/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn detection_result(field: &str, value: Value) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "test".into(),
                rule_id: Some("rule-1".into()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["sel".into()],
                matched_fields: vec![FieldMatch::new(field, value)],
                event: None,
            }),
        }
    }

    fn enricher(
        db_path: &str,
        key: &str,
        fields: Option<MmdbFields>,
        default: Option<Value>,
    ) -> MmdbEnricher {
        MmdbEnricher::new(
            "geo".into(),
            EnricherKind::Detection,
            "geo".into(),
            key.into(),
            fields,
            default,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            Arc::new(MmdbDatabase::open(db_path).unwrap()),
        )
    }

    #[test]
    fn path_parsing_accepts_keys_and_indexes() {
        let raw = BTreeMap::from([("sub".to_string(), "subdivisions.0.iso_code".to_string())]);
        let fields = MmdbFields::parse(&raw).unwrap();
        assert_eq!(
            fields.0["sub"],
            vec![
                Segment::Key("subdivisions".into()),
                Segment::Index(0),
                Segment::Key("iso_code".into())
            ]
        );
    }

    #[test]
    fn path_parsing_rejects_empty_path_and_segments() {
        for bad in ["", ".country", "country.", "country..iso_code"] {
            let raw = BTreeMap::from([("x".to_string(), bad.to_string())]);
            assert!(
                MmdbFields::parse(&raw).is_err(),
                "path '{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn path_parsing_rejects_empty_field_name() {
        let raw = BTreeMap::from([("  ".to_string(), "country.iso_code".to_string())]);
        assert!(MmdbFields::parse(&raw).is_err());
    }

    #[test]
    fn projects_present_paths() {
        let db = MmdbDatabase::open(fixture("city-test.mmdb")).unwrap();
        let fields = MmdbFields::parse(&BTreeMap::from([
            ("country".to_string(), "country.iso_code".to_string()),
            (
                "subdivision".to_string(),
                "subdivisions.0.iso_code".to_string(),
            ),
        ]))
        .unwrap();
        let value = db
            .lookup("192.0.2.10".parse().unwrap(), Some(&fields))
            .unwrap()
            .unwrap();
        assert_eq!(value["country"], "US");
        assert_eq!(value["subdivision"], "WA");
    }

    #[test]
    fn missing_paths_are_omitted() {
        let db = MmdbDatabase::open(fixture("city-test.mmdb")).unwrap();
        let fields = MmdbFields::parse(&BTreeMap::from([
            ("country".to_string(), "country.iso_code".to_string()),
            ("missing".to_string(), "no.such.key".to_string()),
            ("index".to_string(), "subdivisions.9.iso_code".to_string()),
        ]))
        .unwrap();
        let value = db
            .lookup("192.0.2.10".parse().unwrap(), Some(&fields))
            .unwrap()
            .unwrap();
        assert_eq!(value, serde_json::json!({"country": "US"}));
    }

    #[test]
    fn empty_projection_is_a_miss() {
        let db = MmdbDatabase::open(fixture("city-test.mmdb")).unwrap();
        let fields =
            MmdbFields::parse(&BTreeMap::from([("x".to_string(), "no.such".to_string())])).unwrap();
        assert!(
            db.lookup("192.0.2.10".parse().unwrap(), Some(&fields))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn type_mismatch_is_a_decode_error() {
        let db = MmdbDatabase::open(fixture("city-test.mmdb")).unwrap();
        let fields = MmdbFields::parse(&BTreeMap::from([(
            "x".to_string(),
            "country.0".to_string(),
        )]))
        .unwrap();
        let err = db
            .lookup("192.0.2.10".parse().unwrap(), Some(&fields))
            .unwrap_err();
        assert!(matches!(err, MmdbLookupError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn full_record_decodes() {
        let db = MmdbDatabase::open(fixture("city-test.mmdb")).unwrap();
        let value = db
            .lookup("192.0.2.10".parse().unwrap(), None)
            .unwrap()
            .unwrap();
        assert_eq!(value["country"]["iso_code"], "US");
        assert_eq!(value["city"]["names"]["en"], "Seattle");
    }

    #[tokio::test]
    async fn empty_key_is_a_fetch_error() {
        let e = enricher(
            &fixture("city-test.mmdb"),
            "${detection.fields.Missing}",
            None,
            None,
        );
        let mut result = detection_result("SourceIp", serde_json::json!("192.0.2.10"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("key rendered empty")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn non_ip_key_is_a_parse_error() {
        let e = enricher(
            &fixture("city-test.mmdb"),
            "${detection.fields.Host}",
            None,
            None,
        );
        let mut result = detection_result("Host", serde_json::json!("web-01"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Parse(m) if m.contains("is not an IP address")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn ipv6_key_against_ipv4_database_is_a_fetch_error() {
        let e = enricher(
            &fixture("city-test-v4.mmdb"),
            "${detection.fields.SourceIp}",
            None,
            None,
        );
        let mut result = detection_result("SourceIp", serde_json::json!("2001:db8::1"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("IPv6")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn miss_without_default_is_a_fetch_error() {
        let e = enricher(
            &fixture("city-test.mmdb"),
            "${detection.fields.SourceIp}",
            None,
            None,
        );
        let mut result = detection_result("SourceIp", serde_json::json!("203.0.113.5"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("no record for")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn miss_with_default_injects_the_default() {
        let e = enricher(
            &fixture("city-test.mmdb"),
            "${detection.fields.SourceIp}",
            None,
            Some(serde_json::json!({"country_code": "unknown"})),
        );
        let mut result = detection_result("SourceIp", serde_json::json!("203.0.113.5"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["geo"],
            serde_json::json!({"country_code": "unknown"})
        );
    }

    #[tokio::test]
    async fn empty_projection_without_default_names_the_projection() {
        let fields =
            MmdbFields::parse(&BTreeMap::from([("x".to_string(), "no.such".to_string())])).unwrap();
        let e = enricher(
            &fixture("city-test.mmdb"),
            "${detection.fields.SourceIp}",
            Some(fields),
            None,
        );
        let mut result = detection_result("SourceIp", serde_json::json!("192.0.2.10"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("no projected fields")),
            "got {err}"
        );
    }
}
