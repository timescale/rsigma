//! `DnsEnricher`: resolve a template-expanded name through DNS and inject the
//! answers as presentation-format strings.
//!
//! Requires the **`dns-enrich`** feature. Answers are fetched from the system
//! resolver unless `nameservers` is set, and the record types available are the
//! data types hickory decodes without DNSSEC support. The pseudo-type `IP`
//! queries A and AAAA concurrently and merges the answers.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{Message, Query};
use hickory_resolver::proto::rr::{Name, RecordType};
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    template::render_template,
};

/// Record types this enricher accepts. Every entry is a data type hickory
/// decodes without DNSSEC support, so the display form does not depend on
/// which other features the binary was built with.
pub const SUPPORTED_DNS_RECORD_TYPES: &[&str] = &[
    "A",
    "AAAA",
    "ANAME",
    "CAA",
    "CERT",
    "CNAME",
    "CSYNC",
    "HINFO",
    "HTTPS",
    "MX",
    "NAPTR",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "SMIMEA",
    "SOA",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
];

/// The record types whose presentation format ends in a domain name.
const TRAILING_DOT_TYPES: &[RecordType] = &[
    RecordType::PTR,
    RecordType::CNAME,
    RecordType::NS,
    RecordType::ANAME,
    RecordType::MX,
    RecordType::SRV,
];

/// Default positive TTL cap for the response cache.
pub const DEFAULT_DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default negative TTL cap for the response cache.
pub const DEFAULT_DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Default cap on the number of cached responses.
pub const DEFAULT_DNS_CACHE_MAX_ENTRIES: u64 = 10_000;

/// A DNS record type this enricher can query.
///
/// `IP` is a pseudo-type that queries A and AAAA concurrently and merges the
/// answers. Every other variant is one hickory record type.
///
/// ```
/// use rsigma_runtime::DnsRecordType;
///
/// let record = DnsRecordType::parse("mx").unwrap();
/// assert_eq!(record.as_str(), "MX");
/// assert_eq!(record.query_name("mail.example.com").unwrap(), "mail.example.com.");
///
/// let ip = DnsRecordType::parse("IP").unwrap();
/// assert_eq!(ip.query_name("host.example.com").unwrap(), "host.example.com.");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// Query both A and AAAA and merge the answers.
    Ip,
    /// Query one data record type.
    Record(RecordType),
}

impl DnsRecordType {
    /// Parse a record type name. The value is case-insensitive, and the error
    /// lists the supported names.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let upper = raw.trim().to_ascii_uppercase();
        if upper == "IP" {
            return Ok(Self::Ip);
        }
        if !SUPPORTED_DNS_RECORD_TYPES.contains(&upper.as_str()) {
            return Err(format!(
                "unsupported record_type '{raw}' (supported: IP, {})",
                SUPPORTED_DNS_RECORD_TYPES.join(", ")
            ));
        }
        RecordType::from_str(&upper)
            .map(Self::Record)
            .map_err(|e| e.to_string())
    }

    /// The canonical name of this record type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Record(record_type) => Into::<&'static str>::into(*record_type),
        }
    }

    /// Return the fully qualified name that would be queried for `key`.
    ///
    /// `PTR` keys must be IP addresses and are converted to the reverse name.
    /// Every other type rejects an IP literal and parses the key as a domain
    /// name, applying IDNA. The result is lowercased and fully qualified, so
    /// the resolver never applies its search list.
    pub fn query_name(&self, key: &str) -> Result<String, String> {
        query_name_for(*self, key).map(|name| name.to_ascii())
    }

    /// Decode a wire-format DNS response and return the strings the enricher
    /// would inject for this record type.
    pub fn format_answers(&self, wire: &[u8]) -> Result<Vec<String>, String> {
        let message = Message::from_vec(wire).map_err(|e| e.to_string())?;
        Ok(format_message(*self, &message))
    }
}

/// Query names for one record type. `IP` yields two queries.
fn query_names(record_type: DnsRecordType, key: &str) -> Result<Vec<(Name, RecordType)>, String> {
    match record_type {
        DnsRecordType::Ip => {
            let name = parse_domain_name(key)?;
            Ok(vec![
                (name.clone(), RecordType::A),
                (name, RecordType::AAAA),
            ])
        }
        DnsRecordType::Record(RecordType::PTR) => {
            let ip: IpAddr = key
                .parse()
                .map_err(|_| format!("key '{key}' is not an IP address"))?;
            Ok(vec![(Name::from(ip.to_canonical()), RecordType::PTR)])
        }
        DnsRecordType::Record(record_type) => {
            let name = parse_domain_name(key)?;
            Ok(vec![(name, record_type)])
        }
    }
}

fn query_name_for(record_type: DnsRecordType, key: &str) -> Result<Name, String> {
    if key.is_empty() {
        return Err("key rendered empty".to_string());
    }
    let mut names = query_names(record_type, key)?;
    Ok(names.remove(0).0)
}

fn parse_domain_name(key: &str) -> Result<Name, String> {
    if key.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "key '{key}' is an IP address; use record_type: PTR"
        ));
    }
    let name = Name::from_utf8(key).map_err(|e| e.to_string())?;
    let mut name = name.to_lowercase();
    name.set_fqdn(true);
    Ok(name)
}

fn format_message(record_type: DnsRecordType, message: &Message) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    match record_type {
        DnsRecordType::Ip => {
            for wanted in [RecordType::A, RecordType::AAAA] {
                push_records(&mut out, &mut seen, wanted, message);
            }
        }
        DnsRecordType::Record(wanted) => push_records(&mut out, &mut seen, wanted, message),
    }
    out
}

fn push_records(
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
    wanted: RecordType,
    message: &Message,
) {
    for record in &message.answers {
        if record.record_type() != wanted {
            continue;
        }
        let mut rendered = record.data.to_string();
        if TRAILING_DOT_TYPES.contains(&wanted) && rendered.ends_with('.') {
            rendered.pop();
        }
        if seen.insert(rendered.clone()) {
            out.push(rendered);
        }
    }
}

/// Nameserver and cache settings for a [`DnsEnricher`].
#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    /// Explicit nameservers. Empty means the system resolver.
    pub nameservers: Vec<SocketAddr>,
    /// Per-request resolver timeout.
    pub timeout: Duration,
    /// Cap on positive record TTLs.
    pub cache_ttl: Duration,
    /// Cap on negative (NXDOMAIN and NODATA) TTLs.
    pub negative_cache_ttl: Duration,
    /// Maximum number of cached responses.
    pub cache_max_entries: u64,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            timeout: Duration::from_secs(5),
            cache_ttl: DEFAULT_DNS_CACHE_TTL,
            negative_cache_ttl: DEFAULT_DNS_NEGATIVE_CACHE_TTL,
            cache_max_entries: DEFAULT_DNS_CACHE_MAX_ENTRIES,
        }
    }
}

impl DnsResolverConfig {
    /// Parse one `nameservers` entry. The entry is an IP address with an
    /// optional port (`10.0.0.53`, `10.0.0.53:5353`, `[2001:db8::53]:5353`).
    /// Hostnames are rejected.
    pub fn parse_nameserver(raw: &str) -> Result<SocketAddr, String> {
        if raw.is_empty() {
            return Err("nameserver must not be empty".to_string());
        }
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return Ok(addr);
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, 53));
        }
        Err(format!(
            "invalid nameserver '{raw}' (expected an IP address or IP:port)"
        ))
    }
}

fn build_resolver(config: &DnsResolverConfig) -> Result<TokioResolver, String> {
    let mut builder = if config.nameservers.is_empty() {
        TokioResolver::builder_tokio().map_err(|e| e.to_string())?
    } else {
        let mut resolver_config = ResolverConfig::from_parts(None, vec![], vec![]);
        for addr in &config.nameservers {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            resolver_config.add_name_server(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
        }
        TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
    };
    let opts = builder.options_mut();
    opts.cache_size = 0;
    opts.timeout = config.timeout;
    opts.preserve_intermediates = true;
    builder.build().map_err(|e| e.to_string())
}

/// A DNS query backend. The production implementation wraps a hickory
/// resolver; unit tests inject a fake.
#[async_trait]
trait DnsBackend: Send + Sync {
    async fn query(&self, query: &Query) -> Result<Message, NetError>;
}

struct HickoryBackend {
    resolver: TokioResolver,
}

#[async_trait]
impl DnsBackend for HickoryBackend {
    async fn query(&self, query: &Query) -> Result<Message, NetError> {
        self.resolver
            .lookup(query.name().clone(), query.query_type())
            .await
            .map(Message::from)
    }
}

enum QueryOutcome {
    Answers(Vec<String>),
    Miss,
    Error(EnrichErrorKind),
}

/// DNS lookup enricher.
///
/// ```no_run
/// use std::time::Duration;
/// use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
/// use rsigma_runtime::{DnsEnricher, DnsRecordType, DnsResolverConfig, Enricher, EnricherKind, OnError, Scope};
///
/// # #[tokio::main]
/// # async fn main() {
/// let enricher = DnsEnricher::new(
///     "resolve".to_string(),
///     EnricherKind::Detection,
///     "ips".to_string(),
///     "${detection.fields.Domain}".to_string(),
///     DnsRecordType::parse("IP").unwrap(),
///     None,
///     None,
///     Duration::from_secs(5),
///     OnError::Skip,
///     Scope::default(),
///     DnsResolverConfig::default(),
/// )
/// .unwrap();
///
/// let mut result = EvaluationResult {
///     header: RuleHeader {
///         rule_title: "example".to_string(),
///         rule_id: None,
///         level: None,
///         tags: Vec::new(),
///         custom_attributes: std::sync::Arc::new(std::collections::HashMap::new()),
///         enrichments: None,
///     },
///     body: ResultBody::Detection(DetectionBody {
///         matched_selections: vec!["selection".to_string()],
///         matched_fields: vec![FieldMatch::new("Domain", serde_json::json!("example.com"))],
///         event: None,
///     }),
/// };
/// enricher.enrich(&mut result).await.unwrap();
/// # }
/// ```
pub struct DnsEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    key_template: String,
    record_type: DnsRecordType,
    extract: Option<ExtractExpr>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    backend: Arc<dyn DnsBackend>,
}

impl DnsEnricher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        key_template: String,
        record_type: DnsRecordType,
        extract: Option<ExtractExpr>,
        default: Option<Value>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        resolver: DnsResolverConfig,
    ) -> Result<Self, String> {
        let backend = Arc::new(HickoryBackend {
            resolver: build_resolver(&resolver)?,
        });
        Ok(Self {
            id,
            kind,
            inject_field,
            key_template,
            record_type,
            extract,
            default,
            timeout,
            on_error,
            scope,
            backend,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_backend(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        key_template: String,
        record_type: DnsRecordType,
        extract: Option<ExtractExpr>,
        default: Option<Value>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        backend: Arc<dyn DnsBackend>,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            key_template,
            record_type,
            extract,
            default,
            timeout,
            on_error,
            scope,
            backend,
        }
    }

    fn error(&self, kind: EnrichErrorKind) -> EnrichError {
        EnrichError {
            enricher_id: self.id.clone(),
            kind,
        }
    }

    async fn run_query(&self, name: Name, record_type: RecordType) -> QueryOutcome {
        let query = Query::query(name, record_type);
        match self.backend.query(&query).await {
            Ok(message) => {
                let answers = format_message(self.record_type, &message);
                if answers.is_empty() {
                    QueryOutcome::Miss
                } else {
                    QueryOutcome::Answers(answers)
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(_))) => QueryOutcome::Miss,
            Err(NetError::Timeout) => QueryOutcome::Error(EnrichErrorKind::Timeout),
            Err(e) => QueryOutcome::Error(EnrichErrorKind::Fetch(e.to_string())),
        }
    }

    fn maybe_extract(&self, value: Value) -> Result<Value, EnrichError> {
        match &self.extract {
            None => Ok(value),
            Some(expr) => crate::sources::extract::apply_extract(&value, expr)
                .map_err(|e| self.error(EnrichErrorKind::Extract(format!("{}", e.kind)))),
        }
    }
}

#[async_trait]
impl Enricher for DnsEnricher {
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

        let queries = query_names(self.record_type, key)
            .map_err(|message| self.error(EnrichErrorKind::Parse(message)))?;

        let outcomes = match queries.as_slice() {
            [(name, record_type)] => vec![self.run_query(name.clone(), *record_type).await],
            [(a_name, a_type), (aaaa_name, aaaa_type)] => {
                let (a, aaaa) = tokio::join!(
                    self.run_query(a_name.clone(), *a_type),
                    self.run_query(aaaa_name.clone(), *aaaa_type)
                );
                vec![a, aaaa]
            }
            _ => unreachable!("at most two queries are built"),
        };

        let mut answers = Vec::new();
        let mut first_error = None;
        let mut all_miss = true;
        for outcome in outcomes {
            match outcome {
                QueryOutcome::Answers(mut values) => {
                    all_miss = false;
                    answers.append(&mut values);
                }
                QueryOutcome::Miss => {}
                QueryOutcome::Error(kind) => {
                    all_miss = false;
                    if first_error.is_none() {
                        first_error = Some(kind);
                    }
                }
            }
        }

        if !answers.is_empty() {
            let value = self.maybe_extract(Value::Array(
                answers.into_iter().map(Value::String).collect(),
            ))?;
            inject_enrichment(result, &self.inject_field, value);
            return Ok(());
        }

        if let Some(kind) = first_error {
            return Err(self.error(kind));
        }

        debug_assert!(all_miss);
        match &self.default {
            Some(default) => {
                let value = self.maybe_extract(default.clone())?;
                inject_enrichment(result, &self.inject_field, value);
                Ok(())
            }
            None => Err(self.error(EnrichErrorKind::Fetch(format!(
                "no {} records for {key}",
                self.record_type.as_str()
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::rr::RData;
    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;

    use super::*;

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

    fn name(raw: &str) -> Name {
        Name::from_utf8(raw).unwrap()
    }

    fn message_with(
        query_name: &str,
        query_type: RecordType,
        answers: Vec<(Name, RData)>,
    ) -> Message {
        let mut message = Message::new(
            0,
            hickory_resolver::proto::op::MessageType::Response,
            hickory_resolver::proto::op::OpCode::Query,
        );
        message.add_query(Query::query(name(query_name), query_type));
        for (record_name, data) in answers {
            message.add_answer(hickory_resolver::proto::rr::Record::from_rdata(
                record_name,
                300,
                data,
            ));
        }
        message
    }

    fn a_message(query_name: &str, addresses: &[&str]) -> Message {
        message_with(
            query_name,
            RecordType::A,
            addresses
                .iter()
                .map(|ip| {
                    (
                        name(query_name),
                        RData::A(hickory_resolver::proto::rr::rdata::A(ip.parse().unwrap())),
                    )
                })
                .collect(),
        )
    }

    fn aaaa_message(query_name: &str, addresses: &[&str]) -> Message {
        message_with(
            query_name,
            RecordType::AAAA,
            addresses
                .iter()
                .map(|ip| {
                    (
                        name(query_name),
                        RData::AAAA(hickory_resolver::proto::rr::rdata::AAAA(
                            ip.parse().unwrap(),
                        )),
                    )
                })
                .collect(),
        )
    }

    fn mx_message(query_name: &str) -> Message {
        message_with(
            query_name,
            RecordType::MX,
            vec![(
                name(query_name),
                RData::MX(hickory_resolver::proto::rr::rdata::MX::new(
                    10,
                    name("mail.example.com."),
                )),
            )],
        )
    }

    fn ptr_message(query_name: &str) -> Message {
        message_with(
            query_name,
            RecordType::PTR,
            vec![(
                name(query_name),
                RData::PTR(hickory_resolver::proto::rr::rdata::PTR(name(
                    "host.example.com.",
                ))),
            )],
        )
    }

    fn no_records(query: Query) -> NetError {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            query,
            hickory_resolver::proto::op::ResponseCode::NXDomain,
        )))
    }

    struct FakeBackend {
        responses: Mutex<HashMap<(Name, RecordType), Result<Message, NetError>>>,
        calls: AtomicU64,
    }

    impl FakeBackend {
        fn new(responses: HashMap<(Name, RecordType), Result<Message, NetError>>) -> Self {
            Self {
                responses: Mutex::new(responses),
                calls: AtomicU64::new(0),
            }
        }

        #[allow(dead_code)]
        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DnsBackend for FakeBackend {
        async fn query(&self, query: &Query) -> Result<Message, NetError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses
                .lock()
                .unwrap()
                .get(&(query.name().clone(), query.query_type()))
                .cloned()
                .unwrap_or_else(|| Err(no_records(query.clone())))
        }
    }

    fn enricher(
        record_type: DnsRecordType,
        key: &str,
        default: Option<Value>,
        extract: Option<ExtractExpr>,
        backend: Arc<dyn DnsBackend>,
    ) -> DnsEnricher {
        DnsEnricher::with_backend(
            "dns".into(),
            EnricherKind::Detection,
            "out".into(),
            key.into(),
            record_type,
            extract,
            default,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            backend,
        )
    }

    fn responses(
        entries: Vec<((Name, RecordType), Result<Message, NetError>)>,
    ) -> HashMap<(Name, RecordType), Result<Message, NetError>> {
        entries.into_iter().collect()
    }

    #[test]
    fn record_type_parsing_is_case_insensitive() {
        assert_eq!(DnsRecordType::parse("a").unwrap().as_str(), "A");
        assert_eq!(DnsRecordType::parse("Mx").unwrap().as_str(), "MX");
        assert_eq!(DnsRecordType::parse("IP").unwrap(), DnsRecordType::Ip);
        for name in SUPPORTED_DNS_RECORD_TYPES {
            assert_eq!(DnsRecordType::parse(name).unwrap().as_str(), *name);
        }
    }

    #[test]
    fn record_type_parsing_rejects_unsupported_values() {
        for bad in ["ANY", "AXFR", "OPT", "RRSIG", "BOGUS"] {
            let err = DnsRecordType::parse(bad).unwrap_err();
            assert!(err.contains("unsupported record_type"), "got {err}");
            assert!(err.contains("supported: IP"), "got {err}");
        }
    }

    #[test]
    fn nameserver_parsing_accepts_ip_and_port_forms() {
        assert_eq!(
            DnsResolverConfig::parse_nameserver("10.0.0.53").unwrap(),
            "10.0.0.53:53".parse().unwrap()
        );
        assert_eq!(
            DnsResolverConfig::parse_nameserver("10.0.0.53:5353").unwrap(),
            "10.0.0.53:5353".parse().unwrap()
        );
        assert_eq!(
            DnsResolverConfig::parse_nameserver("2001:db8::53").unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        );
        assert_eq!(
            DnsResolverConfig::parse_nameserver("[2001:db8::53]:5353").unwrap(),
            "[2001:db8::53]:5353".parse().unwrap()
        );
    }

    #[test]
    fn nameserver_parsing_rejects_bad_values() {
        for bad in ["resolver.example.com", "", "10.0.0.53:99999"] {
            assert!(
                DnsResolverConfig::parse_nameserver(bad).is_err(),
                "'{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn query_names_are_lowercased_and_fully_qualified() {
        assert_eq!(
            DnsRecordType::parse("A")
                .unwrap()
                .query_name("Host.Example.COM")
                .unwrap(),
            "host.example.com."
        );
        assert_eq!(
            DnsRecordType::parse("A")
                .unwrap()
                .query_name("host.example.com.")
                .unwrap(),
            "host.example.com."
        );
    }

    #[test]
    fn query_names_apply_idna() {
        let name = DnsRecordType::parse("A")
            .unwrap()
            .query_name("bücher.example")
            .unwrap();
        assert!(name.starts_with("xn--"), "got {name}");
    }

    #[test]
    fn ptr_query_names_reverse_ips() {
        assert_eq!(
            DnsRecordType::parse("PTR")
                .unwrap()
                .query_name("192.0.2.10")
                .unwrap(),
            "10.2.0.192.in-addr.arpa."
        );
        assert_eq!(
            DnsRecordType::parse("PTR")
                .unwrap()
                .query_name("::ffff:192.0.2.10")
                .unwrap(),
            "10.2.0.192.in-addr.arpa."
        );
        assert_eq!(
            DnsRecordType::parse("PTR")
                .unwrap()
                .query_name("2001:db8::10")
                .unwrap(),
            "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn query_names_reject_wrong_key_forms() {
        let ptr_err = DnsRecordType::parse("PTR")
            .unwrap()
            .query_name("host.example.com")
            .unwrap_err();
        assert!(ptr_err.contains("is not an IP address"), "got {ptr_err}");

        let a_err = DnsRecordType::parse("A")
            .unwrap()
            .query_name("192.0.2.10")
            .unwrap_err();
        assert!(a_err.contains("use record_type: PTR"), "got {a_err}");

        let label = "a".repeat(64);
        assert!(
            DnsRecordType::parse("A")
                .unwrap()
                .query_name(&label)
                .is_err()
        );
        assert!(DnsRecordType::parse("A").unwrap().query_name("").is_err());
    }

    #[test]
    fn formatting_strips_trailing_dots_for_name_bearing_types() {
        let mx = DnsRecordType::parse("MX").unwrap();
        let wire = mx_message("example.com.").to_vec().unwrap();
        assert_eq!(
            mx.format_answers(&wire).unwrap(),
            vec!["10 mail.example.com"]
        );

        let ptr = DnsRecordType::parse("PTR").unwrap();
        let wire = ptr_message("10.2.0.192.in-addr.arpa.").to_vec().unwrap();
        assert_eq!(ptr.format_answers(&wire).unwrap(), vec!["host.example.com"]);
    }

    #[test]
    fn formatting_joins_txt_character_strings() {
        let txt = DnsRecordType::parse("TXT").unwrap();
        let message = message_with(
            "example.com.",
            RecordType::TXT,
            vec![(
                name("example.com."),
                RData::TXT(hickory_resolver::proto::rr::rdata::TXT::from_bytes(vec![
                    &b"v=spf1 ip4:192.0.2.0/24"[..],
                    &b" -all"[..],
                ])),
            )],
        );
        let wire = message.to_vec().unwrap();
        assert_eq!(
            txt.format_answers(&wire).unwrap(),
            vec!["v=spf1 ip4:192.0.2.0/24 -all"]
        );
    }

    #[test]
    fn formatting_dedupes_and_filters_chain_records() {
        let a = DnsRecordType::parse("A").unwrap();
        let message = message_with(
            "alias.example.com.",
            RecordType::A,
            vec![
                (
                    name("alias.example.com."),
                    RData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(name(
                        "host.example.com.",
                    ))),
                ),
                (
                    name("host.example.com."),
                    RData::A(hickory_resolver::proto::rr::rdata::A(
                        "192.0.2.10".parse().unwrap(),
                    )),
                ),
                (
                    name("host.example.com."),
                    RData::A(hickory_resolver::proto::rr::rdata::A(
                        "192.0.2.10".parse().unwrap(),
                    )),
                ),
            ],
        );
        let wire = message.to_vec().unwrap();
        assert_eq!(a.format_answers(&wire).unwrap(), vec!["192.0.2.10"]);
    }

    #[test]
    fn formatting_ip_lists_a_before_aaaa() {
        let ip = DnsRecordType::parse("IP").unwrap();
        let mut message = a_message("host.example.com.", &["192.0.2.10"]);
        for record in aaaa_message("host.example.com.", &["2001:db8::10"]).answers {
            message.add_answer(record);
        }
        let wire = message.to_vec().unwrap();
        assert_eq!(
            ip.format_answers(&wire).unwrap(),
            vec!["192.0.2.10", "2001:db8::10"]
        );
    }

    #[tokio::test]
    async fn empty_key_is_a_fetch_error() {
        let backend = Arc::new(FakeBackend::new(HashMap::new()));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Missing}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("key rendered empty")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn wrong_key_form_is_a_parse_error() {
        let backend = Arc::new(FakeBackend::new(HashMap::new()));
        let e = enricher(
            DnsRecordType::parse("PTR").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Parse(m) if m.contains("is not an IP address")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn miss_without_default_is_a_fetch_error() {
        let backend = Arc::new(FakeBackend::new(responses(vec![])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("missing.example.com"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("no A records for")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn miss_with_default_injects_the_default() {
        let backend = Arc::new(FakeBackend::new(responses(vec![])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("missing.example.com"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn timeout_maps_to_timeout() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Err(NetError::Timeout),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(matches!(err.kind, EnrichErrorKind::Timeout), "got {err}");
    }

    #[tokio::test]
    async fn servfail_maps_to_fetch() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Err(NetError::Dns(DnsError::ResponseCode(
                hickory_resolver::proto::op::ResponseCode::ServFail,
            ))),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        let err = e.enrich(&mut result).await.unwrap_err();
        assert!(
            matches!(&err.kind, EnrichErrorKind::Fetch(m) if m.contains("error response")),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn ip_with_one_side_nodata_injects_the_other_side() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let e = enricher(
            DnsRecordType::parse("IP").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!(["192.0.2.10"])
        );
    }

    #[tokio::test]
    async fn ip_with_both_sides_nodata_is_a_miss() {
        let backend = Arc::new(FakeBackend::new(HashMap::new()));
        let e = enricher(
            DnsRecordType::parse("IP").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("v4only.example.com"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn extract_applies_to_the_answer_array() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            Some(ExtractExpr::Jq(".[0]".into())),
            backend,
        );
        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!("192.0.2.10")
        );
    }
}
