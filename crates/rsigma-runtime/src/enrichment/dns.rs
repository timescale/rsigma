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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{Message, Query};
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::{ResponseCache, TokioResolver, TtlConfig};
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;

use crate::metrics::{MetricsHook, NoopMetrics};

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, empty_key_message,
    inject_enrichment, render_enricher_template,
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

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Per-enricher DNS response cache.
///
/// The resolver is built with hickory's internal cache disabled, so this is
/// the only cache on the query path. Negative answers (NXDOMAIN and NODATA)
/// are cached from the SOA TTL clamped to `negative_cache_ttl`; transient
/// errors are never cached.
struct DnsCache {
    cache: Option<ResponseCache>,
    clock: Clock,
    enricher_id: String,
    metrics: Arc<dyn MetricsHook>,
}

impl DnsCache {
    fn new(
        config: &DnsResolverConfig,
        clock: Clock,
        enricher_id: String,
        metrics: Arc<dyn MetricsHook>,
    ) -> Self {
        if config.cache_ttl.is_zero() && config.negative_cache_ttl.is_zero() {
            return Self {
                cache: None,
                clock,
                enricher_id,
                metrics,
            };
        }
        let mut opts = ResolverOpts::default();
        opts.positive_max_ttl = Some(config.cache_ttl);
        opts.negative_max_ttl = Some(config.negative_cache_ttl);
        let ttl_config = TtlConfig::from_opts(&opts);
        Self {
            cache: Some(ResponseCache::new(config.cache_max_entries, ttl_config)),
            clock,
            enricher_id,
            metrics,
        }
    }

    fn get(&self, query: &Query) -> Option<Result<Message, NetError>> {
        let cached = self
            .cache
            .as_ref()
            .and_then(|cache| cache.get(query, (self.clock)()));
        match cached {
            Some(result) => {
                self.metrics.on_enrichment_dns_cache_hit(&self.enricher_id);
                Some(result)
            }
            None => {
                self.metrics.on_enrichment_dns_cache_miss(&self.enricher_id);
                None
            }
        }
    }

    fn insert(&self, query: Query, result: Result<Message, NetError>) {
        if let Some(cache) = &self.cache {
            cache.insert(query, result, (self.clock)());
        }
    }
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

/// Classify a backend result for the `rsigma_enrichment_dns_queries_total`
/// `result` label.
fn query_result_label(query_type: RecordType, result: &Result<Message, NetError>) -> &'static str {
    match result {
        Ok(message)
            if message
                .answers
                .iter()
                .any(|r| r.record_type() == query_type) =>
        {
            "answer"
        }
        Ok(_) => "no_records",
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => "no_records",
        Err(_) => "error",
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
///         tenant_id: None,
///         level: None,
///         tags: Vec::new(),
///         custom_attributes: std::sync::Arc::new(std::collections::HashMap::new()),
///         enrichments: None,
///         ruleset: None,
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
    on_miss: OnError,
    scope: Scope,
    backend: Arc<dyn DnsBackend>,
    cache: DnsCache,
    metrics: Arc<dyn MetricsHook>,
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
        let cache = DnsCache::new(
            &resolver,
            Arc::new(Instant::now),
            id.clone(),
            Arc::new(NoopMetrics),
        );
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
            on_miss: on_error,
            scope,
            backend,
            cache,
            metrics: Arc::new(NoopMetrics),
        })
    }

    /// Set the policy applied when this enricher finds no data
    /// ([`EnrichErrorKind::Miss`]). Defaults to the `on_error` policy.
    pub fn with_on_miss(mut self, on_miss: OnError) -> Self {
        self.on_miss = on_miss;
        self
    }

    /// Report this enricher's cache and query counters into `metrics`.
    ///
    /// Pre-registers the label sets so the counters appear on `/metrics` from
    /// startup.
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsHook>) -> Self {
        metrics.register_dns_enricher(&self.id);
        self.cache.enricher_id = self.id.clone();
        self.cache.metrics = Arc::clone(&metrics);
        self.metrics = metrics;
        self
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
        resolver: DnsResolverConfig,
        clock: Clock,
    ) -> Self {
        let cache = DnsCache::new(&resolver, clock, id.clone(), Arc::new(NoopMetrics));
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
            on_miss: on_error,
            scope,
            backend,
            cache,
            metrics: Arc::new(NoopMetrics),
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
        if let Some(result) = self.cache.get(&query) {
            return self.outcome_from_result(result);
        }
        let result = self.backend.query(&query).await;
        self.metrics
            .on_enrichment_dns_query(&self.id, query_result_label(query.query_type(), &result));
        self.cache.insert(query, result.clone());
        self.outcome_from_result(result)
    }

    fn outcome_from_result(&self, result: Result<Message, NetError>) -> QueryOutcome {
        match result {
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
    fn on_miss(&self) -> OnError {
        self.on_miss
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let rendered = render_enricher_template(&self.key_template, result);
        let key = rendered.trim();
        if key.is_empty() {
            return Err(self.error(EnrichErrorKind::Fetch(empty_key_message(
                &self.key_template,
            ))));
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
                inject_enrichment(result, &self.inject_field, default.clone());
                Ok(())
            }
            None => Err(self.error(EnrichErrorKind::Miss(format!(
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
                tenant_id: None,
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
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

    fn no_records_with_soa(query: Query, negative_ttl: u32) -> NetError {
        let mut records =
            NoRecords::new(query, hickory_resolver::proto::op::ResponseCode::NXDomain);
        records.negative_ttl = Some(negative_ttl);
        NetError::Dns(DnsError::NoRecordsFound(records))
    }

    /// A clock the tests can move forward without sleeping.
    struct TestClock {
        offset_secs: AtomicU64,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                offset_secs: AtomicU64::new(0),
            })
        }

        fn advance(&self, duration: Duration) {
            self.offset_secs
                .fetch_add(duration.as_secs(), Ordering::SeqCst);
        }

        fn clock(self: &Arc<Self>) -> Clock {
            let clock = Arc::clone(self);
            Arc::new(move || {
                Instant::now() + Duration::from_secs(clock.offset_secs.load(Ordering::SeqCst))
            })
        }
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
        enricher_with_config(
            record_type,
            key,
            default,
            extract,
            backend,
            DnsResolverConfig::default(),
            Arc::new(Instant::now),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enricher_with_config(
        record_type: DnsRecordType,
        key: &str,
        default: Option<Value>,
        extract: Option<ExtractExpr>,
        backend: Arc<dyn DnsBackend>,
        resolver: DnsResolverConfig,
        clock: Clock,
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
            resolver,
            clock,
        )
    }

    fn responses(
        entries: Vec<((Name, RecordType), Result<Message, NetError>)>,
    ) -> HashMap<(Name, RecordType), Result<Message, NetError>> {
        entries.into_iter().collect()
    }

    #[derive(Default)]
    struct CollectingMetrics {
        hits: Mutex<Vec<String>>,
        misses: Mutex<Vec<String>>,
        queries: Mutex<Vec<(String, &'static str)>>,
        registered: Mutex<Vec<String>>,
    }

    impl MetricsHook for CollectingMetrics {
        fn on_parse_error(&self) {}
        fn on_events_processed(&self, _: u64) {}
        fn on_detection_matches(&self, _: u64) {}
        fn on_correlation_matches(&self, _: u64) {}
        fn observe_processing_latency(&self, _: f64) {}
        fn on_input_queue_depth_change(&self, _: i64) {}
        fn on_back_pressure(&self) {}
        fn observe_batch_size(&self, _: u64) {}
        fn on_output_queue_depth_change(&self, _: i64) {}
        fn observe_pipeline_latency(&self, _: f64) {}
        fn set_correlation_state_entries(&self, _: u64) {}
        fn on_enrichment_dns_cache_hit(&self, enricher_id: &str) {
            self.hits.lock().unwrap().push(enricher_id.to_string());
        }
        fn on_enrichment_dns_cache_miss(&self, enricher_id: &str) {
            self.misses.lock().unwrap().push(enricher_id.to_string());
        }
        fn on_enrichment_dns_query(&self, enricher_id: &str, result: &'static str) {
            self.queries
                .lock()
                .unwrap()
                .push((enricher_id.to_string(), result));
        }
        fn register_dns_enricher(&self, enricher_id: &str) {
            self.registered
                .lock()
                .unwrap()
                .push(enricher_id.to_string());
        }
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
    async fn miss_without_default_is_a_miss() {
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
            matches!(&err.kind, EnrichErrorKind::Miss(m) if m.contains("no A records for")),
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

    #[tokio::test]
    async fn default_is_injected_without_extract() {
        let backend = Arc::new(FakeBackend::new(responses(vec![])));
        let e = enricher(
            DnsRecordType::parse("PTR").unwrap(),
            "${detection.fields.Ip}",
            Some(serde_json::json!("unknown")),
            Some(ExtractExpr::Jq(".[0]".into())),
            backend,
        );
        let mut result = detection_result("Ip", serde_json::json!("192.0.2.99"));
        e.enrich(&mut result).await.unwrap();
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!("unknown")
        );
    }

    async fn enrich_ok(e: &DnsEnricher, host: &str) -> EvaluationResult {
        let mut result = detection_result("Host", serde_json::json!(host));
        e.enrich(&mut result).await.unwrap();
        result
    }

    #[tokio::test]
    async fn cache_serves_repeated_queries_without_backend_calls() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        );

        let first = enrich_ok(&e, "host.example.com").await;
        let second = enrich_ok(&e, "host.example.com").await;

        assert_eq!(backend.calls(), 1);
        let expected = serde_json::json!(["192.0.2.10"]);
        assert_eq!(first.header.enrichments.unwrap()["out"], expected);
        assert_eq!(second.header.enrichments.unwrap()["out"], expected);
    }

    #[tokio::test]
    async fn cache_re_queries_after_the_positive_ttl_cap() {
        let clock = TestClock::new();
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let resolver = DnsResolverConfig {
            cache_ttl: Duration::from_secs(1),
            ..DnsResolverConfig::default()
        };
        let e = enricher_with_config(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
            resolver,
            clock.clock(),
        );

        enrich_ok(&e, "host.example.com").await;
        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 1);

        clock.advance(Duration::from_secs(2));
        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 2);
    }

    #[tokio::test]
    async fn cache_re_queries_after_the_negative_ttl_cap() {
        let clock = TestClock::new();
        let query = Query::query(name("missing.example.com."), RecordType::A);
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("missing.example.com."), RecordType::A),
            Err(no_records_with_soa(query, 60)),
        )])));
        let resolver = DnsResolverConfig {
            negative_cache_ttl: Duration::from_secs(10),
            ..DnsResolverConfig::default()
        };
        let e = enricher_with_config(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
            resolver,
            clock.clock(),
        );

        let first = enrich_ok(&e, "missing.example.com").await;
        let second = enrich_ok(&e, "missing.example.com").await;
        assert_eq!(backend.calls(), 1);
        assert_eq!(
            first.header.enrichments.unwrap()["out"],
            serde_json::json!([])
        );
        assert_eq!(
            second.header.enrichments.unwrap()["out"],
            serde_json::json!([])
        );

        clock.advance(Duration::from_secs(11));
        enrich_ok(&e, "missing.example.com").await;
        assert_eq!(backend.calls(), 2);
    }

    #[tokio::test]
    async fn cache_does_not_store_transient_errors() {
        for error in [
            NetError::Timeout,
            NetError::Dns(DnsError::ResponseCode(
                hickory_resolver::proto::op::ResponseCode::ServFail,
            )),
        ] {
            let backend = Arc::new(FakeBackend::new(responses(vec![(
                (name("host.example.com."), RecordType::A),
                Err(error.clone()),
            )])));
            let e = enricher(
                DnsRecordType::parse("A").unwrap(),
                "${detection.fields.Host}",
                None,
                None,
                Arc::clone(&backend) as Arc<dyn DnsBackend>,
            );

            for _ in 0..2 {
                let mut result = detection_result("Host", serde_json::json!("host.example.com"));
                e.enrich(&mut result).await.unwrap_err();
            }
            assert_eq!(backend.calls(), 2, "error should not be cached: {error:?}");
        }
    }

    #[tokio::test]
    async fn zero_ttls_disable_the_cache() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let resolver = DnsResolverConfig {
            cache_ttl: Duration::ZERO,
            negative_cache_ttl: Duration::ZERO,
            ..DnsResolverConfig::default()
        };
        let e = enricher_with_config(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
            resolver,
            Arc::new(Instant::now),
        );

        enrich_ok(&e, "host.example.com").await;
        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 2);
    }

    fn frozen_clock() -> Clock {
        let now = Instant::now();
        Arc::new(move || now)
    }

    #[tokio::test]
    async fn zero_positive_ttl_caches_only_negative_answers() {
        let missing = Query::query(name("missing.example.com."), RecordType::A);
        let backend = Arc::new(FakeBackend::new(responses(vec![
            (
                (name("host.example.com."), RecordType::A),
                Ok(a_message("host.example.com.", &["192.0.2.10"])),
            ),
            (
                (name("missing.example.com."), RecordType::A),
                Err(no_records_with_soa(missing, 60)),
            ),
        ])));
        let resolver = DnsResolverConfig {
            cache_ttl: Duration::ZERO,
            ..DnsResolverConfig::default()
        };
        let e = enricher_with_config(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
            resolver,
            frozen_clock(),
        );

        enrich_ok(&e, "host.example.com").await;
        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 2);

        enrich_ok(&e, "missing.example.com").await;
        enrich_ok(&e, "missing.example.com").await;
        assert_eq!(backend.calls(), 3);
    }

    #[tokio::test]
    async fn negative_answers_without_an_soa_are_not_cached() {
        let backend = Arc::new(FakeBackend::new(responses(vec![])));
        let e = enricher_with_config(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
            DnsResolverConfig::default(),
            frozen_clock(),
        );

        enrich_ok(&e, "missing.example.com").await;
        enrich_ok(&e, "missing.example.com").await;
        assert_eq!(backend.calls(), 2);
    }

    #[tokio::test]
    async fn cache_keys_ignore_key_case() {
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        );

        enrich_ok(&e, "HOST.Example.COM").await;
        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn ip_caches_a_and_aaaa_entries_separately() {
        let backend = Arc::new(FakeBackend::new(responses(vec![
            (
                (name("host.example.com."), RecordType::A),
                Ok(a_message("host.example.com.", &["192.0.2.10"])),
            ),
            (
                (name("host.example.com."), RecordType::AAAA),
                Ok(aaaa_message("host.example.com.", &["2001:db8::10"])),
            ),
        ])));
        let e = enricher(
            DnsRecordType::parse("IP").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        );

        enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 2);

        // A second pass is served from the two cache entries. If A and AAAA
        // shared a key, one side would be re-queried here.
        let result = enrich_ok(&e, "host.example.com").await;
        assert_eq!(backend.calls(), 2);
        assert_eq!(
            result.header.enrichments.unwrap()["out"],
            serde_json::json!(["192.0.2.10", "2001:db8::10"])
        );
    }

    #[test]
    fn metrics_pre_register_the_enricher() {
        let metrics = Arc::new(CollectingMetrics::default());
        let backend = Arc::new(FakeBackend::new(HashMap::new()));
        let _e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            backend,
        )
        .with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsHook>);

        assert_eq!(metrics.registered.lock().unwrap().clone(), vec!["dns"]);
    }

    #[tokio::test]
    async fn metrics_record_a_miss_then_a_hit() {
        let metrics = Arc::new(CollectingMetrics::default());
        let backend = Arc::new(FakeBackend::new(responses(vec![(
            (name("host.example.com."), RecordType::A),
            Ok(a_message("host.example.com.", &["192.0.2.10"])),
        )])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        )
        .with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsHook>);

        enrich_ok(&e, "host.example.com").await;
        enrich_ok(&e, "host.example.com").await;

        assert_eq!(metrics.misses.lock().unwrap().clone(), vec!["dns"]);
        assert_eq!(metrics.hits.lock().unwrap().clone(), vec!["dns"]);
        assert_eq!(
            metrics.queries.lock().unwrap().clone(),
            vec![("dns".to_string(), "answer")]
        );
    }

    #[tokio::test]
    async fn metrics_record_answer_no_records_and_error_results() {
        let metrics = Arc::new(CollectingMetrics::default());
        let backend = Arc::new(FakeBackend::new(responses(vec![
            (
                (name("host.example.com."), RecordType::A),
                Ok(a_message("host.example.com.", &["192.0.2.10"])),
            ),
            (
                (name("fail.example.com."), RecordType::A),
                Err(NetError::Dns(DnsError::ResponseCode(
                    hickory_resolver::proto::op::ResponseCode::ServFail,
                ))),
            ),
        ])));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Host}",
            Some(serde_json::json!([])),
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        )
        .with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsHook>);

        enrich_ok(&e, "host.example.com").await;
        enrich_ok(&e, "missing.example.com").await;
        let mut result = detection_result("Host", serde_json::json!("fail.example.com"));
        e.enrich(&mut result).await.unwrap_err();

        assert_eq!(
            metrics.queries.lock().unwrap().clone(),
            vec![
                ("dns".to_string(), "answer"),
                ("dns".to_string(), "no_records"),
                ("dns".to_string(), "error"),
            ]
        );
    }

    #[tokio::test]
    async fn metrics_count_both_ip_queries() {
        let metrics = Arc::new(CollectingMetrics::default());
        let backend = Arc::new(FakeBackend::new(responses(vec![
            (
                (name("host.example.com."), RecordType::A),
                Ok(a_message("host.example.com.", &["192.0.2.10"])),
            ),
            (
                (name("host.example.com."), RecordType::AAAA),
                Ok(aaaa_message("host.example.com.", &["2001:db8::10"])),
            ),
        ])));
        let e = enricher(
            DnsRecordType::parse("IP").unwrap(),
            "${detection.fields.Host}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        )
        .with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsHook>);

        enrich_ok(&e, "host.example.com").await;

        let queries = metrics.queries.lock().unwrap().clone();
        assert_eq!(queries.len(), 2, "IP must count two queries: {queries:?}");
        assert!(
            queries
                .iter()
                .all(|(id, result)| id == "dns" && *result == "answer"),
            "got {queries:?}"
        );
    }

    #[tokio::test]
    async fn metrics_ignore_key_errors() {
        let metrics = Arc::new(CollectingMetrics::default());
        let backend = Arc::new(FakeBackend::new(HashMap::new()));
        let e = enricher(
            DnsRecordType::parse("A").unwrap(),
            "${detection.fields.Missing}",
            None,
            None,
            Arc::clone(&backend) as Arc<dyn DnsBackend>,
        )
        .with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsHook>);

        let mut result = detection_result("Host", serde_json::json!("host.example.com"));
        e.enrich(&mut result).await.unwrap_err();

        assert!(metrics.hits.lock().unwrap().is_empty());
        assert!(metrics.misses.lock().unwrap().is_empty());
        assert!(metrics.queries.lock().unwrap().is_empty());
        assert_eq!(backend.calls(), 0);
    }
}
