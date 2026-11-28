//! TAXII 2.1 HTTP client.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use rustls::pki_types::ServerName;
use url::Url;

use crate::core::StixId;
use crate::model::{ParseOptions, StixObject};

use super::TaxiiAuthProvider;
use super::TaxiiError;
use super::address_filter::{AddressFilter, FilteringResolver};
use super::capability::{
    ensure_api_root_supports_taxii, ensure_collection_accepts_stix, ensure_post_content_type,
};
use super::dns;
use super::envelope::ManifestResponse;
use super::envelope::{ManifestRecord, TaxiiEnvelope, TaxiiStatus};
use super::filter::{DeleteObjectFilter, ObjectByIdFilter, TaxiiFilter, VersionsQueryFilter};
use super::headers::{TaxiiPageHeaders, TaxiiPaged};
use super::media::{MANIFEST_ACCEPT, TAXII_ACCEPT};
use super::pagination::{
    ManifestPaginationState, ObjectByIdPaginationState, ObjectPaginationState,
    VersionsPaginationState, recover_from_range_not_satisfiable,
};
use super::policy::{CapabilityPolicy, PostSubmitPolicy, PreflightPolicy};
use super::request::{
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_STATUS_MAX_POLLS, DEFAULT_STATUS_POLL_INTERVAL,
    DEFAULT_TIMEOUT, TaxiiHttp, default_user_agent,
};
use super::resources::{
    CollectionsResponse, TaxiiApiRoot, TaxiiCollection, TaxiiDiscovery, VersionsResponse,
};
use super::retry::RetryPolicy;
use super::server_trust::{
    ServerTrustPolicy, TlsaCache, build_rustls_config_for, server_name_to_str, system_roots,
};
use super::tls::ClientCertificate;
use super::url::{HttpsPolicy, discovery_url, join_api_root};

/// Configuration for [`TaxiiClient`].
#[derive(Clone)]
pub struct TaxiiClientConfig {
    base_url: String,
    auth: Option<Arc<dyn TaxiiAuthProvider>>,
    timeout: Duration,
    user_agent: String,
    retry: RetryPolicy,
    preflight: PreflightPolicy,
    client_certificate: Option<ClientCertificate>,
    allow_insecure_http: bool,
    max_response_bytes: usize,
    parse_options: ParseOptions,
    status_poll_interval: Duration,
    status_max_polls: u32,
    post_submit: PostSubmitPolicy,
    capability: CapabilityPolicy,
    server_trust: ServerTrustPolicy,
    tlsa_cache: TlsaCache,
    dns_nameserver: Option<SocketAddr>,
    dane_require_dnssec: bool,
    address_filter: Option<AddressFilter>,
    clock_skew_correction: bool,
    server_identity: Option<String>,
}

impl TaxiiClientConfig {
    /// Create config with `base_url` (scheme + host, optional path prefix).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth: None,
            timeout: DEFAULT_TIMEOUT,
            user_agent: default_user_agent(),
            retry: RetryPolicy::default(),
            preflight: PreflightPolicy::default(),
            client_certificate: None,
            allow_insecure_http: false,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            parse_options: ParseOptions::default(),
            status_poll_interval: DEFAULT_STATUS_POLL_INTERVAL,
            status_max_polls: DEFAULT_STATUS_MAX_POLLS,
            post_submit: PostSubmitPolicy::default(),
            capability: CapabilityPolicy::default(),
            server_trust: ServerTrustPolicy::default(),
            tlsa_cache: TlsaCache::default(),
            dns_nameserver: None,
            dane_require_dnssec: true,
            address_filter: None,
            clock_skew_correction: true,
            server_identity: None,
        }
    }

    /// Override the server base URL (scheme + host).
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the authentication provider.
    pub fn auth(mut self, auth: impl TaxiiAuthProvider + 'static) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// Set the HTTP timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the User-Agent header (TXC section 2.1.4).
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Set the retry policy.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    /// Set preflight read/write checks.
    pub fn preflight(mut self, policy: PreflightPolicy) -> Self {
        self.preflight = policy;
        self
    }

    /// Attach a client certificate for mutual TLS.
    pub fn client_certificate(mut self, certificate: ClientCertificate) -> Self {
        self.client_certificate = Some(certificate);
        self
    }

    /// Allow `http://` URLs (testing/interop only; spec section 8.5.1 requires HTTPS).
    pub fn allow_insecure_http(mut self, allowed: bool) -> Self {
        self.allow_insecure_http = allowed;
        self
    }

    /// Maximum response body size in bytes.
    pub fn max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// STIX parse options for envelope objects.
    pub fn parse_options(mut self, options: ParseOptions) -> Self {
        self.parse_options = options;
        self
    }

    /// Interval between status poll attempts.
    pub fn status_poll_interval(mut self, interval: Duration) -> Self {
        self.status_poll_interval = interval;
        self
    }

    /// Maximum status poll attempts before [`TaxiiError::StatusPollTimeout`].
    pub fn status_max_polls(mut self, max_polls: u32) -> Self {
        self.status_max_polls = max_polls;
        self
    }

    /// Control POST status polling (spec section 5.5 SHOULD).
    pub fn post_submit(mut self, policy: PostSubmitPolicy) -> Self {
        self.post_submit = policy;
        self
    }

    /// Control API Root / collection capability checks.
    pub fn capability(mut self, policy: CapabilityPolicy) -> Self {
        self.capability = policy;
        self
    }

    /// Server TLS trust policy (pinning, DANE, or system roots).
    pub fn server_trust(mut self, policy: ServerTrustPolicy) -> Self {
        self.server_trust = policy;
        self
    }

    /// Shared TLSA cache for DANE validation.
    pub fn tlsa_cache(mut self, cache: TlsaCache) -> Self {
        self.tlsa_cache = cache;
        self
    }

    /// Override the DNS resolver used for SRV/TLSA lookups (testing / local CoreDNS).
    pub fn dns_nameserver(mut self, nameserver: SocketAddr) -> Self {
        self.dns_nameserver = Some(nameserver);
        self
    }

    /// When [`ServerTrustPolicy::Dane`] is active: require DNSSEC-validated TLSA and SRV answers
    /// (TAXII 2.1 section 8.5.2 SHOULD). Default `true`. Set `false` only for unsigned lab DNS.
    pub fn dane_require_dnssec(mut self, required: bool) -> Self {
        self.dane_require_dnssec = required;
        self
    }

    /// Accept only destination addresses for which `filter` returns true.
    ///
    /// Name resolution drops rejected addresses and fails when none remain. IP
    /// literals are checked on every request, including absolute URLs advertised
    /// by the server. Redirects and proxies are disabled so a later hop cannot
    /// bypass the filter. With no filter, the client keeps its default resolver,
    /// redirect policy, and proxy behavior.
    pub fn address_filter(mut self, filter: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>) -> Self {
        self.address_filter = Some(filter);
        self
    }

    /// Shift a caller-supplied `added_after` by the offset between the local
    /// clock and the server's HTTP `Date` header. Default `true`.
    ///
    /// A cursor taken from `X-TAXII-Date-Added-Last` during pagination is
    /// already in server time and is never shifted. Turn this off when the
    /// caller's `added_after` also comes from that header, for example the
    /// cursor of an earlier poll. An offset of more than 24 hours is ignored.
    pub fn clock_skew_correction(mut self, enabled: bool) -> Self {
        self.clock_skew_correction = enabled;
        self
    }

    /// Check the server certificate against `name` instead of the URL host.
    ///
    /// The connection, SNI, and `Host` header still use the URL host. Under
    /// [`ServerTrustPolicy::Dane`] the TLSA lookup uses `name` too.
    /// [`TaxiiClient::discover_via_srv`] sets this to the queried domain when
    /// the SRV answer is not DNSSEC-validated and the caller has not set it.
    pub fn server_identity(mut self, name: impl Into<String>) -> Self {
        self.server_identity = Some(name.into());
        self
    }
}

struct TaxiiClientInner {
    http: TaxiiHttp,
    preflight: PreflightPolicy,
    status_poll_interval: Duration,
    status_max_polls: u32,
    post_submit: PostSubmitPolicy,
    capability: CapabilityPolicy,
    https_policy: HttpsPolicy,
    clock_skew_correction: bool,
}

/// Page and object bounds for one [`TaxiiClient::poll_object_pages`] call.
///
/// The struct is non-exhaustive. Build it with [`PollBudget::new`] or
/// [`PollBudget::for_indicators`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollBudget {
    /// Maximum objects pages fetched in one poll.
    pub max_pages: usize,
    /// Maximum objects delivered in one poll.
    pub max_objects: usize,
}

/// One objects page delivered by [`TaxiiClient::poll_object_pages`].
#[derive(Debug)]
pub struct PolledPage {
    /// Objects on this page.
    pub objects: Vec<StixObject>,
    /// `X-TAXII-Date-Added-Last` for this page, when the server sent it.
    pub date_added_last: Option<crate::core::TaxiiTimestamp>,
}

/// Why [`TaxiiClient::poll_object_pages`] returned after the pages it delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollStop {
    /// The server reported no further pages.
    Finished,
    /// The budget was reached and the server still has more.
    Budget,
}

impl PollBudget {
    /// A budget that fails the poll before a request when either bound is zero.
    pub fn new(max_pages: usize, max_objects: usize) -> Self {
        Self {
            max_pages,
            max_objects,
        }
    }

    /// One poll of work for a source that keeps at most `max_indicators`.
    ///
    /// `max_objects` is `max_indicators` plus one page, and `max_pages` is that
    /// many objects divided by `page_size`. A larger collection continues on
    /// the next poll. [`TaxiiClient::poll_object_pages`] returns
    /// [`PollStop::Budget`] after the last page it applied.
    /// [`TaxiiClient::poll_objects`] reports that stop as
    /// [`TaxiiError::PollBudgetExceeded`].
    pub fn for_indicators(page_size: usize, max_indicators: usize) -> Self {
        let page_size = page_size.max(1);
        let max_objects = max_indicators.saturating_add(page_size).max(1);
        let max_pages = max_objects.div_ceil(page_size).max(1);
        Self::new(max_pages, max_objects)
    }
}

/// TAXII 2.1 HTTP client.
#[derive(Clone)]
pub struct TaxiiClient {
    base_url: Url,
    inner: Arc<TaxiiClientInner>,
}

impl TaxiiClient {
    /// Build a client from `config`.
    pub fn new(config: TaxiiClientConfig) -> Result<Self, TaxiiError> {
        let https_policy = if config.allow_insecure_http {
            HttpsPolicy::Allowed
        } else {
            HttpsPolicy::Required
        };

        let base_url =
            Url::parse(&config.base_url).map_err(|err| TaxiiError::InvalidUrl(err.to_string()))?;
        super::url::ensure_https(&base_url, https_policy)?;

        let identity = config
            .server_identity
            .as_deref()
            .map(|name| {
                let name = name.trim().trim_end_matches('.');
                ServerName::try_from(name.to_owned()).map_err(|err| {
                    TaxiiError::InvalidServerTrust {
                        reason: format!("invalid server identity `{name}`: {err}"),
                    }
                })
            })
            .transpose()?;
        let tls_identity = identity.as_ref().map(server_name_to_str);
        let tls = build_rustls_config_for(
            &config.server_trust,
            &config.tlsa_cache,
            config.client_certificate.as_ref(),
            identity,
            system_roots(),
        )?;
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .use_preconfigured_tls(tls);
        if let Some(filter) = config.address_filter.clone() {
            builder = builder
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .dns_resolver(FilteringResolver { permit: filter });
        }
        let client = builder.build().map_err(TaxiiError::NetworkError)?;

        Ok(Self {
            base_url,
            inner: Arc::new(TaxiiClientInner {
                http: TaxiiHttp {
                    client,
                    user_agent: config.user_agent,
                    auth: config.auth,
                    retry: config.retry,
                    max_response_bytes: config.max_response_bytes,
                    parse_options: config.parse_options,
                    clock_skew: Arc::new(std::sync::RwLock::new(None)),
                    server_trust: config.server_trust,
                    tlsa_cache: config.tlsa_cache,
                    dns_nameserver: config.dns_nameserver,
                    dane_require_dnssec: config.dane_require_dnssec,
                    address_filter: config.address_filter,
                    tls_identity,
                },
                preflight: config.preflight,
                status_poll_interval: config.status_poll_interval,
                status_max_polls: config.status_max_polls,
                post_submit: config.post_submit,
                capability: config.capability,
                https_policy,
                clock_skew_correction: config.clock_skew_correction,
            }),
        })
    }

    /// Discover a TAXII server via DNS SRV (`_taxii2._tcp.{domain}`) then GET `/taxii2/`.
    ///
    /// Targets are tried in SRV order. The server certificate must be valid
    /// for `domain` unless the SRV record is DNSSEC-validated, in which case
    /// the target's own name is accepted (RFC 6125 section 6.2.1). A
    /// [`TaxiiClientConfig::server_identity`] set by the caller always wins.
    /// Credentials are sent only over a connection that passed that check.
    pub async fn discover_via_srv(
        domain: &str,
        config: TaxiiClientConfig,
    ) -> Result<TaxiiDiscovery, TaxiiError> {
        let mut last_err = None;
        let nameserver = config.dns_nameserver;
        let dns_options = if matches!(config.server_trust, ServerTrustPolicy::Dane) {
            dns::DnsLookupOptions::for_dane(config.dane_require_dnssec)
        } else {
            dns::DnsLookupOptions::default()
        };
        let source_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        for target in dns::resolve_taxii_srv_targets(domain, nameserver, dns_options).await? {
            let base = match target.base_url() {
                Ok(base) => base,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };
            let mut target_config = config.clone().base_url(base.to_string());
            if target_config.server_identity.is_none() && !target.dnssec_secure {
                target_config = target_config.server_identity(source_domain.clone());
            }
            match Self::new(target_config) {
                Ok(client) => match client.discover().await {
                    Ok(discovery) => return Ok(discovery),
                    Err(err) => last_err = Some(err),
                },
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or(TaxiiError::DnsDiscovery(format!(
            "no SRV records for domain {domain}"
        ))))
    }

    /// GET `/taxii2/` discovery resource.
    pub async fn discover(&self) -> Result<TaxiiDiscovery, TaxiiError> {
        let url = discovery_url(&self.base_url, self.inner.https_policy)?;
        let response = self.inner.http.get(url, &[], TAXII_ACCEPT).await?;
        self.inner.http.decode_json(&response)
    }

    /// GET `{api_root}/` information resource.
    pub async fn api_root(&self, api_root_url: &str) -> Result<TaxiiApiRoot, TaxiiError> {
        let url = join_api_root(api_root_url, "", self.inner.https_policy)?;
        let response = self.inner.http.get(url, &[], TAXII_ACCEPT).await?;
        self.inner.http.decode_json(&response)
    }

    /// GET `{api_root}/collections/`.
    pub async fn collections(
        &self,
        api_root_url: &str,
    ) -> Result<Vec<TaxiiCollection>, TaxiiError> {
        let url = join_api_root(api_root_url, "collections/", self.inner.https_policy)?;
        let response = self.inner.http.get(url, &[], TAXII_ACCEPT).await?;
        let parsed: CollectionsResponse = self.inner.http.decode_json(&response)?;
        Ok(parsed.collections)
    }

    /// GET `{api_root}/collections/{id}/`.
    pub async fn collection(
        &self,
        api_root_url: &str,
        collection_id: &str,
    ) -> Result<TaxiiCollection, TaxiiError> {
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/"),
            self.inner.https_policy,
        )?;
        let response = self.inner.http.get(url, &[], TAXII_ACCEPT).await?;
        self.inner.http.decode_json(&response)
    }

    /// GET `{api_root}/collections/{id}/objects/` with filtering.
    pub async fn objects(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: TaxiiFilter,
    ) -> Result<TaxiiPaged<TaxiiEnvelope>, TaxiiError> {
        self.ensure_can_read(api_root_url, collection_id).await?;
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/"),
            self.inner.https_policy,
        )?;
        let query = with_clock_skew_filter(&filter, self.clock_skew(false)).to_query_pairs()?;
        let mut response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let envelope = self
            .inner
            .http
            .decode_envelope(std::mem::take(&mut response.body))
            .await?;
        Ok(TaxiiPaged::new(envelope, &response))
    }

    /// GET `{api_root}/collections/{id}/objects/{object_id}/` (spec section 5.6).
    pub async fn get_object(
        &self,
        api_root_url: &str,
        collection_id: &str,
        object_id: &StixId,
        filter: ObjectByIdFilter,
    ) -> Result<TaxiiPaged<TaxiiEnvelope>, TaxiiError> {
        self.ensure_can_read(api_root_url, collection_id).await?;
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/{object_id}/"),
            self.inner.https_policy,
        )?;
        let query =
            with_clock_skew_object_filter(&filter, self.clock_skew(false)).to_query_pairs()?;
        let mut response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let envelope = self
            .inner
            .http
            .decode_envelope(std::mem::take(&mut response.body))
            .await?;
        Ok(TaxiiPaged::new(envelope, &response))
    }

    /// Drain objects pages until the collection ends.
    ///
    /// The header is consumed while advancing pages. Callers that poll with
    /// `added_after` use the returned timestamp as the next cursor. A failed
    /// page returns the error and no objects. [`PollStop::Budget`] from
    /// [`TaxiiClient::poll_object_pages`] is [`TaxiiError::PollBudgetExceeded`]
    /// here, because this method cannot resume. A page that does not advance
    /// the filter is [`TaxiiError::RepeatedPaginationCursor`]. HTTP 416 recovery
    /// that would request the same filter returns that 416 error.
    pub async fn poll_objects(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: TaxiiFilter,
        budget: PollBudget,
    ) -> Result<(Vec<StixObject>, Option<crate::core::TaxiiTimestamp>), TaxiiError> {
        let mut objects = Vec::new();
        let mut date_added_last = None;
        let stop = self
            .poll_object_pages(api_root_url, collection_id, filter, budget, |page| {
                if page.date_added_last.is_some() {
                    date_added_last = page.date_added_last.clone();
                }
                objects.extend(page.objects);
            })
            .await?;
        match stop {
            PollStop::Finished => Ok((objects, date_added_last)),
            PollStop::Budget => Err(TaxiiError::PollBudgetExceeded {
                max_pages: budget.max_pages,
                max_objects: budget.max_objects,
            }),
        }
    }

    /// Deliver each objects page, then stop at `budget` or at the end.
    ///
    /// `on_page` runs after the page is fetched and before the next request.
    /// [`PollStop::Budget`] means the pages already delivered are complete and
    /// the server still has more. The last page's `X-TAXII-Date-Added-Last`
    /// is the cursor a later poll passes as `added_after`. A zero budget
    /// returns [`TaxiiError::PollBudgetExceeded`] before a request. A page that
    /// does not advance the filter is [`TaxiiError::RepeatedPaginationCursor`].
    /// HTTP 416 recovery that would request the same filter returns that 416
    /// error. Either error can follow pages already passed to `on_page`; the
    /// caller decides whether to keep them.
    pub async fn poll_object_pages<F>(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: TaxiiFilter,
        budget: PollBudget,
        mut on_page: F,
    ) -> Result<PollStop, TaxiiError>
    where
        F: FnMut(PolledPage) + Send,
    {
        if budget.max_pages == 0 || budget.max_objects == 0 {
            return Err(TaxiiError::PollBudgetExceeded {
                max_pages: budget.max_pages,
                max_objects: budget.max_objects,
            });
        }
        let mut pagination = ObjectPaginationState::new(filter);
        let mut pages = 0usize;
        let mut objects_seen = 0usize;
        loop {
            if pagination.finished {
                return Ok(PollStop::Finished);
            }
            if pages >= budget.max_pages || objects_seen >= budget.max_objects {
                return Ok(PollStop::Budget);
            }
            let sent = pagination.filter.clone();
            match self
                .fetch_objects_page(
                    api_root_url,
                    collection_id,
                    &pagination.filter,
                    pagination.server_cursor,
                )
                .await
            {
                Ok((envelope, response)) => {
                    let date_added_last =
                        TaxiiPageHeaders::from_response(&response).date_added_last;
                    pagination.apply_page(
                        envelope.more,
                        envelope.next,
                        date_added_last.clone(),
                        envelope.objects,
                    )?;
                    if !pagination.finished && pagination.filter == sent {
                        return Err(TaxiiError::RepeatedPaginationCursor);
                    }
                    let objects: Vec<_> = pagination.pending_objects.drain(..).collect();
                    objects_seen += objects.len();
                    pages += 1;
                    on_page(PolledPage {
                        objects,
                        date_added_last,
                    });
                }
                Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                    recover_from_range_not_satisfiable(
                        &mut pagination.filter,
                        pagination.baseline_added_after.clone(),
                    );
                    pagination.server_cursor = false;
                    if pagination.filter == sent {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Paginated stream of STIX objects from a collection.
    pub fn objects_stream(
        &self,
        api_root_url: impl Into<String>,
        collection_id: impl Into<String>,
        filter: TaxiiFilter,
    ) -> Pin<Box<dyn Stream<Item = Result<StixObject, TaxiiError>> + Send>> {
        let client = self.clone();
        let api_root_url = api_root_url.into();
        let collection_id = collection_id.into();
        Box::pin(futures::stream::unfold(
            Some(ObjectPaginationState::new(filter)),
            move |pagination| {
                let client = client.clone();
                let api_root_url = api_root_url.clone();
                let collection_id = collection_id.clone();
                async move {
                    let mut pagination = pagination?;
                    loop {
                        if let Some(object) = pagination.pending_objects.pop_front() {
                            return Some((Ok(object), Some(pagination)));
                        }
                        if pagination.finished {
                            return None;
                        }
                        let sent = pagination.filter.clone();
                        match client
                            .fetch_objects_page(
                                &api_root_url,
                                &collection_id,
                                &pagination.filter,
                                pagination.server_cursor,
                            )
                            .await
                        {
                            Ok((envelope, response)) => {
                                if let Err(err) = pagination.apply_page(
                                    envelope.more,
                                    envelope.next,
                                    TaxiiPageHeaders::from_response(&response).date_added_last,
                                    envelope.objects,
                                ) {
                                    return Some((Err(err), None));
                                }
                                if !pagination.finished && pagination.filter == sent {
                                    return Some((Err(TaxiiError::RepeatedPaginationCursor), None));
                                }
                            }
                            Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                                recover_from_range_not_satisfiable(
                                    &mut pagination.filter,
                                    pagination.baseline_added_after.clone(),
                                );
                                pagination.server_cursor = false;
                                if pagination.filter == sent {
                                    return Some((Err(err), None));
                                }
                            }
                            Err(err) => return Some((Err(err), None)),
                        }
                    }
                }
            },
        ))
    }

    /// Paginated stream for a single object id (spec section 5.6).
    pub fn object_stream(
        &self,
        api_root_url: impl Into<String>,
        collection_id: impl Into<String>,
        object_id: StixId,
        filter: ObjectByIdFilter,
    ) -> Pin<Box<dyn Stream<Item = Result<StixObject, TaxiiError>> + Send>> {
        let client = self.clone();
        let api_root_url = api_root_url.into();
        let collection_id = collection_id.into();
        Box::pin(futures::stream::unfold(
            Some(ObjectByIdPaginationState::new(filter)),
            move |pagination| {
                let client = client.clone();
                let api_root_url = api_root_url.clone();
                let collection_id = collection_id.clone();
                let object_id = object_id.clone();
                async move {
                    let mut pagination = pagination?;
                    loop {
                        if let Some(object) = pagination.pending_objects.pop_front() {
                            return Some((Ok(object), Some(pagination)));
                        }
                        if pagination.finished {
                            return None;
                        }
                        let sent = pagination.filter.clone();
                        match client
                            .fetch_object_page(
                                &api_root_url,
                                &collection_id,
                                &object_id,
                                &pagination.filter,
                                pagination.server_cursor,
                            )
                            .await
                        {
                            Ok((envelope, response)) => {
                                if let Err(err) = pagination.apply_page(
                                    envelope.more,
                                    envelope.next,
                                    TaxiiPageHeaders::from_response(&response).date_added_last,
                                    envelope.objects,
                                ) {
                                    return Some((Err(err), None));
                                }
                                if !pagination.finished && pagination.filter == sent {
                                    return Some((Err(TaxiiError::RepeatedPaginationCursor), None));
                                }
                            }
                            Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                                recover_from_range_not_satisfiable(
                                    &mut pagination.filter,
                                    pagination.baseline_added_after.clone(),
                                );
                                pagination.server_cursor = false;
                                if pagination.filter == sent {
                                    return Some((Err(err), None));
                                }
                            }
                            Err(err) => return Some((Err(err), None)),
                        }
                    }
                }
            },
        ))
    }

    /// POST `{api_root}/collections/{id}/objects/` (202 + status resource).
    pub async fn add_objects(
        &self,
        api_root_url: &str,
        collection_id: &str,
        envelope: &TaxiiEnvelope,
    ) -> Result<TaxiiStatus, TaxiiError> {
        self.ensure_can_write(api_root_url, collection_id).await?;
        let api = self.api_root(api_root_url).await?;
        self.ensure_api_capabilities(&api).await?;
        let collection = self.collection(api_root_url, collection_id).await?;
        self.ensure_collection_capabilities(&collection).await?;
        ensure_post_content_type(&collection)?;
        let body = serde_json::to_vec(envelope).map_err(|err| TaxiiError::MalformedResponse {
            reason: err.to_string(),
        })?;
        if body.len() as u64 > api.max_content_length {
            return Err(TaxiiError::RequestBodyTooLarge {
                len: body.len(),
                max: api.max_content_length,
            });
        }
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/"),
            self.inner.https_policy,
        )?;
        let response = self.inner.http.post(url, body).await?;
        if response.status.as_u16() != 202 {
            return Err(TaxiiError::MalformedResponse {
                reason: format!("expected HTTP 202, got {}", response.status),
            });
        }
        let status: TaxiiStatus = self.inner.http.decode_json(&response)?;
        match self.inner.post_submit {
            PostSubmitPolicy::ReturnInitial => Ok(status),
            PostSubmitPolicy::PollUntilComplete => {
                if matches!(status.status, super::StatusState::Complete) {
                    Ok(status)
                } else {
                    self.poll_status(api_root_url, &status.id).await
                }
            }
        }
    }

    /// DELETE `{api_root}/collections/{id}/objects/{object_id}/`.
    pub async fn delete_object(
        &self,
        api_root_url: &str,
        collection_id: &str,
        object_id: &StixId,
        filter: impl Into<DeleteObjectFilter>,
    ) -> Result<(), TaxiiError> {
        self.ensure_can_delete(api_root_url, collection_id).await?;
        let query = filter.into().to_query_pairs()?;
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/{object_id}/"),
            self.inner.https_policy,
        )?;
        self.inner.http.delete(url, &query).await?;
        Ok(())
    }

    /// GET `{api_root}/collections/{id}/objects/{object_id}/versions/`.
    pub async fn object_versions(
        &self,
        api_root_url: &str,
        collection_id: &str,
        object_id: &StixId,
        filter: VersionsQueryFilter,
    ) -> Result<TaxiiPaged<VersionsResponse>, TaxiiError> {
        self.ensure_can_read(api_root_url, collection_id).await?;
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/{object_id}/versions/"),
            self.inner.https_policy,
        )?;
        let query =
            with_clock_skew_versions_filter(&filter, self.clock_skew(false)).to_query_pairs()?;
        let response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let parsed: VersionsResponse = self.inner.http.decode_json(&response)?;
        Ok(TaxiiPaged::new(parsed, &response))
    }

    /// Paginated stream of version strings for an object.
    pub fn object_versions_stream(
        &self,
        api_root_url: impl Into<String>,
        collection_id: impl Into<String>,
        object_id: StixId,
        filter: VersionsQueryFilter,
    ) -> Pin<Box<dyn Stream<Item = Result<String, TaxiiError>> + Send>> {
        let client = self.clone();
        let api_root_url = api_root_url.into();
        let collection_id = collection_id.into();
        Box::pin(futures::stream::unfold(
            Some(VersionsPaginationState::new(filter)),
            move |pagination| {
                let client = client.clone();
                let api_root_url = api_root_url.clone();
                let collection_id = collection_id.clone();
                let object_id = object_id.clone();
                async move {
                    let mut pagination = pagination?;
                    loop {
                        if let Some(version) = pagination.pending_versions.pop_front() {
                            return Some((Ok(version), Some(pagination)));
                        }
                        if pagination.finished {
                            return None;
                        }
                        let sent = pagination.filter.clone();
                        match client
                            .fetch_versions_page(
                                &api_root_url,
                                &collection_id,
                                &object_id,
                                &pagination.filter,
                                pagination.server_cursor,
                            )
                            .await
                        {
                            Ok((page, response)) => {
                                if let Err(err) = pagination.apply_page(
                                    page.more,
                                    page.next,
                                    TaxiiPageHeaders::from_response(&response).date_added_last,
                                    page.versions,
                                ) {
                                    return Some((Err(err), None));
                                }
                                if !pagination.finished && pagination.filter == sent {
                                    return Some((Err(TaxiiError::RepeatedPaginationCursor), None));
                                }
                            }
                            Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                                recover_from_range_not_satisfiable(
                                    &mut pagination.filter,
                                    pagination.baseline_added_after.clone(),
                                );
                                pagination.server_cursor = false;
                                if pagination.filter == sent {
                                    return Some((Err(err), None));
                                }
                            }
                            Err(err) => return Some((Err(err), None)),
                        }
                    }
                }
            },
        ))
    }

    /// GET `{api_root}/status/{status_id}/`.
    pub async fn get_status(
        &self,
        api_root_url: &str,
        status_id: &str,
    ) -> Result<TaxiiStatus, TaxiiError> {
        let url = join_api_root(
            api_root_url,
            &format!("status/{status_id}/"),
            self.inner.https_policy,
        )?;
        let response = self.inner.http.get(url, &[], TAXII_ACCEPT).await?;
        self.inner.http.decode_json(&response)
    }

    /// Poll status until complete or [`TaxiiError::StatusPollTimeout`].
    pub async fn poll_status(
        &self,
        api_root_url: &str,
        status_id: &str,
    ) -> Result<TaxiiStatus, TaxiiError> {
        let mut polls = 0u32;
        loop {
            let status = self.get_status(api_root_url, status_id).await?;
            if matches!(status.status, super::StatusState::Complete) {
                return Ok(status);
            }
            polls += 1;
            if polls >= self.inner.status_max_polls {
                return Err(TaxiiError::StatusPollTimeout {
                    last: status,
                    max_polls: self.inner.status_max_polls,
                });
            }
            tokio::time::sleep(self.inner.status_poll_interval).await;
        }
    }

    /// GET `{api_root}/collections/{id}/manifest/`.
    pub async fn manifest(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: TaxiiFilter,
    ) -> Result<TaxiiPaged<ManifestResponse>, TaxiiError> {
        self.ensure_can_read(api_root_url, collection_id).await?;
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/manifest/"),
            self.inner.https_policy,
        )?;
        let query = with_clock_skew_filter(&filter, self.clock_skew(false)).to_query_pairs()?;
        let response = self.inner.http.get(url, &query, MANIFEST_ACCEPT).await?;
        let parsed: ManifestResponse = self.inner.http.decode_json(&response)?;
        Ok(TaxiiPaged::new(parsed, &response))
    }

    /// Paginated stream of manifest records.
    pub fn manifest_stream(
        &self,
        api_root_url: impl Into<String>,
        collection_id: impl Into<String>,
        filter: TaxiiFilter,
    ) -> Pin<Box<dyn Stream<Item = Result<ManifestRecord, TaxiiError>> + Send>> {
        let client = self.clone();
        let api_root_url = api_root_url.into();
        let collection_id = collection_id.into();
        Box::pin(futures::stream::unfold(
            Some(ManifestPaginationState::new(filter)),
            move |pagination| {
                let client = client.clone();
                let api_root_url = api_root_url.clone();
                let collection_id = collection_id.clone();
                async move {
                    let mut pagination = pagination?;
                    loop {
                        if let Some(record) = pagination.pending_records.pop_front() {
                            return Some((Ok(record), Some(pagination)));
                        }
                        if pagination.finished {
                            return None;
                        }
                        let sent = pagination.filter.clone();
                        match client
                            .fetch_manifest_page(
                                &api_root_url,
                                &collection_id,
                                &pagination.filter,
                                pagination.server_cursor,
                            )
                            .await
                        {
                            Ok((page, response)) => {
                                if let Err(err) = pagination.apply_page(
                                    page.more,
                                    page.next,
                                    TaxiiPageHeaders::from_response(&response).date_added_last,
                                    page.objects,
                                ) {
                                    return Some((Err(err), None));
                                }
                                if !pagination.finished && pagination.filter == sent {
                                    return Some((Err(TaxiiError::RepeatedPaginationCursor), None));
                                }
                            }
                            Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                                recover_from_range_not_satisfiable(
                                    &mut pagination.filter,
                                    pagination.baseline_added_after.clone(),
                                );
                                pagination.server_cursor = false;
                                if pagination.filter == sent {
                                    return Some((Err(err), None));
                                }
                            }
                            Err(err) => return Some((Err(err), None)),
                        }
                    }
                }
            },
        ))
    }

    pub(crate) async fn fetch_objects_page(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: &TaxiiFilter,
        server_cursor: bool,
    ) -> Result<(TaxiiEnvelope, super::request::TaxiiResponse), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Enabled {
            let collection = self.collection(api_root_url, collection_id).await?;
            if !collection.can_read {
                return Err(TaxiiError::ReadNotPermitted);
            }
        }
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/"),
            self.inner.https_policy,
        )?;
        let query =
            with_clock_skew_filter(filter, self.clock_skew(server_cursor)).to_query_pairs()?;
        let mut response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let envelope = self
            .inner
            .http
            .decode_envelope(std::mem::take(&mut response.body))
            .await?;
        Ok((envelope, response))
    }

    async fn fetch_object_page(
        &self,
        api_root_url: &str,
        collection_id: &str,
        object_id: &StixId,
        filter: &ObjectByIdFilter,
        server_cursor: bool,
    ) -> Result<(TaxiiEnvelope, super::request::TaxiiResponse), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Enabled {
            let collection = self.collection(api_root_url, collection_id).await?;
            if !collection.can_read {
                return Err(TaxiiError::ReadNotPermitted);
            }
        }
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/{object_id}/"),
            self.inner.https_policy,
        )?;
        let query = with_clock_skew_object_filter(filter, self.clock_skew(server_cursor))
            .to_query_pairs()?;
        let mut response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let envelope = self
            .inner
            .http
            .decode_envelope(std::mem::take(&mut response.body))
            .await?;
        Ok((envelope, response))
    }

    async fn fetch_manifest_page(
        &self,
        api_root_url: &str,
        collection_id: &str,
        filter: &TaxiiFilter,
        server_cursor: bool,
    ) -> Result<(ManifestResponse, super::request::TaxiiResponse), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Enabled {
            let collection = self.collection(api_root_url, collection_id).await?;
            if !collection.can_read {
                return Err(TaxiiError::ReadNotPermitted);
            }
        }
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/manifest/"),
            self.inner.https_policy,
        )?;
        let query =
            with_clock_skew_filter(filter, self.clock_skew(server_cursor)).to_query_pairs()?;
        let response = self.inner.http.get(url, &query, MANIFEST_ACCEPT).await?;
        let parsed: ManifestResponse = self.inner.http.decode_json(&response)?;
        Ok((parsed, response))
    }

    async fn fetch_versions_page(
        &self,
        api_root_url: &str,
        collection_id: &str,
        object_id: &StixId,
        filter: &VersionsQueryFilter,
        server_cursor: bool,
    ) -> Result<(VersionsResponse, super::request::TaxiiResponse), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Enabled {
            let collection = self.collection(api_root_url, collection_id).await?;
            if !collection.can_read {
                return Err(TaxiiError::ReadNotPermitted);
            }
        }
        let url = join_api_root(
            api_root_url,
            &format!("collections/{collection_id}/objects/{object_id}/versions/"),
            self.inner.https_policy,
        )?;
        let query = with_clock_skew_versions_filter(filter, self.clock_skew(server_cursor))
            .to_query_pairs()?;
        let response = self.inner.http.get(url, &query, TAXII_ACCEPT).await?;
        let parsed: VersionsResponse = self.inner.http.decode_json(&response)?;
        Ok((parsed, response))
    }

    async fn ensure_can_read(
        &self,
        api_root_url: &str,
        collection_id: &str,
    ) -> Result<(), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Disabled
            && self.inner.capability == CapabilityPolicy::Disabled
        {
            return Ok(());
        }
        let collection = self.collection(api_root_url, collection_id).await?;
        if self.inner.preflight == PreflightPolicy::Enabled && !collection.can_read {
            return Err(TaxiiError::ReadNotPermitted);
        }
        self.ensure_collection_capabilities(&collection).await?;
        if self.inner.capability == CapabilityPolicy::Enforce {
            let api = self.api_root(api_root_url).await?;
            self.ensure_api_capabilities(&api).await?;
        }
        Ok(())
    }

    async fn ensure_can_write(
        &self,
        api_root_url: &str,
        collection_id: &str,
    ) -> Result<(), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Disabled
            && self.inner.capability == CapabilityPolicy::Disabled
        {
            return Ok(());
        }
        let collection = self.collection(api_root_url, collection_id).await?;
        if self.inner.preflight == PreflightPolicy::Enabled && !collection.can_write {
            return Err(TaxiiError::WriteNotPermitted);
        }
        self.ensure_collection_capabilities(&collection).await?;
        if self.inner.capability == CapabilityPolicy::Enforce {
            let api = self.api_root(api_root_url).await?;
            self.ensure_api_capabilities(&api).await?;
        }
        Ok(())
    }

    async fn ensure_can_delete(
        &self,
        api_root_url: &str,
        collection_id: &str,
    ) -> Result<(), TaxiiError> {
        if self.inner.preflight == PreflightPolicy::Disabled {
            return Ok(());
        }
        let collection = self.collection(api_root_url, collection_id).await?;
        if collection.can_read && collection.can_write {
            Ok(())
        } else {
            Err(TaxiiError::DeleteNotPermitted)
        }
    }

    /// Seconds to shift `added_after` by: `None` for a server-supplied cursor.
    fn clock_skew(&self, server_cursor: bool) -> Option<i64> {
        if server_cursor || !self.inner.clock_skew_correction {
            return None;
        }
        self.inner.http.clock_skew_secs()
    }

    async fn ensure_api_capabilities(&self, api: &TaxiiApiRoot) -> Result<(), TaxiiError> {
        if self.inner.capability == CapabilityPolicy::Enforce {
            ensure_api_root_supports_taxii(api)?;
        }
        Ok(())
    }

    async fn ensure_collection_capabilities(
        &self,
        collection: &TaxiiCollection,
    ) -> Result<(), TaxiiError> {
        if self.inner.capability == CapabilityPolicy::Enforce {
            ensure_collection_accepts_stix(collection)?;
        }
        Ok(())
    }
}

fn with_clock_skew_filter(filter: &TaxiiFilter, skew_secs: Option<i64>) -> TaxiiFilter {
    let mut adjusted = filter.clone();
    // Guard skew first so `take()` does not run when skew is absent.
    if let Some(secs) = skew_secs
        && let Some(ts) = adjusted.added_after.take()
    {
        adjusted.added_after = Some(ts.adjust_seconds(secs));
    }
    adjusted
}

fn with_clock_skew_object_filter(
    filter: &ObjectByIdFilter,
    skew_secs: Option<i64>,
) -> ObjectByIdFilter {
    let mut adjusted = filter.clone();
    if let Some(secs) = skew_secs
        && let Some(ts) = adjusted.added_after.take()
    {
        adjusted.added_after = Some(ts.adjust_seconds(secs));
    }
    adjusted
}

fn with_clock_skew_versions_filter(
    filter: &VersionsQueryFilter,
    skew_secs: Option<i64>,
) -> VersionsQueryFilter {
    let mut adjusted = filter.clone();
    if let Some(secs) = skew_secs
        && let Some(ts) = adjusted.added_after.take()
    {
        adjusted.added_after = Some(ts.adjust_seconds(secs));
    }
    adjusted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TaxiiTimestamp;

    fn assert_added_after_query(pairs: &[(String, String)], expected: &str) {
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == "added_after" && v == expected),
            "missing added_after={expected} in {pairs:?}"
        );
    }

    #[test]
    fn clock_skew_helper_preserves_added_after_when_skew_absent() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = TaxiiFilter::new().added_after(ts.clone());
        let adjusted = with_clock_skew_filter(&filter, None);
        assert_eq!(adjusted.added_after, Some(ts));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:00.000000Z",
        );
    }

    #[test]
    fn clock_skew_helper_shifts_added_after_when_skew_present() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = TaxiiFilter::new().added_after(ts);
        let adjusted = with_clock_skew_filter(&filter, Some(2));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:02.000000Z",
        );
    }

    #[test]
    fn clock_skew_object_filter_preserves_added_after_when_skew_absent() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = ObjectByIdFilter::new().added_after(ts.clone());
        let adjusted = with_clock_skew_object_filter(&filter, None);
        assert_eq!(adjusted.added_after, Some(ts));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:00.000000Z",
        );
    }

    #[test]
    fn clock_skew_object_filter_shifts_added_after_when_skew_present() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = ObjectByIdFilter::new().added_after(ts);
        let adjusted = with_clock_skew_object_filter(&filter, Some(2));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:02.000000Z",
        );
    }

    #[test]
    fn clock_skew_versions_filter_preserves_added_after_when_skew_absent() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = VersionsQueryFilter::new().added_after(ts.clone());
        let adjusted = with_clock_skew_versions_filter(&filter, None);
        assert_eq!(adjusted.added_after, Some(ts));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:00.000000Z",
        );
    }

    #[test]
    fn clock_skew_versions_filter_shifts_added_after_when_skew_present() {
        let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
        let filter = VersionsQueryFilter::new().added_after(ts);
        let adjusted = with_clock_skew_versions_filter(&filter, Some(2));
        assert_added_after_query(
            &adjusted.to_query_pairs().expect("encode"),
            "2018-01-01T00:00:02.000000Z",
        );
    }
}
