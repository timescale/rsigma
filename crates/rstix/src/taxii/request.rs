//! Internal HTTP request execution with retries.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use reqwest::{Method, StatusCode, header::HeaderMap};
use url::Url;

use crate::model::ParseOptions;

use super::TaxiiError;
use super::address_filter::{self, AddressFilter};
use super::dns::DnsLookupOptions;
use super::envelope::parse_envelope;
use super::error::{parse_error_body, parse_retry_after};
use super::media::{TAXII_ACCEPT, TAXII_CONTENT_TYPE, is_taxii_content_type};
use super::retry::RetryPolicy;
use super::server_trust::{ServerTrustPolicy, TlsaCache};
use super::www_authenticate::parse_www_authenticate;
use super::{TaxiiAuthProvider, TaxiiEnvelope};

pub(crate) struct TaxiiHttp {
    pub client: reqwest::Client,
    pub user_agent: String,
    pub auth: Option<Arc<dyn TaxiiAuthProvider>>,
    pub retry: RetryPolicy,
    pub max_response_bytes: usize,
    pub parse_options: ParseOptions,
    pub clock_skew: Arc<std::sync::RwLock<Option<i64>>>,
    pub server_trust: ServerTrustPolicy,
    pub tlsa_cache: TlsaCache,
    pub dns_nameserver: Option<SocketAddr>,
    pub dane_require_dnssec: bool,
    pub address_filter: Option<AddressFilter>,
    /// Host the certificate is checked against when it is not the URL host.
    pub tls_identity: Option<String>,
}

pub(crate) struct TaxiiResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TaxiiHttp {
    pub async fn get(
        &self,
        url: Url,
        query: &[(String, String)],
        accept: &str,
    ) -> Result<TaxiiResponse, TaxiiError> {
        self.execute(Method::GET, url, query, None, accept).await
    }

    pub async fn post(&self, url: Url, body: Vec<u8>) -> Result<TaxiiResponse, TaxiiError> {
        self.execute(Method::POST, url, &[], Some(body), TAXII_ACCEPT)
            .await
    }

    pub async fn delete(
        &self,
        url: Url,
        query: &[(String, String)],
    ) -> Result<TaxiiResponse, TaxiiError> {
        self.execute(Method::DELETE, url, query, None, TAXII_ACCEPT)
            .await
    }

    pub fn clock_skew_secs(&self) -> Option<i64> {
        self.clock_skew.read().ok().and_then(|v| *v)
    }

    async fn execute(
        &self,
        method: Method,
        url: Url,
        query: &[(String, String)],
        body: Option<Vec<u8>>,
        accept: &str,
    ) -> Result<TaxiiResponse, TaxiiError> {
        let mut attempt = 0u32;
        if let Some(filter) = &self.address_filter {
            address_filter::reject_literal_host(&url, filter)?;
        }
        loop {
            self.prefetch_dane(&url).await?;

            let mut builder = self
                .client
                .request(method.clone(), url.clone())
                .header(reqwest::header::ACCEPT, accept)
                .header(reqwest::header::USER_AGENT, &self.user_agent);
            if method == Method::POST {
                builder = builder.header(reqwest::header::CONTENT_TYPE, TAXII_CONTENT_TYPE);
            }
            if let Some(auth) = &self.auth {
                let mut headers = HeaderMap::new();
                auth.inject_credentials(&mut headers)?;
                for (name, value) in headers.iter() {
                    builder = builder.header(name, value);
                }
            }
            if !query.is_empty() {
                builder = builder.query(query);
            }
            if let Some(payload) = &body {
                builder = builder.body(payload.clone());
            }

            match builder.send().await {
                Ok(response) => match self.consume(response).await {
                    Ok(parsed) if parsed.status.is_success() => return Ok(parsed),
                    Ok(parsed) => {
                        let retry_after = parsed
                            .headers
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(parse_retry_after);
                        let www_authenticate = parsed
                            .headers
                            .get(reqwest::header::WWW_AUTHENTICATE)
                            .and_then(|v| v.to_str().ok())
                            .map(parse_www_authenticate)
                            .unwrap_or_default();
                        let err = TaxiiError::from_http_status(
                            parsed.status,
                            parse_error_body(&String::from_utf8_lossy(&parsed.body)),
                            retry_after,
                            www_authenticate,
                        );
                        if attempt < self.retry.max_attempts && err.is_retryable() {
                            let Some(delay) = self.retry_delay(&err, attempt + 1) else {
                                return Err(err);
                            };
                            attempt += 1;
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(err);
                    }
                    Err(err) if attempt < self.retry.max_attempts && err.is_retryable() => {
                        attempt += 1;
                        tokio::time::sleep(self.retry.delay_for_attempt(attempt)).await;
                        continue;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) if attempt < self.retry.max_attempts && is_transport_retryable(&err) => {
                    attempt += 1;
                    tokio::time::sleep(self.retry.delay_for_attempt(attempt)).await;
                    continue;
                }
                Err(err) => return Err(TaxiiError::NetworkError(err)),
            }
        }
    }

    /// Delay before retry `attempt`, or `None` when the server asked for a
    /// longer wait than [`RetryPolicy::max_delay`].
    fn retry_delay(&self, err: &TaxiiError, attempt: u32) -> Option<Duration> {
        match err.retry_after() {
            Some(requested) if requested > self.retry.max_delay => None,
            Some(requested) => Some(requested),
            None => Some(self.retry.delay_for_attempt(attempt)),
        }
    }

    async fn consume(&self, response: reqwest::Response) -> Result<TaxiiResponse, TaxiiError> {
        let status = response.status();
        let headers = response.headers().clone();
        if status.is_success() {
            validate_success_content_type(&headers)?;
        }
        let clock_skew = headers
            .get(reqwest::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date_skew);
        match clock_skew {
            Some(skew) if skew.unsigned_abs() > MAX_CLOCK_SKEW_SECS => {
                tracing::warn!(
                    skew_secs = skew,
                    "TAXII server Date header is more than 24 hours from the local clock; ignoring it"
                );
            }
            Some(skew) => {
                if let Ok(mut guard) = self.clock_skew.write() {
                    *guard = Some(skew);
                }
            }
            None => {}
        }
        let body = read_response_body(response, self.max_response_bytes).await?;
        Ok(TaxiiResponse {
            status,
            headers,
            body,
        })
    }

    pub fn decode_json<T: serde::de::DeserializeOwned>(
        &self,
        response: &TaxiiResponse,
    ) -> Result<T, TaxiiError> {
        serde_json::from_slice(&response.body).map_err(|err| TaxiiError::MalformedResponse {
            reason: err.to_string(),
        })
    }

    /// Parse an envelope body on the blocking pool, so a large page does not
    /// stall the async runtime.
    pub async fn decode_envelope(&self, body: Vec<u8>) -> Result<TaxiiEnvelope, TaxiiError> {
        let options = self.parse_options.clone();
        match tokio::task::spawn_blocking(move || parse_envelope(&body, &options)).await {
            Ok(result) => result,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => Err(TaxiiError::MalformedResponse {
                reason: format!("envelope parse did not finish: {err}"),
            }),
        }
    }

    async fn prefetch_dane(&self, url: &Url) -> Result<(), TaxiiError> {
        if !matches!(self.server_trust, ServerTrustPolicy::Dane) || url.scheme() != "https" {
            return Ok(());
        }
        let Some(host) = self.tls_identity.as_deref().or(url.host_str()) else {
            return Ok(());
        };
        let port = url.port().unwrap_or(443);
        let dns_options = DnsLookupOptions::for_dane(self.dane_require_dnssec);
        let records =
            super::dns::resolve_tlsa_with_options(host, port, self.dns_nameserver, dns_options)
                .await?;
        if records.is_empty() {
            return Err(TaxiiError::InvalidServerTrust {
                reason: format!("DANE: no TLSA records for {host}:{port}"),
            });
        }
        self.tlsa_cache.insert(host.to_owned(), records);
        Ok(())
    }
}

fn check_content_length(len: Option<u64>, max_response_bytes: usize) -> Result<(), TaxiiError> {
    if let Some(len) = len
        && len > max_response_bytes as u64
    {
        return Err(TaxiiError::ResponseTooLarge {
            max: max_response_bytes,
        });
    }
    Ok(())
}

async fn read_response_body(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, TaxiiError> {
    check_content_length(response.content_length(), max_response_bytes)?;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(TaxiiError::NetworkError)?;
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(TaxiiError::ResponseTooLarge {
                max: max_response_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn default_user_agent() -> String {
    format!("rstix/{}", env!("CARGO_PKG_VERSION"))
}

pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 512 * 1024 * 1024;
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_STATUS_MAX_POLLS: u32 = 120;

fn is_transport_retryable(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

/// Largest server clock offset, in seconds, applied to `added_after`.
const MAX_CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;

pub(crate) fn parse_http_date_skew(value: &str) -> Option<i64> {
    let server =
        time::OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc2822)
            .ok()?;
    let now = time::OffsetDateTime::now_utc();
    server.unix_timestamp().checked_sub(now.unix_timestamp())
}

fn validate_success_content_type(headers: &HeaderMap) -> Result<(), TaxiiError> {
    match headers.get(reqwest::header::CONTENT_TYPE) {
        Some(content_type) => {
            let value = content_type.to_str().unwrap_or_default();
            if is_taxii_content_type(value) {
                Ok(())
            } else {
                Err(TaxiiError::InvalidContentType {
                    got: value.to_owned(),
                })
            }
        }
        None => Err(TaxiiError::MissingContentType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_content_type_is_rejected() {
        let headers = HeaderMap::new();
        let err = validate_success_content_type(&headers).unwrap_err();
        assert!(matches!(err, TaxiiError::MissingContentType));
    }

    #[test]
    fn invalid_content_type_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let err = validate_success_content_type(&headers).unwrap_err();
        assert!(matches!(err, TaxiiError::InvalidContentType { .. }));
    }

    #[test]
    fn content_length_over_max_is_rejected_before_read() {
        let err = check_content_length(Some(1024), 512).unwrap_err();
        assert!(matches!(err, TaxiiError::ResponseTooLarge { max: 512 }));
    }
}
