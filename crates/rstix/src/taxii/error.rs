//! TAXII HTTP and transport errors.

use crate::ParseError;

/// Structured TAXII error response body (spec section 3.6.1).
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct TaxiiErrorResponse {
    /// Human-readable title (required).
    pub title: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional error instance id.
    #[serde(default)]
    pub error_id: Option<String>,
    /// Optional application error code.
    #[serde(default)]
    pub error_code: Option<String>,
    /// Optional HTTP status echo.
    #[serde(default)]
    pub http_status: Option<String>,
    /// Optional external details URL.
    #[serde(default)]
    pub external_details: Option<String>,
    /// Optional structured details object.
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

/// Errors raised by the TAXII client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TaxiiError {
    /// HTTP 400 Bad Request.
    #[error("400 Bad Request: {description}")]
    BadRequest {
        /// Error description from the server or status line.
        description: String,
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 401 Unauthorized.
    #[error("401 Unauthorized")]
    Unauthorized {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
        /// Parsed `WWW-Authenticate` challenges when present.
        challenges: Vec<super::www_authenticate::AuthChallenge>,
    },
    /// HTTP 403 Forbidden.
    #[error("403 Forbidden")]
    Forbidden {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 404 Not Found.
    #[error("404 Not Found: {description}")]
    NotFound {
        /// Error description.
        description: String,
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 406 Not Acceptable.
    #[error("406 Not Acceptable")]
    NotAcceptable {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 415 Unsupported Media Type.
    #[error("415 Unsupported Media Type")]
    UnsupportedMediaType {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 413 Payload Too Large.
    #[error("413 Payload Too Large")]
    PayloadTooLarge {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 416 Range Not Satisfiable (cursor expired).
    #[error("416 Range Not Satisfiable (cursor expired)")]
    RequestedRangeNotSatisfiable {
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 422 Unprocessable Entity.
    #[error("422 Unprocessable Entity: {description}")]
    UnprocessableEntity {
        /// Error description.
        description: String,
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 429 Rate Limited.
    #[error("429 Rate Limited; retry after {retry_after:?}")]
    RateLimited {
        /// Parsed Retry-After duration when present.
        retry_after: Option<std::time::Duration>,
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// HTTP 5xx server error.
    #[error("server error {status}")]
    ServerError {
        /// HTTP status code.
        status: u16,
        /// Parsed Retry-After duration when present.
        retry_after: Option<std::time::Duration>,
        /// Parsed TAXII error body when present.
        body: Option<TaxiiErrorResponse>,
    },
    /// Response `Content-Type` is not TAXII JSON.
    #[error("invalid content type: got {got}")]
    InvalidContentType {
        /// Observed header value.
        got: String,
    },
    /// Success response omitted required `Content-Type`.
    #[error("missing Content-Type header on success response")]
    MissingContentType,
    /// Response body could not be interpreted.
    #[error("malformed response: {reason}")]
    MalformedResponse {
        /// Parse failure reason.
        reason: String,
    },
    /// Underlying HTTP transport failure.
    #[error("network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    /// STIX object in a TAXII envelope failed to parse.
    #[error("STIX parse error in response: {0}")]
    StixParseError(#[from] ParseError),
    /// Client-side write guard: collection `can_write` is false.
    #[error("write operation blocked: collection has can_write=false")]
    WriteNotPermitted,
    /// Client-side read guard: collection `can_read` is false.
    #[error("read operation blocked: collection has can_read=false")]
    ReadNotPermitted,
    /// Client-side delete guard: collection requires both `can_read` and `can_write`.
    #[error("delete operation blocked: collection requires can_read=true and can_write=true")]
    DeleteNotPermitted,
    /// Invalid filter parameters for a TAXII request.
    #[error("invalid filter: {reason}")]
    InvalidFilter {
        /// Validation failure reason.
        reason: String,
    },
    /// URL must use HTTPS (spec section 8.5.1).
    #[error("TAXII requires HTTPS: {0}")]
    InsecureUrl(String),
    /// DNS SRV discovery failure.
    #[error("DNS SRV discovery failed: {0}")]
    DnsDiscovery(String),
    /// Client certificate could not be loaded.
    #[error("invalid client certificate: {0}")]
    InvalidClientCertificate(String),
    /// Request body exceeds API Root `max_content_length`.
    #[error("request body length {len} exceeds max_content_length {max}")]
    RequestBodyTooLarge {
        /// Serialized body length in octets.
        len: usize,
        /// API Root limit.
        max: u64,
    },
    /// Response exceeded configured byte limit.
    #[error("response exceeds max_response_bytes ({max})")]
    ResponseTooLarge {
        /// Configured limit.
        max: usize,
    },
    /// Invalid URL construction or resolution.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// Status polling exceeded the configured maximum attempts.
    #[error("status polling exceeded max_polls ({max_polls})")]
    StatusPollTimeout {
        /// Last observed status.
        last: super::TaxiiStatus,
        /// Configured poll limit.
        max_polls: u32,
    },
    /// Authentication provider failure.
    #[error("authentication error: {0}")]
    Auth(#[from] super::auth::AuthError),
    /// API Root does not advertise TAXII 2.1.
    #[error("API Root does not support TAXII 2.1; versions: {versions:?}")]
    UnsupportedApiRoot {
        /// Advertised `versions` values.
        versions: Vec<String>,
    },
    /// Collection does not accept STIX 2.1 objects.
    #[error("collection media_types do not include STIX 2.1: {media_types:?}")]
    UnsupportedCollectionMedia {
        /// Advertised collection `media_types`.
        media_types: Vec<String>,
    },
    /// Paginated response missing required headers (spec section 3.2).
    #[error("missing pagination headers while more=true")]
    MissingPaginationHeaders,
    /// Invalid server trust / TLS configuration.
    #[error("invalid server trust configuration: {reason}")]
    InvalidServerTrust {
        /// Failure reason.
        reason: String,
    },
}

impl TaxiiError {
    pub(crate) fn from_http_status(
        status: reqwest::StatusCode,
        body: Option<TaxiiErrorResponse>,
        retry_after: Option<std::time::Duration>,
        www_authenticate: Vec<super::www_authenticate::AuthChallenge>,
    ) -> Self {
        let description = body
            .as_ref()
            .and_then(|b| b.description.clone())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned());
        match status.as_u16() {
            400 => Self::BadRequest { description, body },
            401 => Self::Unauthorized {
                body,
                challenges: www_authenticate,
            },
            403 => Self::Forbidden { body },
            404 => Self::NotFound { description, body },
            406 => Self::NotAcceptable { body },
            413 => Self::PayloadTooLarge { body },
            415 => Self::UnsupportedMediaType { body },
            416 => Self::RequestedRangeNotSatisfiable { body },
            422 => Self::UnprocessableEntity { description, body },
            429 => Self::RateLimited { retry_after, body },
            code if (500..600).contains(&code) => Self::ServerError {
                status: code,
                retry_after,
                body,
            },
            code => Self::ServerError {
                status: code,
                retry_after,
                body,
            },
        }
    }

    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::NetworkError(err) => err.is_timeout() || err.is_connect() || err.is_request(),
            Self::ServerError { .. } | Self::RateLimited { .. } => true,
            _ => false,
        }
    }

    pub(crate) fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::RateLimited { retry_after, .. } => *retry_after,
            Self::ServerError { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

pub(crate) fn parse_error_body(text: &str) -> Option<TaxiiErrorResponse> {
    serde_json::from_str(text).ok()
}

pub(crate) fn parse_retry_after(value: &str) -> Option<std::time::Duration> {
    if let Ok(secs) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(secs));
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822)
        .ok()
        .and_then(|dt| {
            let now = time::OffsetDateTime::now_utc();
            dt.unix_timestamp()
                .checked_sub(now.unix_timestamp())
                .map(|s| std::time::Duration::from_secs(s.max(0) as u64))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_errors_are_retryable() {
        assert!(
            TaxiiError::ServerError {
                status: 503,
                retry_after: None,
                body: None
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_found_is_not_retryable() {
        assert!(
            !TaxiiError::NotFound {
                description: "x".into(),
                body: None
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_carries_challenges() {
        let err = TaxiiError::Unauthorized {
            body: None,
            challenges: super::super::www_authenticate::parse_www_authenticate(
                r#"Basic realm="x""#,
            ),
        };
        match err {
            TaxiiError::Unauthorized { challenges, .. } => assert!(!challenges.is_empty()),
            _ => panic!("expected Unauthorized"),
        }
    }
}
