//! Poll a TAXII 2.1 collection into a dynamic-source value.
//!
//! Poll state is not persisted. After a restart the next resolve is a full poll.
//! A failed poll leaves the previous indicator set and cursor unchanged.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::pipeline::sources::{DynamicSource, SourceType, StixOptions, TaxiiAuthConfig};
use rstix::core::{StixTimestamp, TaxiiTimestamp};
use rstix::model::sdo::SdoObject;
use rstix::{
    ApiKeyHeader, BasicAuth, BearerAuth, ParseOptions, PollBudget, StixObject, TaxiiClient,
    TaxiiClientConfig, TaxiiError, TaxiiFilter,
};

use super::stix::{IndicatorSet, StixBuild};
use super::{SourceError, SourceErrorKind};
use crate::EgressPolicy;

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Prepared {
    client: TaxiiClient,
    url: String,
    collection: String,
    page_size: usize,
    options: StixOptions,
}

#[derive(Clone)]
pub(crate) struct PollState {
    set: IndicatorSet,
    added_after: Option<TaxiiTimestamp>,
}

/// Clients and cursors for the TAXII sources this resolver was prepared with.
#[derive(Default)]
pub(crate) struct TaxiiSources {
    prepared: HashMap<String, Prepared>,
    polls: HashMap<String, PollState>,
}

impl TaxiiSources {
    pub(crate) fn prepare(
        &mut self,
        sources: &[DynamicSource],
        policy: EgressPolicy,
        allow_insecure_http: bool,
    ) -> Result<(), SourceError> {
        let mut prepared = HashMap::new();
        for source in sources {
            let SourceType::Taxii {
                url,
                collection,
                auth,
                page_size,
                stix,
            } = &source.source_type
            else {
                continue;
            };
            policy.check_url(url).map_err(|err| SourceError {
                source_id: source.id.clone(),
                kind: SourceErrorKind::Fetch(err.to_string()),
            })?;
            let client = build_client(
                &source.id,
                url,
                *page_size,
                auth,
                source.timeout,
                policy,
                allow_insecure_http,
            )?;
            prepared.insert(
                source.id.clone(),
                Prepared {
                    client,
                    url: url.clone(),
                    collection: collection.clone(),
                    page_size: *page_size,
                    options: stix.clone(),
                },
            );
        }
        self.prepared = prepared;
        self.polls.clear();
        Ok(())
    }

    /// Remove the poll state so the caller can poll without cloning the set.
    ///
    /// The client stays in `prepared`. On failure the caller puts the state back.
    pub(crate) fn take_poll(
        &mut self,
        source_id: &str,
    ) -> Result<(Prepared, Option<PollState>), SourceError> {
        let prepared = self
            .prepared
            .get(source_id)
            .cloned()
            .ok_or_else(|| SourceError {
                source_id: source_id.to_owned(),
                kind: SourceErrorKind::Fetch("TAXII source is not prepared".into()),
            })?;
        Ok((prepared, self.polls.remove(source_id)))
    }

    pub(crate) fn commit(&mut self, source_id: &str, state: PollState) {
        self.polls.insert(source_id.to_owned(), state);
    }
}

/// Poll, then return the state that should be stored and the build.
///
/// On failure the state is the one passed in, unchanged. On success it is the
/// merged set. `None` means there was no state and the poll failed.
pub(crate) async fn poll(
    prepared: &Prepared,
    previous: Option<PollState>,
    now: &StixTimestamp,
) -> (Option<PollState>, Result<StixBuild, SourceError>) {
    let previous_cursor = previous
        .as_ref()
        .and_then(|state| state.added_after.clone());
    let mut filter = TaxiiFilter::new()
        .object_type("indicator")
        .spec_version("2.1")
        .limit(prepared.page_size);
    if let Some(cursor) = previous_cursor.clone() {
        filter = filter.added_after(cursor);
    }
    let budget = PollBudget::for_indicators(prepared.page_size, prepared.options.max_indicators);
    let polled = prepared
        .client
        .poll_objects(&prepared.url, &prepared.collection, filter, budget)
        .await;
    let (objects, date_added_last) = match polled {
        Ok(value) => value,
        Err(err) => return (previous, Err(fetch_error(err))),
    };
    let mut set = previous.map(|state| state.set).unwrap_or_default();
    let mut received_ids = HashSet::new();
    let received = objects.len();
    for object in objects {
        if let StixObject::Sdo(SdoObject::Indicator(indicator)) = object {
            received_ids.insert(indicator.common.id.to_string());
            set.upsert(indicator);
        }
    }
    let (value, skips, active) = set.build(&prepared.options, now, Some(&received_ids));
    (
        Some(PollState {
            set,
            added_after: date_added_last.or(previous_cursor),
        }),
        Ok(StixBuild {
            value,
            skips,
            active,
            objects: received,
        }),
    )
}

fn fetch_error(err: TaxiiError) -> SourceError {
    SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Fetch(err.to_string()),
    }
}

fn build_client(
    source_id: &str,
    url: &str,
    page_size: usize,
    auth: &TaxiiAuthConfig,
    timeout: Option<Duration>,
    policy: EgressPolicy,
    allow_insecure_http: bool,
) -> Result<TaxiiClient, SourceError> {
    let parse_options = ParseOptions {
        allow_custom: true,
        max_object_count: page_size.saturating_mul(2),
        ..ParseOptions::default()
    };
    let permit = move |ip: IpAddr| policy.permit_ip(ip).is_ok();
    let mut config = TaxiiClientConfig::new(url)
        .allow_insecure_http(allow_insecure_http)
        .max_response_bytes(MAX_RESPONSE_BYTES)
        .parse_options(parse_options)
        .address_filter(Arc::new(permit));
    if let Some(timeout) = timeout {
        config = config.timeout(timeout);
    }
    config = apply_auth(config, auth, source_id)?;
    TaxiiClient::new(config).map_err(|err| SourceError {
        source_id: source_id.to_owned(),
        kind: SourceErrorKind::Fetch(err.to_string()),
    })
}

fn apply_auth(
    config: TaxiiClientConfig,
    auth: &TaxiiAuthConfig,
    source_id: &str,
) -> Result<TaxiiClientConfig, SourceError> {
    let read = |name: &str| {
        std::env::var(name).map_err(|_| SourceError {
            source_id: source_id.to_owned(),
            kind: SourceErrorKind::Fetch(format!("environment variable `{name}` is not set")),
        })
    };
    if let Some(name) = &auth.bearer_token_env {
        return Ok(config.auth(BearerAuth::new(read(name)?)));
    }
    if let (Some(user_env), Some(password_env)) = (&auth.basic_user_env, &auth.basic_password_env) {
        return Ok(config.auth(BasicAuth::new(read(user_env)?, read(password_env)?)));
    }
    if auth.basic_user_env.is_some() || auth.basic_password_env.is_some() {
        return Err(SourceError {
            source_id: source_id.to_owned(),
            kind: SourceErrorKind::Fetch(
                "TAXII basic auth requires basic_user_env and basic_password_env".into(),
            ),
        });
    }
    if let Some(name) = &auth.api_key_env {
        let header = auth
            .api_key_header
            .clone()
            .unwrap_or_else(|| "X-API-Key".to_owned());
        return Ok(config.auth(ApiKeyHeader::new(header, read(name)?)));
    }
    Ok(config)
}
