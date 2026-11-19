//! Poll a TAXII 2.1 collection into a dynamic-source value.
//!
//! Poll state is not persisted. After a restart the next resolve is a full poll.
//! A failed poll keeps the pages it applied and leaves the cursor unchanged. A
//! poll that stops at its budget keeps the pages it applied and moves the cursor
//! to just before the last page's `X-TAXII-Date-Added-Last`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::pipeline::sources::{DynamicSource, SourceType, StixOptions, TaxiiAuthConfig};
use rstix::core::{StixTimestamp, TaxiiTimestamp};
use rstix::model::sdo::SdoObject;
use rstix::{
    ApiKeyHeader, BasicAuth, BearerAuth, ParseOptions, PollBudget, PollStop, StixObject,
    TaxiiClient, TaxiiClientConfig, TaxiiError, TaxiiFilter,
};

use super::stix::{IndicatorSet, StixBuild};
use super::{SourceError, SourceErrorKind};
use crate::EgressPolicy;

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Prepared {
    source_id: String,
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
                    source_id: source.id.clone(),
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
/// Pages applied before a failure stay in the set and the cursor stays where it
/// was, so the next poll reads them again and the upsert ignores the repeats.
/// A budget stop is success when it moves the cursor, and the build covers the
/// pages applied so far.
pub(crate) async fn poll(
    prepared: &Prepared,
    previous: Option<PollState>,
    now: &StixTimestamp,
) -> (PollState, Result<StixBuild, SourceError>) {
    let (mut set, previous_cursor) = match previous {
        Some(state) => (state.set, state.added_after),
        None => (IndicatorSet::default(), None),
    };
    let mut filter = TaxiiFilter::new()
        .object_type("indicator")
        .spec_version("2.1")
        .limit(prepared.page_size);
    if let Some(cursor) = previous_cursor.clone() {
        filter = filter.added_after(cursor);
    }
    let budget = PollBudget::for_indicators(prepared.page_size, prepared.options.max_indicators);
    let mut received_ids = HashSet::new();
    let mut received = 0usize;
    let mut last_page_date = None;
    let mut latest_date = None;
    let polled = prepared
        .client
        .poll_object_pages(
            &prepared.url,
            &prepared.collection,
            filter,
            budget,
            |page| {
                received += page.objects.len();
                for object in page.objects {
                    if let StixObject::Sdo(SdoObject::Indicator(indicator)) = object {
                        received_ids.insert(indicator.common.id.to_string());
                        set.upsert(indicator);
                    }
                }
                last_page_date = page.date_added_last;
                if last_page_date.is_some() {
                    latest_date = last_page_date.clone();
                }
            },
        )
        .await;
    let kept = |set: IndicatorSet| PollState {
        set,
        added_after: previous_cursor.clone(),
    };
    let added_after = match polled {
        Err(err) => return (kept(set), Err(fetch_error(err.to_string()))),
        Ok(PollStop::Finished) => latest_date.or(previous_cursor.clone()),
        Ok(PollStop::Budget) => {
            // `added_after` is exclusive and objects on the next page can share
            // the last page's date, so the cursor sits one microsecond before it.
            let resume = last_page_date.map(|date| date.adjust_micros(-1));
            match resume {
                Some(cursor) if previous_cursor.as_ref().is_none_or(|prev| cursor > *prev) => {
                    tracing::warn!(
                        source_id = %prepared.source_id,
                        objects = received,
                        added_after = %cursor.to_rfc3339(),
                        "TAXII poll stopped at its budget; the next refresh continues from the cursor"
                    );
                    Some(cursor)
                }
                _ => {
                    let err = TaxiiError::PollBudgetExceeded {
                        max_pages: budget.max_pages,
                        max_objects: budget.max_objects,
                    };
                    return (
                        kept(set),
                        Err(fetch_error(format!(
                            "{err}, and the last page did not advance X-TAXII-Date-Added-Last, so the next poll cannot continue"
                        ))),
                    );
                }
            }
        }
    };
    let (value, skips, active) = set.build(&prepared.options, now, Some(&received_ids));
    (
        PollState { set, added_after },
        Ok(StixBuild {
            value,
            skips,
            active,
            objects: received,
        }),
    )
}

fn fetch_error(message: String) -> SourceError {
    SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Fetch(message),
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
