//! Import TAXII collection objects into a [`StixStore`](crate::store::StixStore).
//!
//! Requires **`taxii`** and **`store`** features (or the `taxii-store` meta-feature).
//! Optional validation before import requires the **`validate`** feature and
//! [`IngestOptions::validator`](IngestOptions::validator).

use crate::core::StixId;
#[cfg(feature = "validate")]
use crate::model::Bundle;
use crate::store::{ImportReport, StixStore, StoreError, audit_unresolved_refs};
#[cfg(feature = "validate")]
use crate::validate::{ValidationReport, Validator};

use super::envelope::TaxiiEnvelope;
use super::headers::TaxiiPageHeaders;
use super::pagination::{advance_more_page, recover_from_range_not_satisfiable};
use super::{TaxiiClient, TaxiiError, TaxiiFilter};

/// Synthetic bundle id for [`ingest_collection`] when no custom id is supplied.
pub const DEFAULT_INGEST_BUNDLE_ID: &str = "bundle--00000000-0000-0000-0000-000000000001";

/// Options controlling TAXII collection ingest.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "validate"), derive(Default))]
pub struct IngestOptions {
    /// When set, each object is validated before import as a one-object synthetic [`Bundle`]
    /// (profile-dependent; [`Validator::producer_strict`] skips References).
    #[cfg(feature = "validate")]
    pub validator: Option<Validator>,
    /// Skip store import for objects that fail validation (default: `true` when `validate` is enabled).
    #[cfg(feature = "validate")]
    pub reject_invalid_objects: bool,
}

#[cfg(feature = "validate")]
impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            validator: None,
            reject_invalid_objects: true,
        }
    }
}

#[cfg(feature = "validate")]
impl IngestOptions {
    /// Validate each object with [`Validator::producer_strict`] and reject invalid objects.
    ///
    /// Skips the References phase (TAXII pages are not closed bundles). Unresolved refs are
    /// audited after all pages via [`ImportReport::unresolved_references`].
    pub fn producer_strict() -> Self {
        Self {
            validator: Some(Validator::producer_strict()),
            reject_invalid_objects: true,
        }
    }

    /// Validate each object with [`Validator::interop_strict`] at zero leniency.
    ///
    /// **Stricter than [`Self::producer_strict`]:** warnings (for example `STIX-W0010`) fail
    /// validation, and the References phase runs on each one-object synthetic bundle (unresolved
    /// outbound refs fail closed). Not for paginated collection ingest — use
    /// [`Self::producer_strict`].
    pub fn interop_strict() -> Self {
        Self {
            validator: Some(Validator::interop_strict()),
            reject_invalid_objects: true,
        }
    }

    /// Attach a custom validator profile.
    pub fn with_validator(validator: Validator) -> Self {
        Self {
            validator: Some(validator),
            reject_invalid_objects: true,
        }
    }

    /// Import objects even when validation fails (diagnostics still recorded).
    pub fn allow_invalid_objects(mut self) -> Self {
        self.reject_invalid_objects = false;
        self
    }
}

/// Validation outcome for one rejected TAXII object.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(feature = "validate")]
pub struct IngestValidationFailure {
    /// Zero-based page index in fetch order.
    pub page: usize,
    /// STIX id of the object that was not imported (or imported with `allow_invalid_objects`).
    pub object_id: StixId,
    /// Pipeline diagnostics for the object.
    pub report: ValidationReport,
}

/// Aggregated validation results for an ingest run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg(feature = "validate")]
pub struct IngestValidationReport {
    /// Objects validated (validator configured and page non-empty).
    pub objects_validated: usize,
    /// Objects skipped because validation failed and [`IngestOptions::reject_invalid_objects`] was set.
    pub objects_rejected: usize,
    /// Per-object failure details.
    pub failures: Vec<IngestValidationFailure>,
}

#[cfg(feature = "validate")]
impl IngestValidationReport {
    /// True when no object was rejected.
    pub fn is_valid(&self) -> bool {
        self.objects_rejected == 0
    }
}

/// Result of TAXII collection ingest (import + optional validation summary).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Store import counters and unresolved reference audit.
    pub import: ImportReport,
    /// Present when the `validate` feature is enabled.
    #[cfg(feature = "validate")]
    pub validation: IngestValidationReport,
}

impl IngestReport {
    /// Import counters (convenience for callers that only need store stats).
    pub fn import(&self) -> &ImportReport {
        &self.import
    }
}

/// Errors from TAXII collection ingest into a store.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// HTTP / TAXII client failure while fetching objects.
    #[error(transparent)]
    Taxii(#[from] TaxiiError),
    /// Store import failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Fetch all objects from a TAXII collection (paginated) and import them into `store`.
///
/// Each TAXII response page is upserted via [`StixStore::import_objects`] so memory stays
/// bounded by page size. After the full collection is imported, references are audited once
/// against the store.
///
/// Uses [`DEFAULT_INGEST_BUNDLE_ID`] as the conventional wrapper id when exporting the store
/// with [`StixStore::export_bundle`]. For a custom id, call
/// [`ingest_collection_with_bundle_id`].
pub async fn ingest_collection(
    client: &TaxiiClient,
    store: &impl StixStore,
    api_root_url: &str,
    collection_id: &str,
    filter: TaxiiFilter,
) -> Result<IngestReport, IngestError> {
    ingest_collection_with_bundle_id(
        client,
        store,
        api_root_url,
        collection_id,
        filter,
        StixId::parse(DEFAULT_INGEST_BUNDLE_ID).expect("valid default ingest bundle id"),
        IngestOptions::default(),
    )
    .await
}

/// Like [`ingest_collection`], recording `bundle_id` for callers that export with
/// [`StixStore::export_bundle`]. Ingest does not materialize a STIX bundle on the wire.
pub async fn ingest_collection_with_bundle_id(
    client: &TaxiiClient,
    store: &impl StixStore,
    api_root_url: &str,
    collection_id: &str,
    filter: TaxiiFilter,
    bundle_id: StixId,
    options: IngestOptions,
) -> Result<IngestReport, IngestError> {
    let baseline_added_after = filter.added_after.clone();
    let mut filter = filter;
    let mut finished = false;
    let mut report = IngestReport::default();
    let mut ingested_ids = Vec::new();
    let mut page_index = 0usize;
    let mut server_cursor = false;

    while !finished {
        let sent = filter.clone();
        match client
            .fetch_objects_page(api_root_url, collection_id, &filter, server_cursor)
            .await
        {
            Ok((envelope, response)) => {
                let date_added_last = TaxiiPageHeaders::from_response(&response).date_added_last;
                let more = envelope.more;
                let next = envelope.next.clone();
                let page_empty = envelope.objects.is_empty();
                import_page(
                    store,
                    envelope,
                    bundle_id.clone(),
                    &options,
                    page_index,
                    &mut report,
                    &mut ingested_ids,
                )?;
                page_index += 1;
                finished = if page_empty && more {
                    true
                } else {
                    advance_more_page(&mut filter, more, next, date_added_last, false)?
                };
                if !finished && filter == sent {
                    return Err(TaxiiError::RepeatedPaginationCursor.into());
                }
                server_cursor = true;
            }
            Err(err @ TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                recover_from_range_not_satisfiable(&mut filter, baseline_added_after.clone());
                if filter == sent {
                    return Err(err.into());
                }
                server_cursor = false;
            }
            Err(err) => return Err(err.into()),
        }
    }

    report.import.unresolved_references = audit_unresolved_refs(store, &ingested_ids)?;
    Ok(report)
}

fn import_page(
    store: &impl StixStore,
    envelope: TaxiiEnvelope,
    bundle_id: StixId,
    options: &IngestOptions,
    page_index: usize,
    report: &mut IngestReport,
    ingested_ids: &mut Vec<StixId>,
) -> Result<(), IngestError> {
    if envelope.objects.is_empty() {
        return Ok(());
    }

    #[cfg(not(feature = "validate"))]
    let _ = (&bundle_id, options, page_index);

    let mut batch = Vec::with_capacity(envelope.objects.len());
    for object in envelope.objects {
        #[cfg(feature = "validate")]
        if let Some(validator) = &options.validator {
            report.validation.objects_validated += 1;
            let bundle = Bundle::from_objects(bundle_id.clone(), vec![object.clone()]);
            let validation = validator.validate_bundle(&bundle);
            if !validation.is_valid() {
                report.validation.failures.push(IngestValidationFailure {
                    page: page_index,
                    object_id: object.id().clone(),
                    report: validation,
                });
                if options.reject_invalid_objects {
                    report.validation.objects_rejected += 1;
                    continue;
                }
            }
        }
        ingested_ids.push(object.id().clone());
        batch.push(object);
    }

    if batch.is_empty() {
        return Ok(());
    }
    merge_import_report(&mut report.import, store.import_objects(&batch)?);
    Ok(())
}

fn merge_import_report(into: &mut ImportReport, page: ImportReport) {
    into.objects_added += page.objects_added;
    into.objects_updated += page.objects_updated;
    into.objects_deduplicated += page.objects_deduplicated;
    into.fingerprint_conflicts
        .extend(page.fingerprint_conflicts);
}
