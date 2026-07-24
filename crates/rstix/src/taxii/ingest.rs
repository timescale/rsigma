//! Import TAXII collection objects into a [`StixStore`](crate::store::StixStore).
//!
//! Requires **`taxii`** and **`store`** features (or the `taxii-store` meta-feature).

use crate::core::StixId;
use crate::store::{ImportReport, StixStore, StoreError, audit_unresolved_refs};

use super::envelope::TaxiiEnvelope;
use super::headers::TaxiiPageHeaders;
use super::pagination::{advance_more_page, recover_from_range_not_satisfiable};
use super::{TaxiiClient, TaxiiError, TaxiiFilter};

/// Synthetic bundle id for [`ingest_collection`] when no custom id is supplied.
pub const DEFAULT_INGEST_BUNDLE_ID: &str = "bundle--00000000-0000-0000-0000-000000000001";

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
) -> Result<ImportReport, IngestError> {
    ingest_collection_with_bundle_id(
        client,
        store,
        api_root_url,
        collection_id,
        filter,
        StixId::parse(DEFAULT_INGEST_BUNDLE_ID).expect("valid default ingest bundle id"),
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
    _bundle_id: StixId,
) -> Result<ImportReport, IngestError> {
    let baseline_added_after = filter.added_after.clone();
    let mut filter = filter;
    let mut finished = false;
    let mut report = ImportReport::default();
    let mut ingested_ids = Vec::new();

    while !finished {
        match client
            .fetch_objects_page(api_root_url, collection_id, &filter)
            .await
        {
            Ok((envelope, response)) => {
                let date_added_last = TaxiiPageHeaders::from_response(&response).date_added_last;
                let more = envelope.more;
                let next = envelope.next.clone();
                let page_empty = envelope.objects.is_empty();
                import_page(store, envelope, &mut report, &mut ingested_ids)?;
                finished = if page_empty && more {
                    true
                } else {
                    advance_more_page(&mut filter, more, next, date_added_last, false)?
                };
            }
            Err(TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                recover_from_range_not_satisfiable(&mut filter, baseline_added_after.clone());
            }
            Err(err) => return Err(err.into()),
        }
    }

    report.unresolved_references = audit_unresolved_refs(store, &ingested_ids)?;
    Ok(report)
}

fn import_page(
    store: &impl StixStore,
    envelope: TaxiiEnvelope,
    report: &mut ImportReport,
    ingested_ids: &mut Vec<StixId>,
) -> Result<(), IngestError> {
    if envelope.objects.is_empty() {
        return Ok(());
    }
    for object in &envelope.objects {
        ingested_ids.push(object.id().clone());
    }
    merge_import_report(report, store.import_objects(&envelope.objects)?);
    Ok(())
}

fn merge_import_report(into: &mut ImportReport, page: ImportReport) {
    into.objects_added += page.objects_added;
    into.objects_updated += page.objects_updated;
    into.objects_deduplicated += page.objects_deduplicated;
    into.fingerprint_conflicts
        .extend(page.fingerprint_conflicts);
}
