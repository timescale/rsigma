//! Import TAXII collection objects into a [`StixStore`](crate::store::StixStore).
//!
//! Requires **`taxii`** and **`store`** features (or the `taxii-store` meta-feature).

use futures::StreamExt;

use crate::core::StixId;
use crate::model::Bundle;
use crate::store::{ImportReport, StixStore, StoreError};

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
/// Objects are collected from [`TaxiiClient::objects_stream`], wrapped in a synthetic
/// [`Bundle`] via [`Bundle::from_objects`], then passed to [`StixStore::import_bundle`].
/// Cross-object references are checked against the fetched set and objects already
/// in the store (incremental TAXII sync).
///
/// Uses [`DEFAULT_INGEST_BUNDLE_ID`] as the wrapper bundle id. For a custom id, call
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

/// Like [`ingest_collection`], with an explicit wrapper [`Bundle`] id (for export/metadata).
pub async fn ingest_collection_with_bundle_id(
    client: &TaxiiClient,
    store: &impl StixStore,
    api_root_url: &str,
    collection_id: &str,
    filter: TaxiiFilter,
    bundle_id: StixId,
) -> Result<ImportReport, IngestError> {
    let mut objects = Vec::new();
    let mut stream = client.objects_stream(api_root_url, collection_id, filter);
    while let Some(result) = stream.next().await {
        objects.push(result?);
    }
    let bundle = Bundle::from_objects(bundle_id, objects);
    Ok(store.import_bundle(&bundle)?)
}
