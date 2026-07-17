//! STIX object store trait and query types.

mod error;
#[cfg(feature = "store-fs")]
mod fs;
mod memory;
mod search;

pub use error::StoreError;
#[cfg(feature = "store-fs")]
pub use fs::FsStore;
pub use memory::{MemoryStore, StoredSco};

use crate::core::{StixId, StixObjectKind, StixTimestamp};
use crate::model::Bundle;
use crate::model::stix_object::StixObject;

/// Cross-producer SCO fingerprint collision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintConflict {
    /// First asserted id observed for the fingerprint.
    pub existing_asserted_id: StixId,
    /// New asserted id with the same fingerprint.
    pub new_asserted_id: StixId,
    /// Computed UUIDv5 fingerprint id.
    pub fingerprint_id: StixId,
}

/// Result of importing a bundle into a store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Objects newly inserted.
    pub objects_added: usize,
    /// Objects updated with a new version.
    pub objects_updated: usize,
    /// Identical objects skipped (idempotent upsert).
    pub objects_deduplicated: usize,
    /// SCO fingerprint collisions across producers.
    pub fingerprint_conflicts: Vec<FingerprintConflict>,
    /// References to objects absent from the imported bundle.
    pub unresolved_references: Vec<(StixId, String, StixId)>,
}

/// Opaque pagination cursor for store queries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryCursor {
    /// Byte/row offset into the sorted query result.
    pub offset: usize,
}

/// Query result page.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryResult {
    /// Matching objects for this page.
    pub objects: Vec<StixObject>,
    /// Cursor for the next page when truncated.
    pub next_cursor: Option<QueryCursor>,
}

/// Typed store query parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StixQuery {
    /// Restrict to STIX object kinds.
    pub type_filter: Option<Vec<StixObjectKind>>,
    /// Restrict to explicit ids.
    pub id_filter: Option<Vec<StixId>>,
    /// Include objects modified after this timestamp.
    pub modified_after: Option<StixTimestamp>,
    /// Include objects whose labels contain any listed value.
    pub labels_include: Option<Vec<String>>,
    /// Case-insensitive substring match against indexed searchable text.
    pub text_search: Option<String>,
    /// Maximum number of results.
    pub max_results: Option<usize>,
    /// Pagination cursor.
    pub cursor: Option<QueryCursor>,
}

impl StixQuery {
    /// Create an empty query (match all objects).
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict results to the given STIX kinds.
    pub fn type_filter(mut self, types: Vec<StixObjectKind>) -> Self {
        self.type_filter = Some(types);
        self
    }

    /// Restrict results to explicit object ids.
    pub fn id_filter(mut self, ids: Vec<StixId>) -> Self {
        self.id_filter = Some(ids);
        self
    }

    /// Include only objects modified after `ts`.
    pub fn modified_after(mut self, ts: StixTimestamp) -> Self {
        self.modified_after = Some(ts);
        self
    }

    /// Include objects whose labels contain any of `labels`.
    pub fn labels_include(mut self, labels: Vec<String>) -> Self {
        self.labels_include = Some(labels);
        self
    }

    /// Include objects whose indexed searchable text contains `text` (case-insensitive).
    pub fn text_search(mut self, text: impl Into<String>) -> Self {
        self.text_search = Some(text.into());
        self
    }

    /// Limit the number of returned objects.
    pub fn max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }

    /// Set the pagination cursor.
    pub fn cursor(mut self, cursor: QueryCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

/// Object-safe STIX store trait.
pub trait StixStore: Send + Sync {
    /// Insert or update an object.
    fn upsert(&self, obj: &StixObject) -> Result<(), StoreError>;

    /// Returns an owned (cloned) object, not a borrowed reference.
    fn get(&self, id: &StixId) -> Result<Option<StixObject>, StoreError>;

    /// All stored versions for `id`.
    fn get_all_versions(&self, id: &StixId) -> Result<Vec<StixObject>, StoreError>;

    /// Run a typed query.
    fn query(&self, q: &StixQuery) -> Result<QueryResult, StoreError>;

    /// Import all objects from `bundle`.
    fn import_bundle(&self, bundle: &Bundle) -> Result<ImportReport, StoreError>;

    /// Remove an object and all of its versions from the store.
    fn delete(&self, id: &StixId) -> Result<bool, StoreError>;

    /// Export the latest version of every stored object into a bundle.
    fn export_bundle(&self, bundle_id: StixId) -> Result<Bundle, StoreError>;
}

#[cfg(test)]
mod query {
    use super::*;
    use crate::core::{SdoKind, StixObjectKind};

    #[test]
    fn builder_compiles() {
        let _query = StixQuery::new().type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)]);
    }
}

#[cfg(test)]
mod import_report {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn counts_added_and_deduplicated() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse");
        let store = MemoryStore::new();
        let first = store.import_bundle(&bundle).expect("import");
        assert_eq!(first.objects_added, 1);
        let second = store.import_bundle(&bundle).expect("reimport");
        assert_eq!(second.objects_deduplicated, 1);
    }
}
