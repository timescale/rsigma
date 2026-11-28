//! In-memory STIX object store.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::core::{QueryableStixObject, ScoKind, StixId, StixObjectKind};
use crate::id::generate_sco_id;
use crate::model::stix_object::StixObject;
use crate::model::{Bundle, ScoObject};

use super::error::StoreError;
use super::search::{StoredRef, object_search_text, query_matches, sco_search_text, text_matches};
use super::{
    FingerprintConflict, ImportReport, QueryResult, StixQuery, StixStore, TextMatch,
    audit_unresolved_refs,
};

#[cfg(test)]
thread_local! {
    /// Objects [`MemoryStore::query`] cloned into result pages on this thread.
    static PAGE_CLONES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Consumer-path SCO storage model.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredSco {
    /// ID from the source — preserved verbatim as the store key.
    pub asserted_id: StixId,
    /// UUIDv5 fingerprint from contributing properties when computable.
    pub computed_fingerprint_id: Option<StixId>,
    /// Stored SCO payload.
    pub object: ScoObject,
}

/// In-memory [`StixStore`] with type indexing and SCO fingerprint reporting.
pub struct MemoryStore {
    sdo: RwLock<HashMap<String, Vec<StixObject>>>,
    sro: RwLock<HashMap<String, Vec<StixObject>>>,
    meta: RwLock<HashMap<String, Vec<StixObject>>>,
    scos: RwLock<HashMap<String, StoredSco>>,
    fingerprint_index: RwLock<HashMap<String, String>>,
    kind_index: RwLock<HashMap<StixObjectKind, HashSet<String>>>,
    text_index: RwLock<HashMap<String, String>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            sdo: RwLock::new(HashMap::new()),
            sro: RwLock::new(HashMap::new()),
            meta: RwLock::new(HashMap::new()),
            scos: RwLock::new(HashMap::new()),
            fingerprint_index: RwLock::new(HashMap::new()),
            kind_index: RwLock::new(HashMap::new()),
            text_index: RwLock::new(HashMap::new()),
        }
    }

    /// Replace every indexed object and search metadata with `other`.
    ///
    /// Used by [`FsStore::reload_from_disk`](super::FsStore::reload_from_disk) after
    /// building a fresh index from disk so a failed reload leaves the previous
    /// corpus intact and queries never observe an empty intermediate state.
    #[cfg(feature = "store-fs")]
    pub(crate) fn replace_with(&self, other: Self) -> Result<(), StoreError> {
        *self.sdo.write().map_err(|_| StoreError::LockPoisoned)? = other
            .sdo
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self.sro.write().map_err(|_| StoreError::LockPoisoned)? = other
            .sro
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self.meta.write().map_err(|_| StoreError::LockPoisoned)? = other
            .meta
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self.scos.write().map_err(|_| StoreError::LockPoisoned)? = other
            .scos
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self
            .fingerprint_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)? = other
            .fingerprint_index
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self
            .kind_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)? = other
            .kind_index
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        *self
            .text_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)? = other
            .text_index
            .into_inner()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(())
    }

    /// Drop every indexed object and search metadata.
    pub fn clear(&self) -> Result<(), StoreError> {
        self.sdo
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.sro
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.meta
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.scos
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.fingerprint_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.kind_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        self.text_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .clear();
        Ok(())
    }

    /// Lookup a stored SCO by asserted id (cloned payload).
    ///
    /// Returns an owned [`StoredSco`] because the store trait surface is object-safe;
    /// callers needing borrowed access should use [`StixStore::get`] for the SCO payload.
    pub fn get_sco(&self, id: &StixId) -> Result<Option<StoredSco>, StoreError> {
        Ok(self
            .scos
            .read()
            .map_err(|_| StoreError::LockPoisoned)?
            .get(id.as_str())
            .cloned())
    }
}

impl StixStore for MemoryStore {
    fn upsert(&self, obj: &StixObject) -> Result<(), StoreError> {
        match obj {
            StixObject::Sco(sco) => {
                upsert_sco(self, sco)?;
            }
            _ => upsert_versioned(self, obj)?,
        }
        Ok(())
    }

    fn get(&self, id: &StixId) -> Result<Option<StixObject>, StoreError> {
        let key = id.as_str();
        if let Some(stored) = self
            .scos
            .read()
            .map_err(|_| StoreError::LockPoisoned)?
            .get(key)
        {
            return Ok(Some(StixObject::Sco(stored.object.clone())));
        }
        for map in [&self.sdo, &self.sro, &self.meta] {
            let guard = map.read().map_err(|_| StoreError::LockPoisoned)?;
            if let Some(versions) = guard.get(key)
                && let Some(latest) = versions.last()
            {
                return Ok(Some(latest.clone()));
            }
        }
        Ok(None)
    }

    fn get_all_versions(&self, id: &StixId) -> Result<Vec<StixObject>, StoreError> {
        let key = id.as_str();
        if let Some(stored) = self
            .scos
            .read()
            .map_err(|_| StoreError::LockPoisoned)?
            .get(key)
        {
            return Ok(vec![StixObject::Sco(stored.object.clone())]);
        }
        for map in [&self.sdo, &self.sro, &self.meta] {
            let guard = map.read().map_err(|_| StoreError::LockPoisoned)?;
            if let Some(versions) = guard.get(key) {
                return Ok(versions.clone());
            }
        }
        Ok(Vec::new())
    }

    fn contains(&self, id: &StixId) -> Result<bool, StoreError> {
        let key = id.as_str();
        if self
            .scos
            .read()
            .map_err(|_| StoreError::LockPoisoned)?
            .contains_key(key)
        {
            return Ok(true);
        }
        for map in [&self.sdo, &self.sro, &self.meta] {
            let guard = map.read().map_err(|_| StoreError::LockPoisoned)?;
            if guard.get(key).is_some_and(|versions| !versions.is_empty()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Filters borrowed objects and their indexed search text, sorts the
    /// matching ids, and clones only the objects of the requested page.
    fn query(&self, q: &StixQuery) -> Result<QueryResult, StoreError> {
        let sdo = self.sdo.read().map_err(|_| StoreError::LockPoisoned)?;
        let sro = self.sro.read().map_err(|_| StoreError::LockPoisoned)?;
        let meta = self.meta.read().map_err(|_| StoreError::LockPoisoned)?;
        let scos = self.scos.read().map_err(|_| StoreError::LockPoisoned)?;
        let kind_index = self
            .kind_index
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        let text_index = self
            .text_index
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        let snapshot = Snapshot {
            sdo: &sdo,
            sro: &sro,
            meta: &meta,
            scos: &scos,
        };
        let needle = q.text_search.as_deref().map(str::to_ascii_lowercase);
        let needle = needle.as_deref();
        let search_text = |key: &str, obj: StoredRef<'_>| -> Cow<'_, str> {
            match text_index.get(key) {
                Some(text) => Cow::Borrowed(text.as_str()),
                None => Cow::Owned(stored_search_text(obj)),
            }
        };

        let mut matched: Vec<&str> = Vec::new();
        let mut seen = HashSet::new();
        // `needle` is `None` for candidates whose text already matched.
        let mut keep = |key, needle: Option<&str>| {
            if let Some(obj) = snapshot.get(key)
                && query_matches(q, needle, obj, || search_text(key, obj))
            {
                matched.push(key);
            }
        };
        if let Some(ids) = &q.id_filter {
            for id in ids {
                if seen.insert(id.as_str()) {
                    keep(id.as_str(), needle);
                }
            }
        } else if let Some(needle) = needle {
            let substring = q.text_match == TextMatch::Substring;
            for (key, text) in text_index.iter() {
                let hit = if substring {
                    text.contains(needle)
                } else {
                    text_matches(text, needle, q.text_match)
                };
                if hit {
                    keep(key.as_str(), None);
                }
            }
        } else if let Some(types) = &q.type_filter {
            for kind in types {
                for key in kind_index.get(kind).into_iter().flatten() {
                    if seen.insert(key.as_str()) {
                        keep(key.as_str(), needle);
                    }
                }
            }
        } else {
            for map in [&*sdo, &*sro, &*meta] {
                for key in map.keys() {
                    keep(key.as_str(), needle);
                }
            }
            for key in scos.keys() {
                keep(key.as_str(), needle);
            }
        }

        matched.sort_unstable();
        matched.dedup();
        let total = matched.len();
        let start = q.cursor.as_ref().map(|c| c.offset).unwrap_or(0);
        if start > total {
            return Err(StoreError::InvalidQuery(format!(
                "cursor offset {start} exceeds result size {total}"
            )));
        }
        let max = q.max_results.unwrap_or(total - start);
        let objects: Vec<StixObject> = matched[start..]
            .iter()
            .take(max)
            .filter_map(|key| snapshot.get(key))
            .map(|obj| {
                #[cfg(test)]
                PAGE_CLONES.with(|count| count.set(count.get() + 1));
                obj.to_object()
            })
            .collect();
        let next_offset = start + objects.len();
        let next_cursor = if next_offset < total {
            Some(crate::store::QueryCursor {
                offset: next_offset,
            })
        } else {
            None
        };
        Ok(QueryResult {
            objects,
            next_cursor,
        })
    }

    fn import_bundle(&self, bundle: &Bundle) -> Result<ImportReport, StoreError> {
        let source_ids: Vec<StixId> = bundle
            .objects()
            .iter()
            .map(|object| object.id().clone())
            .collect();
        let mut report = self.import_objects(bundle.objects())?;
        report.unresolved_references = audit_unresolved_refs(self, &source_ids)?;
        Ok(report)
    }

    /// Fingerprint conflicts in the report are those of the SCOs in `objects`.
    fn import_objects(&self, objects: &[StixObject]) -> Result<ImportReport, StoreError> {
        let mut report = ImportReport::default();
        let mut imported_scos = Vec::new();
        for object in objects {
            let existed = self.contains(object.id())?;
            match upsert_tracked(self, object)? {
                UpsertOutcome::Added => report.objects_added += 1,
                UpsertOutcome::Updated => report.objects_updated += 1,
                UpsertOutcome::Deduplicated => report.objects_deduplicated += 1,
                UpsertOutcome::Unchanged if existed => report.objects_deduplicated += 1,
                UpsertOutcome::Unchanged => report.objects_added += 1,
            }
            if let StixObject::Sco(sco) = object {
                imported_scos.push(sco.id().as_str());
            }
        }
        report.fingerprint_conflicts = collect_fingerprint_conflicts(self, &imported_scos)?;
        Ok(report)
    }

    fn delete(&self, id: &StixId) -> Result<bool, StoreError> {
        delete_object(self, id)
    }

    fn export_bundle(&self, bundle_id: StixId) -> Result<Bundle, StoreError> {
        export_all_objects(self, bundle_id)
    }
}

enum UpsertOutcome {
    Added,
    Updated,
    Deduplicated,
    Unchanged,
}

fn index_kind(
    store: &MemoryStore,
    type_name: &str,
    key: &str,
    search_text: String,
) -> Result<(), StoreError> {
    if let Some(kind) = StixObjectKind::from_type_str(type_name) {
        store
            .kind_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .entry(kind)
            .or_default()
            .insert(key.to_owned());
    }
    store
        .text_index
        .write()
        .map_err(|_| StoreError::LockPoisoned)?
        .insert(key.to_owned(), search_text);
    Ok(())
}

fn index_object(store: &MemoryStore, obj: &StixObject) -> Result<(), StoreError> {
    index_kind(
        store,
        obj.type_name(),
        obj.id().as_str(),
        object_search_text(obj),
    )
}

/// Borrowed views of the store maps, read under their locks.
struct Snapshot<'g> {
    sdo: &'g HashMap<String, Vec<StixObject>>,
    sro: &'g HashMap<String, Vec<StixObject>>,
    meta: &'g HashMap<String, Vec<StixObject>>,
    scos: &'g HashMap<String, StoredSco>,
}

impl<'g> Snapshot<'g> {
    /// Latest stored version of `key`, looked up in the order [`StixStore::get`] uses.
    fn get(&self, key: &str) -> Option<StoredRef<'g>> {
        if let Some(stored) = self.scos.get(key) {
            return Some(StoredRef::Sco(&stored.object));
        }
        [self.sdo, self.sro, self.meta]
            .into_iter()
            .find_map(|map| map.get(key).and_then(|versions| versions.last()))
            .map(StoredRef::Object)
    }
}

fn stored_search_text(obj: StoredRef<'_>) -> String {
    match obj {
        StoredRef::Object(obj) => object_search_text(obj),
        StoredRef::Sco(sco) => sco_search_text(sco, serde_json::to_value(sco).ok().as_ref()),
    }
}

fn delete_object(store: &MemoryStore, id: &StixId) -> Result<bool, StoreError> {
    let key = id.as_str().to_owned();
    let mut removed = false;

    let removed_sco = store
        .scos
        .write()
        .map_err(|_| StoreError::LockPoisoned)?
        .remove(&key);
    if let Some(stored) = removed_sco {
        removed = true;
        if let Some(fingerprint) = &stored.computed_fingerprint_id {
            let mut index = store
                .fingerprint_index
                .write()
                .map_err(|_| StoreError::LockPoisoned)?;
            if index.get(fingerprint.as_str()) == Some(&key) {
                index.remove(fingerprint.as_str());
            }
        }
    }

    for map in [&store.sdo, &store.sro, &store.meta] {
        if map
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .remove(&key)
            .is_some()
        {
            removed = true;
        }
    }

    if removed {
        store
            .kind_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .values_mut()
            .for_each(|ids| {
                ids.remove(&key);
            });
        store
            .text_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .remove(&key);
    }

    Ok(removed)
}

fn export_all_objects(store: &MemoryStore, bundle_id: StixId) -> Result<Bundle, StoreError> {
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for map in [&store.sdo, &store.sro, &store.meta] {
        let guard = map.read().map_err(|_| StoreError::LockPoisoned)?;
        for versions in guard.values() {
            if let Some(latest) = versions.last() {
                push_unique(&mut objects, &mut seen, latest.clone());
            }
        }
    }
    let scos = store.scos.read().map_err(|_| StoreError::LockPoisoned)?;
    for stored in scos.values() {
        push_unique(
            &mut objects,
            &mut seen,
            StixObject::Sco(stored.object.clone()),
        );
    }
    objects.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    Ok(Bundle::from_objects(bundle_id, objects))
}

fn upsert_tracked(store: &MemoryStore, obj: &StixObject) -> Result<UpsertOutcome, StoreError> {
    match obj {
        StixObject::Sco(sco) => upsert_sco_tracked(store, sco),
        _ => upsert_versioned_tracked(store, obj),
    }
}

fn upsert_sco_tracked(store: &MemoryStore, sco: &ScoObject) -> Result<UpsertOutcome, StoreError> {
    let key = sco.id().as_str();
    let mut scos = store.scos.write().map_err(|_| StoreError::LockPoisoned)?;
    let previous_fingerprint = match scos.get(key) {
        Some(existing) if existing.object == *sco => return Ok(UpsertOutcome::Deduplicated),
        Some(existing) => Some(existing.computed_fingerprint_id.clone()),
        None => None,
    };
    let wire = serde_json::to_value(sco).ok();
    let fingerprint = wire.as_ref().and_then(|value| sco_fingerprint(sco, value));
    scos.insert(
        key.to_owned(),
        StoredSco {
            asserted_id: sco.id().clone(),
            computed_fingerprint_id: fingerprint.clone(),
            object: sco.clone(),
        },
    );
    {
        let mut index = store
            .fingerprint_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?;
        if let Some(Some(old)) = &previous_fingerprint
            && fingerprint.as_ref() != Some(old)
            && index.get(old.as_str()).map(String::as_str) == Some(key)
        {
            index.remove(old.as_str());
        }
        if let Some(fingerprint_id) = &fingerprint {
            index
                .entry(fingerprint_id.as_str().to_owned())
                .or_insert_with(|| key.to_owned());
        }
    }
    index_kind(
        store,
        QueryableStixObject::type_name(sco),
        key,
        sco_search_text(sco, wire.as_ref()),
    )?;
    Ok(if previous_fingerprint.is_some() {
        UpsertOutcome::Updated
    } else {
        UpsertOutcome::Added
    })
}

fn upsert_sco(store: &MemoryStore, sco: &ScoObject) -> Result<(), StoreError> {
    upsert_sco_tracked(store, sco).map(|_| ())
}

fn upsert_versioned_tracked(
    store: &MemoryStore,
    obj: &StixObject,
) -> Result<UpsertOutcome, StoreError> {
    let map = versioned_map(store, obj);
    let mut guard = map.write().map_err(|_| StoreError::LockPoisoned)?;
    let key = obj.id().as_str().to_owned();
    let entry = guard.entry(key).or_default();
    if entry.is_empty() {
        entry.push(obj.clone());
        index_object(store, obj)?;
        return Ok(UpsertOutcome::Added);
    }
    if let Some(last) = entry.last() {
        if last == obj {
            return Ok(UpsertOutcome::Deduplicated);
        }
        entry.push(obj.clone());
        index_object(store, obj)?;
        return Ok(UpsertOutcome::Updated);
    }
    Ok(UpsertOutcome::Unchanged)
}

fn upsert_versioned(store: &MemoryStore, obj: &StixObject) -> Result<(), StoreError> {
    upsert_versioned_tracked(store, obj).map(|_| ())
}

fn versioned_map<'a>(
    store: &'a MemoryStore,
    obj: &'a StixObject,
) -> &'a RwLock<HashMap<String, Vec<StixObject>>> {
    match obj {
        StixObject::Sdo(_) => &store.sdo,
        StixObject::Sro(_) => &store.sro,
        StixObject::Meta(_) | StixObject::Custom(_) => &store.meta,
        StixObject::Sco(_) => unreachable!(),
    }
}

/// Conflicts of the SCOs stored under `keys`: each one whose fingerprint was
/// first seen on another stored SCO.
fn collect_fingerprint_conflicts(
    store: &MemoryStore,
    keys: &[&str],
) -> Result<Vec<FingerprintConflict>, StoreError> {
    let scos = store.scos.read().map_err(|_| StoreError::LockPoisoned)?;
    let index = store
        .fingerprint_index
        .read()
        .map_err(|_| StoreError::LockPoisoned)?;
    let mut conflicts = Vec::new();
    for key in keys {
        let Some(stored) = scos.get(*key) else {
            continue;
        };
        let Some(fingerprint_id) = &stored.computed_fingerprint_id else {
            continue;
        };
        let Some(first) = index
            .get(fingerprint_id.as_str())
            .filter(|first| first.as_str() != *key)
            .and_then(|first| scos.get(first))
        else {
            continue;
        };
        conflicts.push(FingerprintConflict {
            existing_asserted_id: first.asserted_id.clone(),
            new_asserted_id: stored.asserted_id.clone(),
            fingerprint_id: fingerprint_id.clone(),
        });
    }
    conflicts.sort_by(|a, b| a.new_asserted_id.as_str().cmp(b.new_asserted_id.as_str()));
    conflicts.dedup_by(|a, b| {
        a.new_asserted_id.as_str() == b.new_asserted_id.as_str()
            && a.fingerprint_id.as_str() == b.fingerprint_id.as_str()
    });
    Ok(conflicts)
}

fn sco_fingerprint(sco: &ScoObject, wire: &serde_json::Value) -> Option<StixId> {
    let kind = ScoKind::from_type_str(QueryableStixObject::type_name(sco))?;
    generate_sco_id(kind, wire).ok()
}

fn push_unique(results: &mut Vec<StixObject>, seen: &mut HashSet<String>, obj: StixObject) {
    if seen.insert(obj.id().as_str().to_owned()) {
        results.push(obj);
    }
}

#[cfg(test)]
mod dedup {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn identical_sco_upserts_once() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse");
        let store = MemoryStore::new();
        store.import_bundle(&bundle).expect("import");
        let report = store.import_bundle(&bundle).expect("reimport");
        assert_eq!(report.objects_deduplicated, 1);
    }
}

#[cfg(test)]
mod fingerprint {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn cross_producer_conflict_reported() {
        let a =
            parse_bundle(include_str!("../../tests/fixtures/store/sco-ipv4-a.json")).expect("a");
        let b =
            parse_bundle(include_str!("../../tests/fixtures/store/sco-ipv4-b.json")).expect("b");
        let store = MemoryStore::new();
        store.import_bundle(&a).expect("import a");
        let report = store.import_bundle(&b).expect("import b");
        assert_eq!(report.objects_added, 1);
        assert!(!report.fingerprint_conflicts.is_empty());
    }
}

#[cfg(test)]
mod pagination {
    use super::*;
    use crate::core::{SdoKind, StixObjectKind};
    use crate::parse_bundle;

    #[test]
    fn next_cursor_pages_sorted_results() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/multi-indicators.json"
        ))
        .expect("parse");
        let store = MemoryStore::new();
        store.import_bundle(&bundle).expect("import");

        let first = store
            .query(
                &StixQuery::new()
                    .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                    .max_results(2),
            )
            .expect("page 1");
        assert_eq!(first.objects.len(), 2);
        assert!(first.next_cursor.is_some());

        let second = store
            .query(
                &StixQuery::new()
                    .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                    .max_results(2)
                    .cursor(first.next_cursor.unwrap()),
            )
            .expect("page 2");
        assert_eq!(second.objects.len(), 1);
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn invalid_cursor_offset_rejected() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/multi-indicators.json"
        ))
        .expect("parse");
        let store = MemoryStore::new();
        store.import_bundle(&bundle).expect("import");

        let err = store
            .query(
                &StixQuery::new()
                    .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                    .cursor(crate::store::QueryCursor { offset: 99 }),
            )
            .expect_err("invalid cursor");
        assert_eq!(
            err,
            StoreError::InvalidQuery("cursor offset 99 exceeds result size 3".into())
        );
    }
}

#[cfg(test)]
mod sco_update {
    use super::*;
    use crate::model::ScoObject;
    use crate::parse_bundle;

    #[test]
    fn changed_sco_content_updates_store() {
        let initial = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("initial");
        let updated = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-updated.json"
        ))
        .expect("updated");
        let store = MemoryStore::new();
        store.import_bundle(&initial).expect("import initial");
        let report = store.import_bundle(&updated).expect("import updated");
        assert_eq!(report.objects_updated, 1);

        let sco_id = initial.objects()[0].id().clone();
        let stored = store.get_sco(&sco_id).expect("lookup").expect("sco");
        let ScoObject::Ipv4Addr(addr) = stored.object else {
            panic!("expected ipv4-addr");
        };
        assert_eq!(addr.value, "10.0.0.1");
    }
}

#[cfg(test)]
mod query_paging {
    use super::*;
    use crate::core::{SdoKind, StixTimestamp};
    use crate::store::{QueryCursor, TextMatch};

    fn indicator(n: usize) -> StixObject {
        crate::parse_object(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-{:02}T00:00:00.000Z","name":"Indicator {n}","labels":["l{}"],"pattern":"[ipv4-addr:value = '10.0.{}.{}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00.000Z"}}"#,
            n % 28 + 1,
            n % 3,
            n / 256,
            n % 256
        ))
        .expect("indicator")
    }

    fn ipv4(n: usize) -> StixObject {
        crate::parse_object(&format!(
            r#"{{"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--00000000-0000-4000-8000-{n:012x}","value":"10.0.{}.{}"}}"#,
            n / 256,
            n % 256
        ))
        .expect("ipv4")
    }

    fn store(count: usize) -> (MemoryStore, Vec<StixObject>) {
        let objects: Vec<StixObject> = (0..count).flat_map(|n| [indicator(n), ipv4(n)]).collect();
        let store = MemoryStore::new();
        store.import_objects(&objects).expect("import");
        (store, objects)
    }

    /// Every query result, computed by filtering, sorting, and paging every object.
    fn reference(objects: &[StixObject], q: &StixQuery) -> (Vec<String>, Option<usize>) {
        let needle = q.text_search.as_deref().map(str::to_ascii_lowercase);
        let mut ids: Vec<String> = objects
            .iter()
            .filter(|obj| {
                q.id_filter
                    .as_ref()
                    .is_none_or(|ids| ids.iter().any(|id| id == obj.id()))
            })
            .filter(|obj| {
                let view = match obj {
                    StixObject::Sco(sco) => StoredRef::Sco(sco),
                    other => StoredRef::Object(other),
                };
                query_matches(q, needle.as_deref(), view, || {
                    Cow::Owned(object_search_text(obj))
                })
            })
            .map(|obj| obj.id().as_str().to_owned())
            .collect();
        ids.sort();
        ids.dedup();
        let start = q.cursor.as_ref().map_or(0, |c| c.offset);
        let page: Vec<String> = ids
            .iter()
            .skip(start)
            .take(q.max_results.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        let next = (start + page.len() < ids.len()).then_some(start + page.len());
        (page, next)
    }

    #[test]
    fn match_all_text_search_clones_only_the_page() {
        let (store, _) = store(500);
        for (max, cursor) in [(1, 0), (3, 997)] {
            PAGE_CLONES.with(|count| count.set(0));
            let page = store
                .query(
                    &StixQuery::new()
                        .text_search("--00000000")
                        .max_results(max)
                        .cursor(QueryCursor { offset: cursor }),
                )
                .expect("query");
            let expected = max.min(1_000 - cursor);
            assert_eq!(page.objects.len(), expected);
            assert_eq!(PAGE_CLONES.with(std::cell::Cell::get), expected);
        }
    }

    #[test]
    fn query_matches_the_reference_for_every_filter() {
        let (store, objects) = store(120);
        let since = StixTimestamp::parse("2024-01-20T00:00:00.000Z").expect("ts");
        let queries = [
            StixQuery::new(),
            StixQuery::new().max_results(7),
            StixQuery::new()
                .max_results(7)
                .cursor(QueryCursor { offset: 230 }),
            StixQuery::new().text_search("10.0.0.1"),
            StixQuery::new()
                .text_search("10.0.0.1")
                .text_match(TextMatch::Token),
            StixQuery::new()
                .text_search("10.0.0.1")
                .text_match(TextMatch::Exact),
            StixQuery::new()
                .text_search("INDICATOR 1")
                .text_match(TextMatch::Exact),
            StixQuery::new()
                .text_search("indicator")
                .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                .max_results(5),
            StixQuery::new()
                .type_filter(vec![
                    StixObjectKind::Sdo(SdoKind::Indicator),
                    StixObjectKind::Sdo(SdoKind::Indicator),
                ])
                .modified_after(since.clone()),
            StixQuery::new()
                .labels_include(vec!["l1".into()])
                .text_search("10.0"),
            StixQuery::new().id_filter(vec![
                objects[5].id().clone(),
                objects[5].id().clone(),
                objects[2].id().clone(),
            ]),
            StixQuery::new()
                .id_filter(vec![objects[4].id().clone(), objects[7].id().clone()])
                .text_search("10.0.2"),
        ];
        for q in &queries {
            let page = store.query(q).expect("query");
            let ids: Vec<String> = page
                .objects
                .iter()
                .map(|obj| obj.id().as_str().to_owned())
                .collect();
            let (expected, next) = reference(&objects, q);
            assert_eq!(ids, expected, "{q:?}");
            assert_eq!(page.next_cursor.map(|c| c.offset), next, "{q:?}");
        }
    }

    #[test]
    fn contains_does_not_need_a_clone() {
        let (store, objects) = store(3);
        for object in &objects {
            assert!(store.contains(object.id()).expect("contains"));
        }
        let missing = StixId::parse("ipv4-addr--00000000-0000-4000-8000-0000000fffff").expect("id");
        assert!(!store.contains(&missing).expect("contains"));
    }
}

#[cfg(test)]
mod fingerprint_reports {
    use super::*;
    use crate::parse_bundle;

    fn sco(id: &str, value: &str) -> StixObject {
        crate::parse_object(&format!(
            r#"{{"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--{id}","value":"{value}"}}"#
        ))
        .expect("ipv4")
    }

    #[test]
    fn each_import_reports_only_its_own_conflicts() {
        let a =
            parse_bundle(include_str!("../../tests/fixtures/store/sco-ipv4-a.json")).expect("a");
        let b =
            parse_bundle(include_str!("../../tests/fixtures/store/sco-ipv4-b.json")).expect("b");
        let store = MemoryStore::new();
        store.import_bundle(&a).expect("import a");
        assert_eq!(
            store
                .import_bundle(&b)
                .expect("b")
                .fingerprint_conflicts
                .len(),
            1
        );
        let unrelated = [sco("22222222-2222-4222-8222-222222222222", "10.9.9.9")];
        assert!(
            store
                .import_objects(&unrelated)
                .expect("unrelated")
                .fingerprint_conflicts
                .is_empty()
        );
        assert!(
            store
                .import_bundle(&a)
                .expect("reimport a")
                .fingerprint_conflicts
                .is_empty()
        );
    }

    #[test]
    fn delete_and_update_keep_the_fingerprint_index_current() {
        let store = MemoryStore::new();
        let first = sco("33333333-3333-4333-8333-333333333333", "10.1.1.1");
        let second = sco("44444444-4444-4444-8444-444444444444", "10.1.1.1");
        store
            .import_objects(std::slice::from_ref(&first))
            .expect("first");
        store.delete(first.id()).expect("delete");
        assert!(
            store
                .import_objects(std::slice::from_ref(&second))
                .expect("second")
                .fingerprint_conflicts
                .is_empty(),
            "a deleted SCO does not conflict"
        );

        let moved = sco("44444444-4444-4444-8444-444444444444", "10.2.2.2");
        store.import_objects(&[moved]).expect("update");
        let third = sco("55555555-5555-4555-8555-555555555555", "10.2.2.2");
        let report = store.import_objects(&[third]).expect("third");
        assert_eq!(report.fingerprint_conflicts.len(), 1);
        assert_eq!(
            report.fingerprint_conflicts[0]
                .existing_asserted_id
                .as_str(),
            "ipv4-addr--44444444-4444-4444-8444-444444444444"
        );
        let fourth = sco("66666666-6666-4666-8666-666666666666", "10.1.1.1");
        assert!(
            store
                .import_objects(&[fourth])
                .expect("fourth")
                .fingerprint_conflicts
                .is_empty(),
            "the updated SCO no longer holds its old fingerprint"
        );
    }
}
