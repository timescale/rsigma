//! In-memory STIX object store.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::core::{QueryableStixObject, ScoKind, StixId, StixObjectKind};
use crate::id::generate_sco_id;
use crate::model::ref_paths::collect_ref_paths;
use crate::model::stix_object::StixObject;
use crate::model::{Bundle, ScoObject};

use super::error::StoreError;
use super::search::{object_search_text, query_matches};
use super::{FingerprintConflict, ImportReport, QueryResult, StixQuery, StixStore};

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

    fn query(&self, q: &StixQuery) -> Result<QueryResult, StoreError> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        if let Some(ids) = &q.id_filter {
            for id in ids {
                if let Some(obj) = self.get(id)? {
                    push_unique(&mut results, &mut seen, obj);
                }
            }
        } else if let Some(needle) = &q.text_search {
            let index = self
                .text_index
                .read()
                .map_err(|_| StoreError::LockPoisoned)?;
            let normalized = needle.to_ascii_lowercase();
            for (id_str, blob) in index.iter() {
                if !blob.contains(&normalized) {
                    continue;
                }
                let id: StixId = id_str.parse().map_err(|_| {
                    StoreError::InvalidQuery(format!("invalid indexed id `{id_str}`"))
                })?;
                if let Some(obj) = self.get(&id)? {
                    push_unique(&mut results, &mut seen, obj);
                }
            }
        } else if let Some(types) = &q.type_filter {
            let index = self
                .kind_index
                .read()
                .map_err(|_| StoreError::LockPoisoned)?;
            for kind in types {
                let Some(ids) = index.get(kind) else {
                    continue;
                };
                for id_str in ids {
                    let id: StixId = id_str.parse().map_err(|_| {
                        StoreError::InvalidQuery(format!("invalid indexed id `{id_str}`"))
                    })?;
                    if let Some(obj) = self.get(&id)? {
                        push_unique(&mut results, &mut seen, obj);
                    }
                }
            }
        } else {
            for map in [&self.sdo, &self.sro, &self.meta] {
                let guard = map.read().map_err(|_| StoreError::LockPoisoned)?;
                for versions in guard.values() {
                    if let Some(latest) = versions.last() {
                        push_unique(&mut results, &mut seen, latest.clone());
                    }
                }
            }
            let scos = self.scos.read().map_err(|_| StoreError::LockPoisoned)?;
            for stored in scos.values() {
                push_unique(
                    &mut results,
                    &mut seen,
                    StixObject::Sco(stored.object.clone()),
                );
            }
        }

        results.retain(|obj| {
            let search_text = self
                .text_index
                .read()
                .ok()
                .and_then(|index| index.get(obj.id().as_str()).cloned())
                .unwrap_or_else(|| object_search_text(obj));
            query_matches(q, obj, &search_text)
        });
        results.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
        let total = results.len();
        let start = q.cursor.as_ref().map(|c| c.offset).unwrap_or(0);
        if start > total {
            return Err(StoreError::InvalidQuery(format!(
                "cursor offset {start} exceeds result size {total}"
            )));
        }
        let max = q.max_results.unwrap_or(total.saturating_sub(start));
        let objects: Vec<_> = results.into_iter().skip(start).take(max).collect();
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
        let mut report = ImportReport::default();
        let node_ids: HashSet<String> = bundle
            .objects()
            .iter()
            .map(|object| object.id().as_str().to_owned())
            .collect();

        for object in bundle.objects() {
            let existed = self.get(object.id())?.is_some();
            match upsert_tracked(self, object)? {
                UpsertOutcome::Added => report.objects_added += 1,
                UpsertOutcome::Updated => report.objects_updated += 1,
                UpsertOutcome::Deduplicated => report.objects_deduplicated += 1,
                UpsertOutcome::Unchanged if existed => report.objects_deduplicated += 1,
                UpsertOutcome::Unchanged => report.objects_added += 1,
            }

            let mut paths = Vec::new();
            collect_ref_paths(object, &mut paths);
            for (path, target) in paths {
                if !ref_target_resolved(self, &node_ids, &target)? {
                    report
                        .unresolved_references
                        .push((object.id().clone(), path, target));
                }
            }
        }

        report.fingerprint_conflicts = collect_fingerprint_conflicts(self)?;
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

fn ref_target_resolved(
    store: &MemoryStore,
    bundle_ids: &HashSet<String>,
    target: &StixId,
) -> Result<bool, StoreError> {
    if bundle_ids.contains(target.as_str()) {
        return Ok(true);
    }
    Ok(store.get(target)?.is_some())
}

fn index_kind(store: &MemoryStore, obj: &StixObject) -> Result<(), StoreError> {
    if let Some(kind) = StixObjectKind::from_type_str(obj.type_name()) {
        store
            .kind_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .entry(kind)
            .or_default()
            .insert(obj.id().as_str().to_owned());
    }
    store
        .text_index
        .write()
        .map_err(|_| StoreError::LockPoisoned)?
        .insert(obj.id().as_str().to_owned(), object_search_text(obj));
    Ok(())
}

fn delete_object(store: &MemoryStore, id: &StixId) -> Result<bool, StoreError> {
    let key = id.as_str().to_owned();
    let mut removed = false;

    if store
        .scos
        .write()
        .map_err(|_| StoreError::LockPoisoned)?
        .remove(&key)
        .is_some()
    {
        removed = true;
        store
            .fingerprint_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .retain(|_, asserted| asserted != &key);
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
    if let Some(existing) = scos.get(key) {
        if existing.object == *sco {
            return Ok(UpsertOutcome::Deduplicated);
        }
        scos.insert(
            key.to_owned(),
            StoredSco {
                asserted_id: sco.id().clone(),
                computed_fingerprint_id: compute_sco_fingerprint(sco),
                object: sco.clone(),
            },
        );
        index_kind(store, &StixObject::Sco(sco.clone()))?;
        return Ok(UpsertOutcome::Updated);
    }
    let fingerprint = compute_sco_fingerprint(sco);
    scos.insert(
        key.to_owned(),
        StoredSco {
            asserted_id: sco.id().clone(),
            computed_fingerprint_id: fingerprint.clone(),
            object: sco.clone(),
        },
    );
    if let Some(fingerprint_id) = fingerprint {
        store
            .fingerprint_index
            .write()
            .map_err(|_| StoreError::LockPoisoned)?
            .entry(fingerprint_id.as_str().to_owned())
            .or_insert_with(|| key.to_owned());
    }
    index_kind(store, &StixObject::Sco(sco.clone()))?;
    Ok(UpsertOutcome::Added)
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
        index_kind(store, obj)?;
        return Ok(UpsertOutcome::Added);
    }
    if let Some(last) = entry.last() {
        if last == obj {
            return Ok(UpsertOutcome::Deduplicated);
        }
        entry.push(obj.clone());
        index_kind(store, obj)?;
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

fn collect_fingerprint_conflicts(
    store: &MemoryStore,
) -> Result<Vec<FingerprintConflict>, StoreError> {
    let scos = store.scos.read().map_err(|_| StoreError::LockPoisoned)?;
    let index = store
        .fingerprint_index
        .read()
        .map_err(|_| StoreError::LockPoisoned)?;
    let mut conflicts = Vec::new();
    for stored in scos.values() {
        let Some(fingerprint_id) = &stored.computed_fingerprint_id else {
            continue;
        };
        let Some(first_key) = index.get(fingerprint_id.as_str()) else {
            continue;
        };
        if first_key != stored.asserted_id.as_str() {
            conflicts.push(FingerprintConflict {
                existing_asserted_id: first_key.parse().expect("stored id"),
                new_asserted_id: stored.asserted_id.clone(),
                fingerprint_id: fingerprint_id.clone(),
            });
        }
    }
    conflicts.sort_by(|a, b| a.new_asserted_id.as_str().cmp(b.new_asserted_id.as_str()));
    conflicts.dedup_by(|a, b| {
        a.new_asserted_id.as_str() == b.new_asserted_id.as_str()
            && a.fingerprint_id.as_str() == b.fingerprint_id.as_str()
    });
    Ok(conflicts)
}

fn compute_sco_fingerprint(sco: &ScoObject) -> Option<StixId> {
    let kind = ScoKind::from_type_str(sco.type_name())?;
    let value = serde_json::to_value(sco).ok()?;
    generate_sco_id(kind, &value).ok()
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
