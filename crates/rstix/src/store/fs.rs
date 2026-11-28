//! Filesystem-backed STIX object store.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::core::StixId;
use crate::model::Bundle;
use crate::model::parse_options::ParseOptions;
use crate::model::stix_object::{StixObject, deserialize_stix_object_from_value};

use super::error::StoreError;
use super::memory::MemoryStore;
use super::{ImportReport, QueryResult, StixQuery, StixStore};

const OBJECTS_DIR: &str = "objects";

/// On-disk envelope for a stored object id.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredEnvelope {
    versions: Vec<serde_json::Value>,
}

/// A store file that a load skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedFile {
    /// Path of the file under the store's `objects/` directory.
    pub path: PathBuf,
    /// Why the file could not be loaded.
    pub reason: String,
}

/// Outcome of reading a store directory into memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Object versions loaded.
    pub versions_loaded: usize,
    /// Files left out, in file-name order. The other files still load.
    pub skipped: Vec<SkippedFile>,
}

/// Durable [`StixStore`] backed by JSON files under a directory root.
///
/// Each object id is stored as `objects/<encoded-id>.json` containing all versions.
/// An in-memory index is kept hot for queries; mutations flush to disk synchronously.
/// A write is refused when the stored form would not load back under the
/// store's [`ParseOptions`], and a load skips and reports a file it cannot
/// read instead of failing.
pub struct FsStore {
    root: PathBuf,
    memory: MemoryStore,
    parse_options: ParseOptions,
    last_load: RwLock<LoadReport>,
}

impl FsStore {
    /// Open or create a store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_parse_options(root, ParseOptions::default())
    }

    /// Open or create a store at `root` with explicit [`ParseOptions`] for disk reload.
    ///
    /// Stored values are already decoded, so loading never applies RFC 2047
    /// decoding whatever
    /// [`decode_email_encoded_words`](ParseOptions::decode_email_encoded_words)
    /// says. Files that fail to load are listed in [`FsStore::load_report`].
    pub fn open_with_parse_options(
        root: impl AsRef<Path>,
        parse_options: ParseOptions,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(OBJECTS_DIR)).map_err(|err| StoreError::io(&root, err))?;
        let parse_options = parse_options.decode_email_encoded_words(false);
        let (memory, report) = Self::read_memory_from_disk(&root, &parse_options)?;
        Ok(Self {
            root,
            memory,
            parse_options,
            last_load: RwLock::new(report),
        })
    }

    /// Root directory for persisted objects.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow the in-memory index (read-only queries without disk I/O).
    pub fn memory(&self) -> &MemoryStore {
        &self.memory
    }

    /// What the most recent open or [`reload_from_disk`](Self::reload_from_disk) loaded and skipped.
    pub fn load_report(&self) -> LoadReport {
        self.last_load
            .read()
            .map(|report| report.clone())
            .unwrap_or_default()
    }

    /// Re-read every object envelope from disk into the in-memory index.
    ///
    /// Call after an external writer (for example `rsigma taxii sync`) updates
    /// files under [`FsStore::root`] so existing [`FsStore`] handles observe
    /// the new corpus without reopening the store.
    ///
    /// Builds a fresh index first and then swaps it in. A file that cannot be
    /// read or parsed is skipped and listed in the returned report, and the
    /// other files still load. An error, which leaves the previous corpus
    /// unchanged, means the `objects/` directory itself could not be listed.
    pub fn reload_from_disk(&self) -> Result<LoadReport, StoreError> {
        let (fresh, report) = Self::read_memory_from_disk(&self.root, &self.parse_options)?;
        self.memory.replace_with(fresh)?;
        if let Ok(mut last) = self.last_load.write() {
            *last = report.clone();
        }
        Ok(report)
    }

    fn read_memory_from_disk(
        root: &Path,
        parse_options: &ParseOptions,
    ) -> Result<(MemoryStore, LoadReport), StoreError> {
        let memory = MemoryStore::new();
        let mut report = LoadReport::default();
        let objects_dir = root.join(OBJECTS_DIR);
        if !objects_dir.exists() {
            return Ok((memory, report));
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(&objects_dir).map_err(|err| StoreError::io(&objects_dir, err))? {
            let entry = entry.map_err(|err| StoreError::io(&objects_dir, err))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            match entry.file_type() {
                Ok(file_type) if file_type.is_file() => paths.push(path),
                Ok(_) => {}
                Err(err) => report.skipped.push(SkippedFile {
                    path,
                    reason: err.to_string(),
                }),
            }
        }
        paths.sort();
        for path in paths {
            match read_object_file(&path, parse_options) {
                Ok(objects) => {
                    for object in &objects {
                        memory.upsert(object)?;
                    }
                    report.versions_loaded += objects.len();
                }
                Err(reason) => report.skipped.push(SkippedFile { path, reason }),
            }
        }
        report.skipped.sort_by(|a, b| a.path.cmp(&b.path));
        Ok((memory, report))
    }

    /// Refuse `objects` whose stored form would not load back.
    fn check_reloadable(&self, objects: &[&StixObject]) -> Result<(), StoreError> {
        for object in objects {
            let refused = |reason: String| StoreError::NotReloadable {
                id: object.id().as_str().to_owned(),
                reason,
            };
            let value = serde_json::to_value(object).map_err(|err| refused(err.to_string()))?;
            deserialize_stix_object_from_value(value, &self.parse_options)
                .map_err(|err| refused(err.to_string()))?;
        }
        Ok(())
    }

    fn persist_object(&self, id: &StixId) -> Result<(), StoreError> {
        let path = self.object_path(id)?;
        let stored_versions = self.memory.get_all_versions(id)?;
        if stored_versions.is_empty() {
            if path.exists() {
                fs::remove_file(&path).map_err(|err| StoreError::io(&path, err))?;
            }
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| StoreError::io(parent, err))?;
        }
        let versions: Vec<serde_json::Value> = stored_versions
            .into_iter()
            .map(|object| serde_json::to_value(&object))
            .collect::<Result<_, _>>()
            .map_err(|err| StoreError::Json(err.to_string()))?;
        let payload = serde_json::to_vec_pretty(&StoredEnvelope { versions })
            .map_err(|err| StoreError::Json(err.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut file = File::create(&tmp).map_err(|err| StoreError::io(&tmp, err))?;
            file.write_all(&payload)
                .map_err(|err| StoreError::io(&tmp, err))?;
            file.sync_all().map_err(|err| StoreError::io(&tmp, err))?;
        }
        fs::rename(&tmp, &path).map_err(|err| StoreError::io(&path, err))?;
        Ok(())
    }

    fn object_path(&self, id: &StixId) -> Result<PathBuf, StoreError> {
        Ok(self
            .root
            .join(OBJECTS_DIR)
            .join(format!("{}.json", object_file_stem(id)?)))
    }
}

/// Read every version in one object file, or say why the file cannot load.
fn read_object_file(path: &Path, parse_options: &ParseOptions) -> Result<Vec<StixObject>, String> {
    let contents = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let envelope: StoredEnvelope =
        serde_json::from_str(&contents).map_err(|err| format!("invalid store envelope: {err}"))?;
    let stem = path.file_stem().and_then(|stem| stem.to_str());
    let mut objects = Vec::with_capacity(envelope.versions.len());
    for value in envelope.versions {
        let (object, _extra) = deserialize_stix_object_from_value(value, parse_options)
            .map_err(|err| err.to_string())?;
        let expected = object_file_stem(object.id()).map_err(|err| err.to_string())?;
        if stem != Some(expected.as_str()) {
            return Err(format!(
                "holds `{}`, which belongs in {expected}.json",
                object.id()
            ));
        }
        objects.push(object);
    }
    Ok(objects)
}

impl StixStore for FsStore {
    fn upsert(&self, obj: &StixObject) -> Result<(), StoreError> {
        object_file_stem(obj.id())?;
        self.check_reloadable(&[obj])?;
        self.memory.upsert(obj)?;
        self.persist_object(obj.id())
    }

    fn get(&self, id: &StixId) -> Result<Option<StixObject>, StoreError> {
        self.memory.get(id)
    }

    fn contains(&self, id: &StixId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn get_all_versions(&self, id: &StixId) -> Result<Vec<StixObject>, StoreError> {
        self.memory.get_all_versions(id)
    }

    fn query(&self, q: &StixQuery) -> Result<QueryResult, StoreError> {
        self.memory.query(q)
    }

    fn import_bundle(&self, bundle: &Bundle) -> Result<ImportReport, StoreError> {
        for object in bundle.objects() {
            object_file_stem(object.id())?;
        }
        self.check_reloadable(&bundle.objects().iter().collect::<Vec<_>>())?;
        let report = self.memory.import_bundle(bundle)?;
        for object in bundle.objects() {
            self.persist_object(object.id())?;
        }
        Ok(report)
    }

    fn import_objects(&self, objects: &[StixObject]) -> Result<ImportReport, StoreError> {
        for object in objects {
            object_file_stem(object.id())?;
        }
        self.check_reloadable(&objects.iter().collect::<Vec<_>>())?;
        let report = self.memory.import_objects(objects)?;
        for object in objects {
            self.persist_object(object.id())?;
        }
        Ok(report)
    }

    fn delete(&self, id: &StixId) -> Result<bool, StoreError> {
        object_file_stem(id)?;
        let removed = self.memory.delete(id)?;
        if removed {
            self.persist_object(id)?;
        }
        Ok(removed)
    }

    fn export_bundle(&self, bundle_id: StixId) -> Result<Bundle, StoreError> {
        self.memory.export_bundle(bundle_id)
    }
}

/// Map an id to its file stem under `objects/`.
///
/// [`StixId::generate`] does not validate its type name, so the stem is
/// checked here as well: anything other than ASCII alphanumerics, `-`, and `_`
/// could name a path outside the store root.
fn object_file_stem(id: &StixId) -> Result<String, StoreError> {
    let stem = id.as_str().replace("--", "__");
    if stem
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(stem)
    } else {
        Err(StoreError::InvalidObjectId(id.as_str().to_owned()))
    }
}

#[cfg(test)]
mod open {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn persists_and_reopens_objects() {
        let root = std::env::temp_dir().join(format!("rstix-fs-store-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&root);
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse");
        {
            let store = FsStore::open(&root).expect("open");
            store.import_bundle(&bundle).expect("import");
        }
        let store = FsStore::open(&root).expect("reopen");
        let sco_id = bundle.objects()[0].id().clone();
        assert!(store.get(&sco_id).expect("get").is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reload_from_disk_picks_up_external_writes() {
        let root = std::env::temp_dir().join(format!("rstix-fs-store-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&root);
        let bundle_a = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse");
        let bundle_b = parse_bundle(include_str!(
            "../../tests/fixtures/store/multi-indicators.json"
        ))
        .expect("parse");
        let store = FsStore::open(&root).expect("open");
        store.import_bundle(&bundle_a).expect("import a");
        let sco_id = bundle_a.objects()[0].id().clone();
        assert!(store.get(&sco_id).expect("get").is_some());

        {
            let external = FsStore::open(&root).expect("external open");
            external.import_bundle(&bundle_b).expect("import b");
        }

        store.reload_from_disk().expect("reload");
        assert!(
            store
                .get(&bundle_b.objects()[0].id().clone())
                .expect("get indicator")
                .is_some(),
            "reload must index objects written by another handle"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_ids_that_escape_the_store_root() {
        let base = std::env::temp_dir().join(format!("rstix-fs-store-{}", uuid::Uuid::new_v4()));
        let root = base.join("store");
        let store = FsStore::open(&root).expect("open");
        for type_name in ["../../escape", "/tmp/escape", "..\\escape"] {
            let id = StixId::generate(type_name);
            let object = StixObject::Custom(crate::model::CustomStixObject {
                type_name: type_name.to_owned(),
                id: id.clone(),
                raw: serde_json::json!({"type": type_name, "id": id.as_str()}),
                typed: None,
            });
            let expected = || Err(StoreError::InvalidObjectId(id.as_str().to_owned()));
            assert_eq!(store.upsert(&object), expected());
            assert_eq!(
                store
                    .import_objects(std::slice::from_ref(&object))
                    .map(|_| ()),
                expected()
            );
            assert_eq!(store.delete(&id).map(|_| ()), expected());
            assert!(store.get(&id).expect("get").is_none());
        }
        let entries: Vec<_> = fs::read_dir(&base)
            .expect("read base")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            ["store"],
            "nothing may be written beside the store"
        );
        assert_eq!(fs::read_dir(root.join(OBJECTS_DIR)).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&base);
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("rstix-fs-store-{}", uuid::Uuid::new_v4()))
    }

    fn sco_bundle() -> Bundle {
        parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse")
    }

    fn indicator_bundle() -> Bundle {
        parse_bundle(include_str!(
            "../../tests/fixtures/store/multi-indicators.json"
        ))
        .expect("parse")
    }

    fn custom_object() -> StixObject {
        let json = r#"{"type":"x-acme-widget","spec_version":"2.1","id":"x-acme-widget--1f9e8c11-73b7-4c39-8f55-4ab2e2a7f5a0","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"widget"}"#;
        crate::parse_object_with_extras_and_options(
            json,
            &ParseOptions::default().allow_custom(true),
        )
        .expect("custom object")
        .0
    }

    #[test]
    fn reload_skips_and_reports_a_corrupt_file() {
        let root = temp_root();
        let store = FsStore::open(&root).expect("open");
        store.import_bundle(&sco_bundle()).expect("import sco");
        store
            .import_bundle(&indicator_bundle())
            .expect("import indicators");
        let corrupt = root.join(OBJECTS_DIR).join("corrupt-envelope.json");
        fs::write(&corrupt, "{not json").expect("write corrupt file");

        let report = store.reload_from_disk().expect("reload loads the rest");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].path, corrupt);
        assert!(report.skipped[0].reason.contains("invalid store envelope"));
        assert_eq!(store.load_report(), report);
        for object in sco_bundle()
            .objects()
            .iter()
            .chain(indicator_bundle().objects())
        {
            assert!(store.get(object.id()).unwrap().is_some(), "{}", object.id());
        }

        let reopened = FsStore::open(&root).expect("open with a corrupt file");
        assert_eq!(reopened.load_report().skipped.len(), 1);
        assert_eq!(
            reopened.load_report().versions_loaded,
            1 + indicator_bundle().objects().len()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_skips_files_that_fail_the_parse_options() {
        let root = temp_root();
        let custom = custom_object();
        {
            let store =
                FsStore::open_with_parse_options(&root, ParseOptions::default().allow_custom(true))
                    .expect("open custom");
            store.upsert(&custom).expect("store custom object");
            store.import_bundle(&sco_bundle()).expect("import sco");
        }
        let strict = FsStore::open(&root).expect("open without custom types");
        let report = strict.load_report();
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(report.skipped[0].reason.contains("x-acme-widget"));
        assert!(strict.get(custom.id()).unwrap().is_none());
        assert!(
            strict
                .get(sco_bundle().objects()[0].id())
                .unwrap()
                .is_some()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn refuses_an_object_that_would_not_load_back() {
        let root = temp_root();
        let store = FsStore::open(&root).expect("open");
        let custom = custom_object();
        let refused = |result: Result<(), StoreError>| {
            assert!(
                matches!(&result, Err(StoreError::NotReloadable { id, .. }) if id == custom.id().as_str()),
                "{result:?}"
            );
        };
        refused(store.upsert(&custom));
        refused(
            store
                .import_objects(std::slice::from_ref(&custom))
                .map(|_| ()),
        );
        refused(
            store
                .import_bundle(&Bundle::from_objects(
                    StixId::parse("bundle--3ffc2b14-1f2c-4a47-9b5b-0c7c3d1e2f10").unwrap(),
                    vec![sco_bundle().objects()[0].clone(), custom.clone()],
                ))
                .map(|_| ()),
        );
        assert!(store.get(custom.id()).unwrap().is_none());
        assert!(
            store.get(sco_bundle().objects()[0].id()).unwrap().is_none(),
            "a refused bundle writes nothing"
        );
        assert_eq!(fs::read_dir(root.join(OBJECTS_DIR)).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_skips_a_file_named_for_another_object_and_ignores_temp_files() {
        let root = temp_root();
        {
            let store = FsStore::open(&root).expect("open");
            store.import_bundle(&sco_bundle()).expect("import");
        }
        let objects = root.join(OBJECTS_DIR);
        let stored = fs::read_dir(&objects)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let misplaced = objects.join("ipv4-addr__00000000-0000-4000-8000-000000000000.json");
        fs::copy(&stored, &misplaced).unwrap();
        fs::copy(&stored, objects.join("leftover.json.tmp")).unwrap();

        let store = FsStore::open(&root).expect("open");
        let report = store.load_report();
        assert_eq!(report.versions_loaded, 1);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].path, misplaced);
        assert!(report.skipped[0].reason.contains("belongs in"));
        let _ = fs::remove_dir_all(&root);
    }
}
