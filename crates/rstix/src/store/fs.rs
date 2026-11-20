//! Filesystem-backed STIX object store.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

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

/// Durable [`StixStore`] backed by JSON files under a directory root.
///
/// Each object id is stored as `objects/<encoded-id>.json` containing all versions.
/// An in-memory index is kept hot for queries; mutations flush to disk synchronously.
pub struct FsStore {
    root: PathBuf,
    memory: MemoryStore,
    parse_options: ParseOptions,
}

impl FsStore {
    /// Open or create a store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_parse_options(root, ParseOptions::default())
    }

    /// Open or create a store at `root` with explicit [`ParseOptions`] for disk reload.
    pub fn open_with_parse_options(
        root: impl AsRef<Path>,
        parse_options: ParseOptions,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(OBJECTS_DIR)).map_err(|err| StoreError::io(&root, err))?;
        let memory = MemoryStore::new();
        let mut store = Self {
            root,
            memory,
            parse_options,
        };
        store.load_from_disk()?;
        Ok(store)
    }

    /// Root directory for persisted objects.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow the in-memory index (read-only queries without disk I/O).
    pub fn memory(&self) -> &MemoryStore {
        &self.memory
    }

    /// Re-read every object envelope from disk into the in-memory index.
    ///
    /// Call after an external writer (for example `rsigma taxii sync`) updates
    /// files under [`FsStore::root`] so existing [`FsStore`] handles observe
    /// the new corpus without reopening the store.
    ///
    /// Builds a fresh index first; the live index is swapped only on full
    /// success. Parse or I/O errors leave the previous corpus unchanged.
    pub fn reload_from_disk(&self) -> Result<(), StoreError> {
        let fresh = Self::read_memory_from_disk(&self.root, &self.parse_options)?;
        self.memory.replace_with(fresh)
    }

    fn load_from_disk(&mut self) -> Result<(), StoreError> {
        let fresh = Self::read_memory_from_disk(&self.root, &self.parse_options)?;
        self.memory.replace_with(fresh)
    }

    fn read_memory_from_disk(
        root: &Path,
        parse_options: &ParseOptions,
    ) -> Result<MemoryStore, StoreError> {
        let memory = MemoryStore::new();
        let objects_dir = root.join(OBJECTS_DIR);
        if !objects_dir.exists() {
            return Ok(memory);
        }
        for entry in fs::read_dir(&objects_dir).map_err(|err| StoreError::io(&objects_dir, err))? {
            let entry = entry.map_err(|err| StoreError::io(&objects_dir, err))?;
            if !entry
                .file_type()
                .map_err(|err| StoreError::io(entry.path(), err))?
                .is_file()
            {
                continue;
            }
            let contents = fs::read_to_string(entry.path())
                .map_err(|err| StoreError::io(entry.path(), err))?;
            let envelope: StoredEnvelope =
                serde_json::from_str(&contents).map_err(|err| StoreError::Json(err.to_string()))?;
            for value in envelope.versions {
                let (object, _extra) = deserialize_stix_object_from_value(value, parse_options)
                    .map_err(|err| StoreError::Json(err.to_string()))?;
                memory.upsert(&object)?;
            }
        }
        Ok(memory)
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

impl StixStore for FsStore {
    fn upsert(&self, obj: &StixObject) -> Result<(), StoreError> {
        object_file_stem(obj.id())?;
        self.memory.upsert(obj)?;
        self.persist_object(obj.id())
    }

    fn get(&self, id: &StixId) -> Result<Option<StixObject>, StoreError> {
        self.memory.get(id)
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

    #[test]
    fn reload_from_disk_keeps_previous_index_on_parse_error() {
        let root = std::env::temp_dir().join(format!("rstix-fs-store-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&root);
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/store/sco-ipv4-minimal.json"
        ))
        .expect("parse");
        let store = FsStore::open(&root).expect("open");
        store.import_bundle(&bundle).expect("import");
        let sco_id = bundle.objects()[0].id().clone();
        assert!(store.get(&sco_id).expect("get").is_some());

        fs::write(
            root.join(OBJECTS_DIR).join("corrupt-envelope.json"),
            "{not json",
        )
        .expect("write corrupt file");

        let err = store.reload_from_disk().expect_err("reload must fail");
        assert!(
            matches!(err, StoreError::Json(_)),
            "expected json parse error, got {err:?}"
        );
        assert!(
            store
                .get(&sco_id)
                .expect("get after failed reload")
                .is_some(),
            "failed reload must leave the previous corpus intact"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
