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
}

impl FsStore {
    /// Open or create a store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(OBJECTS_DIR)).map_err(|err| StoreError::io(&root, err))?;
        let memory = MemoryStore::new();
        let mut store = Self { root, memory };
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

    fn load_from_disk(&mut self) -> Result<(), StoreError> {
        let objects_dir = self.root.join(OBJECTS_DIR);
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
            let opts = ParseOptions::default();
            for value in envelope.versions {
                let (object, _extra) = deserialize_stix_object_from_value(value, &opts)
                    .map_err(|err| StoreError::Json(err.to_string()))?;
                self.memory.upsert(&object)?;
            }
        }
        Ok(())
    }

    fn persist_object(&self, id: &StixId) -> Result<(), StoreError> {
        let path = self.object_path(id);
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

    fn object_path(&self, id: &StixId) -> PathBuf {
        self.root
            .join(OBJECTS_DIR)
            .join(format!("{}.json", encode_id(id)))
    }
}

impl StixStore for FsStore {
    fn upsert(&self, obj: &StixObject) -> Result<(), StoreError> {
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
        let report = self.memory.import_bundle(bundle)?;
        for object in bundle.objects() {
            self.persist_object(object.id())?;
        }
        Ok(report)
    }

    fn delete(&self, id: &StixId) -> Result<bool, StoreError> {
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

fn encode_id(id: &StixId) -> String {
    id.as_str().replace("--", "__")
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
}
