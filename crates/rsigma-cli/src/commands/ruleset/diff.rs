//! `rsigma ruleset diff`: compare a resolved ruleset with its lockfile.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process;

use serde::Serialize;
use serde_json::json;

use crate::exit_code::{CONFIG_ERROR, FINDINGS};
use crate::output::{OutputCtx, Tabular, render_report};
use crate::ruleset::build::{ensure_unique, plan_output};
use crate::ruleset::lock::{LOCK_VERSION, LockedDocument};
use crate::ruleset::{load_named, resolve_or_exit};

#[derive(Debug, Serialize)]
struct DiffRow {
    change: String,
    kind: String,
    id: String,
    title: String,
    detail: String,
}

impl Tabular for DiffRow {
    fn headers() -> &'static [&'static str] {
        &["CHANGE", "KIND", "ID", "TITLE", "DETAIL"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.change.clone(),
            self.kind.clone(),
            self.id.clone(),
            self.title.clone(),
            self.detail.clone(),
        ]
    }
}

fn changed_fields(previous: &LockedDocument, current: &LockedDocument) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if previous.title != current.title {
        fields.push("title");
    }
    if previous.decision != current.decision {
        fields.push("decision");
    }
    if previous.overlays != current.overlays {
        fields.push("overlays");
    }
    if previous.origin != current.origin {
        fields.push("origin");
    }
    fields
}

fn document_key(document: &LockedDocument) -> (String, String) {
    (document.kind.clone(), document.file.clone())
}

fn row_for(change: &str, document: &LockedDocument, detail: String) -> DiffRow {
    DiffRow {
        change: change.to_string(),
        kind: document.kind.clone(),
        id: document.id.clone().unwrap_or_else(|| "-".to_string()),
        title: document.title.clone(),
        detail,
    }
}

fn read_lock(path: &Path) -> Result<crate::ruleset::lock::Lockfile, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let lock: crate::ruleset::lock::Lockfile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    if lock.lock_version != LOCK_VERSION {
        return Err(format!(
            "{} has lock_version {}, expected {}",
            path.display(),
            lock.lock_version,
            LOCK_VERSION
        ));
    }
    Ok(lock)
}

pub(crate) fn cmd_diff(args: super::DiffArgs, ctx: OutputCtx) {
    let (name, spec) = load_named(&args.name, args.config.as_deref());

    let lock_path = args.lock.clone().or_else(|| {
        spec.output
            .as_ref()
            .map(|dir| dir.join("ruleset.lock.json"))
    });
    let Some(lock_path) = lock_path else {
        eprintln!(
            "error: ruleset '{name}' has no output directory; pass --lock <PATH> or set output in the ruleset spec"
        );
        process::exit(CONFIG_ERROR);
    };

    let previous = match read_lock(&lock_path) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(CONFIG_ERROR);
        }
    };

    let resolved = resolve_or_exit(&name, &spec, &ctx);
    if let Err(error) = ensure_unique(&resolved) {
        eprintln!("error: ruleset '{name}': {error}");
        process::exit(CONFIG_ERROR);
    }
    let (_, current) = plan_output(&resolved, &spec);

    let mut previous_documents: BTreeMap<(String, String), LockedDocument> = previous
        .documents
        .into_iter()
        .map(|document| (document_key(&document), document))
        .collect();
    let mut current_documents: BTreeMap<(String, String), LockedDocument> = current
        .documents
        .into_iter()
        .map(|document| (document_key(&document), document))
        .collect();

    let mut rows = Vec::new();
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut unchanged = 0usize;

    let keys: Vec<(String, String)> = current_documents
        .keys()
        .chain(previous_documents.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    for key in keys {
        match (
            previous_documents.remove(&key),
            current_documents.remove(&key),
        ) {
            (None, Some(document)) => {
                added += 1;
                rows.push(row_for("added", &document, String::new()));
            }
            (Some(document), None) => {
                removed += 1;
                rows.push(row_for("removed", &document, String::new()));
            }
            (Some(previous), Some(current)) if previous.sha256 != current.sha256 => {
                changed += 1;
                let fields = changed_fields(&previous, &current);
                rows.push(row_for("changed", &current, fields.join(",")));
            }
            (Some(_), Some(_)) => {
                unchanged += 1;
            }
            (None, None) => {}
        }
    }

    let sources_changed = previous.sources != current.sources;
    let overlays_changed = previous.overlay_files != current.overlay_files;
    let spec_changed = previous.spec_sha256 != current.spec_sha256;

    let envelope = json!({
        "ruleset": name,
        "lock": lock_path.display().to_string(),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "sources_changed": sources_changed,
        "overlays_changed": overlays_changed,
        "spec_changed": spec_changed,
        "documents": &rows,
    });
    render_report(&ctx, &envelope, &rows);

    if args.fail_on_change
        && (added > 0
            || removed > 0
            || changed > 0
            || sources_changed
            || overlays_changed
            || spec_changed)
    {
        process::exit(FINDINGS);
    }
}
