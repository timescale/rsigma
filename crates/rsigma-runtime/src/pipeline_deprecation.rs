//! Deprecation warnings for pipeline-embedded configuration that is being
//! removed in a future release.
//!
//! Today the only such surface is the pipeline-level `sources:` block, which
//! v0.13.0 ([PR #135](https://github.com/timescale/rsigma/pull/135)) replaced
//! with the daemon-level `--source <file_or_dir>` flag. The parser still
//! accepts the inline form, but every CLI entry point that loads a pipeline
//! and every daemon hot-reload now surface the deprecation to the operator
//! before the parser swallows it.
//!
//! The helper lives in `rsigma-runtime` (rather than `rsigma-cli` where it
//! started) so the one-shot CLI startup path (`load_pipelines`) and the
//! long-running daemon hot-reload path (`RuntimeEngine::reload_rules` ->
//! `reload_pipelines`) can share one helper, one warning string, and one
//! process-wide dedup set. Library consumers that drive `RuntimeEngine`
//! directly inherit the same warning behaviour without needing to wire
//! anything up.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Deduplication set for the pipeline-embedded `sources:` deprecation warning.
///
/// The set is process-wide and shared between every caller of
/// [`warn_pipeline_inline_sources`] (the CLI's `load_pipelines` at startup,
/// the daemon's [`RuntimeEngine::load_rules`] on every hot-reload, the
/// `pipeline resolve` command, and any library embedder that drives
/// `RuntimeEngine` themselves). Paths are canonicalised before insertion so
/// equivalent spellings (`./pipeline.yml` vs `pipeline.yml`) collapse to one
/// entry; canonicalisation failures fall back to the raw path so we still
/// get one-per-spelling dedup.
///
/// One-shot commands (`eval`, `validate`, `fields`, `convert`, `resolve`)
/// only call into the helper once per pipeline path, so the dedup set is
/// effectively a noop for them. The daemon's hot-reload path is where it
/// earns its keep: SIGHUP, file-watcher events, and `POST /api/v1/reload`
/// all funnel through `reload_pipelines`, which would otherwise re-emit the
/// warning on every reload tick.
///
/// [`RuntimeEngine::load_rules`]: crate::RuntimeEngine::load_rules
static SEEN_INLINE_SOURCES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Process-wide serialization lock for tests that touch [`SEEN_INLINE_SOURCES`].
///
/// Both this module's unit tests and the runtime engine tests in `engine.rs`
/// (which warn through `load_rules`) mutate the shared dedup set, so they must
/// hold one lock. cargo runs a binary's tests in parallel threads, so two
/// separate locks would let an engine test and a deprecation test race on the
/// global set. `lock().unwrap_or_else(into_inner)` recovers a poisoned guard so
/// one failing test does not cascade into the others.
#[cfg(test)]
pub(crate) static DEDUP_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Surface the pipeline-embedded `sources:` deprecation notice for one
/// pipeline file. Idempotent per canonical path (dedup state lives in
/// a process-wide `OnceLock<Mutex<HashSet<PathBuf>>>` private to this
/// module).
///
/// The warning is emitted via both `tracing::warn!` (for structured log
/// aggregation, with `pipeline` and `path` fields) and `eprintln!` (for
/// direct operator visibility on stderr when the tracing subscriber is
/// quiet, e.g. one-shot CLI invocations without `RUST_LOG=info`).
///
/// Phases of the deprecation cycle this helper backs:
/// - Phase 1 ([#135](https://github.com/timescale/rsigma/pull/135)):
///   `tracing::warn!` only, emitted from the CLI's startup path. Shipped in
///   v0.13.0.
/// - Phase 3 ([#136](https://github.com/timescale/rsigma/issues/136)):
///   `tracing::warn!` + `eprintln!`, emitted from both the CLI startup path
///   and the daemon hot-reload path. This helper.
/// - Phase 4 ([#137](https://github.com/timescale/rsigma/issues/137)):
///   hard parse error at v1.0; this helper is removed.
pub fn warn_pipeline_inline_sources(path: &Path, pipeline_name: &str) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let seen = SEEN_INLINE_SOURCES.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = seen.lock().expect("inline-sources warn mutex poisoned");
    if !guard.insert(canonical) {
        return;
    }
    drop(guard);

    tracing::warn!(
        pipeline = %pipeline_name,
        path = %path.display(),
        "pipeline declares inline 'sources:' block, which is deprecated; \
         use '--source <file>' instead. Run 'rsigma rule migrate-sources' \
         to extract sources into a standalone file. Pipeline-embedded \
         sources will be removed in v1.0."
    );
    eprintln!(
        "warning: pipeline '{}' ({}) declares an inline 'sources:' block, \
         which is deprecated and will be removed in v1.0. Migrate with \
         `rsigma rule migrate-sources -p {} -o sources.yml` and load via \
         `--source sources.yml` on `rsigma engine daemon`.",
        pipeline_name,
        path.display(),
        path.display(),
    );
}

/// Clear the dedup set so the next [`warn_pipeline_inline_sources`] call for
/// a previously-seen path re-emits the warning. Intended for tests that
/// exercise multiple separate "process lifetimes" inside one test binary.
#[doc(hidden)]
pub fn reset_inline_sources_dedup_for_tests() {
    if let Some(seen) = SEEN_INLINE_SOURCES.get() {
        seen.lock()
            .expect("inline-sources warn mutex poisoned")
            .clear();
    }
}

/// Read-only snapshot of the dedup set. Intended for tests that need to
/// assert that a particular caller routed through [`warn_pipeline_inline_sources`]
/// (e.g. asserting the runtime hot-reload path covers the deprecation).
#[doc(hidden)]
pub fn tests_only_snapshot() -> HashSet<PathBuf> {
    SEEN_INLINE_SOURCES
        .get()
        .map(|m| {
            m.lock()
                .expect("inline-sources warn mutex poisoned")
                .clone()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn dedup_suppresses_repeat_warnings_for_same_canonical_path() {
        let _guard = DEDUP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        writeln!(file, "name: deprecated_pipeline").unwrap();
        reset_inline_sources_dedup_for_tests();

        warn_pipeline_inline_sources(file.path(), "deprecated_pipeline");
        warn_pipeline_inline_sources(file.path(), "deprecated_pipeline");

        // Snapshot (which drops the global guard) before asserting so a failed
        // assertion cannot poison `SEEN_INLINE_SOURCES`.
        let canonical = file.path().canonicalize().unwrap();
        let seen = tests_only_snapshot();
        assert!(
            seen.contains(&canonical),
            "canonical path should be recorded in dedup set"
        );
    }

    #[test]
    fn dedup_distinguishes_distinct_canonical_paths() {
        let _guard = DEDUP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        let b = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        reset_inline_sources_dedup_for_tests();

        warn_pipeline_inline_sources(a.path(), "a");
        warn_pipeline_inline_sources(b.path(), "b");

        let seen = tests_only_snapshot();
        assert!(seen.contains(&a.path().canonicalize().unwrap()));
        assert!(seen.contains(&b.path().canonicalize().unwrap()));
    }
}
