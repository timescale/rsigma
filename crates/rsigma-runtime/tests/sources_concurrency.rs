//! Concurrent source resolution, per-source refresh tasks, and panic containment.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{
    DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
};
use rsigma_runtime::sources::refresh::{RefreshScheduler, RefreshTrigger};
use rsigma_runtime::sources::{
    MAX_CONCURRENT_RESOLVES, ResolvedValue, SourceError, SourceErrorKind, SourceResolver,
    resolve_all,
};

/// Resolves by source id: `hang*` never returns, `panic*` panics, `slow*`
/// sleeps 300 ms, anything else returns its own id.
#[derive(Default)]
struct Scripted {
    calls: Mutex<HashMap<String, usize>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl Scripted {
    fn calls(&self, id: &str) -> usize {
        self.calls.lock().unwrap().get(id).copied().unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl SourceResolver for Scripted {
    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        *self
            .calls
            .lock()
            .unwrap()
            .entry(source.id.clone())
            .or_default() += 1;
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        if source.id.starts_with("hang") {
            std::future::pending::<()>().await;
        }
        if source.id.starts_with("slow") {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        if source.id.starts_with("panic") {
            panic!("scripted panic in {}", source.id);
        }
        Ok(ResolvedValue {
            data: serde_json::json!(source.id),
            resolved_at: Instant::now(),
            from_cache: false,
        })
    }
}

fn source(id: &str, required: bool) -> DynamicSource {
    DynamicSource {
        id: id.to_owned(),
        source_type: SourceType::File {
            path: "unused.json".into(),
            format: DataFormat::Json,
            extract: None,
            stix: None,
        },
        refresh: RefreshPolicy::OnDemand,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required,
        default: None,
    }
}

async fn wait_for<F: Fn(&HashMap<String, serde_json::Value>) -> bool>(
    results: &mut tokio::sync::watch::Receiver<Option<rsigma_runtime::RefreshResult>>,
    ready: F,
) -> HashMap<String, serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(result) = results.borrow_and_update().as_ref()
                && ready(&result.resolved)
            {
                return result.resolved.clone();
            }
            results.changed().await.expect("scheduler alive");
        }
    })
    .await
    .expect("refresh result in time")
}

#[tokio::test]
async fn resolve_all_runs_sources_concurrently() {
    let resolver = Scripted::default();
    let sources: Vec<_> = (0..MAX_CONCURRENT_RESOLVES)
        .map(|i| source(&format!("slow-{i}"), true))
        .collect();
    let started = Instant::now();
    let resolved = resolve_all(&resolver, &sources).await.expect("resolve");
    assert_eq!(resolved.len(), MAX_CONCURRENT_RESOLVES);
    assert!(
        started.elapsed() < Duration::from_millis(300 * 3),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        resolver.max_active.load(Ordering::SeqCst),
        MAX_CONCURRENT_RESOLVES
    );
}

#[tokio::test]
async fn resolve_all_bounds_how_many_sources_run_at_once() {
    let resolver = Scripted::default();
    let sources: Vec<_> = (0..MAX_CONCURRENT_RESOLVES * 2)
        .map(|i| source(&format!("slow-{i}"), true))
        .collect();
    resolve_all(&resolver, &sources).await.expect("resolve");
    assert_eq!(
        resolver.max_active.load(Ordering::SeqCst),
        MAX_CONCURRENT_RESOLVES
    );
}

#[tokio::test]
async fn resolve_all_contains_a_panic_to_its_source() {
    let resolver = Scripted::default();
    let resolved = resolve_all(&resolver, &[source("panic", false), source("ok", true)])
        .await
        .expect("optional panic is skipped");
    assert_eq!(resolved["panic"], serde_json::Value::Null);
    assert_eq!(resolved["ok"], "ok");

    let err = resolve_all(&resolver, &[source("ok", true), source("panic", true)])
        .await
        .expect_err("required panic fails");
    assert_eq!(err.source_id, "panic");
    assert!(
        matches!(&err.kind, SourceErrorKind::Panic(message) if message.contains("scripted panic")),
        "{err}"
    );
}

#[tokio::test]
async fn resolve_all_reports_the_first_required_failure_in_order() {
    let resolver = Scripted::default();
    let err = resolve_all(
        &resolver,
        &[
            source("slow", true),
            source("panic-a", true),
            source("panic-b", true),
        ],
    )
    .await
    .expect_err("required failure");
    assert_eq!(err.source_id, "panic-a");
}

#[tokio::test]
async fn scheduler_publishes_other_sources_while_one_hangs() {
    let resolver = Arc::new(Scripted::default());
    let scheduler = RefreshScheduler::new();
    let mut results = scheduler.result_receiver();
    let trigger = scheduler.trigger_sender();
    let handle = scheduler.run(
        vec![source("hang", true), source("fast", true)],
        resolver.clone(),
    );

    trigger.send(RefreshTrigger::All).await.unwrap();
    let resolved = wait_for(&mut results, |r| r.contains_key("fast")).await;
    assert_eq!(resolved["fast"], "fast");

    trigger
        .send(RefreshTrigger::Single("fast".into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while resolver.calls("fast") < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a later trigger still runs");
    assert_eq!(resolver.calls("hang"), 1);
    handle.abort();
}

#[tokio::test]
async fn scheduler_survives_a_panicking_source() {
    let resolver = Arc::new(Scripted::default());
    let scheduler = RefreshScheduler::new();
    let mut results = scheduler.result_receiver();
    let trigger = scheduler.trigger_sender();
    let handle = scheduler.run(
        vec![source("panic", true), source("ok", true)],
        resolver.clone(),
    );

    trigger.send(RefreshTrigger::All).await.unwrap();
    wait_for(&mut results, |r| r.contains_key("ok")).await;
    trigger.send(RefreshTrigger::All).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while resolver.calls("ok") < 2 || resolver.calls("panic") < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the scheduler keeps running after a panic");
    assert!(!handle.is_finished());
    assert!(
        !results
            .borrow()
            .as_ref()
            .unwrap()
            .resolved
            .contains_key("panic")
    );
    handle.abort();
}

#[tokio::test]
async fn scheduler_reruns_a_source_triggered_while_it_resolves() {
    let resolver = Arc::new(Scripted::default());
    let scheduler = RefreshScheduler::new();
    let trigger = scheduler.trigger_sender();
    let handle = scheduler.run(vec![source("slow", true)], resolver.clone());

    for _ in 0..3 {
        trigger
            .send(RefreshTrigger::Single("slow".into()))
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while resolver.calls("slow") < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("rerun after the first resolve");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        resolver.calls("slow"),
        2,
        "triggers during a resolve coalesce"
    );
    assert_eq!(resolver.max_active.load(Ordering::SeqCst), 1);
    handle.abort();
}
