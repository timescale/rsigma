//! Memory and throughput stress bench for correlation window modes.
//!
//! Unlike the Criterion suites, this target measures **peak heap** via a
//! counting global allocator, which Criterion cannot observe. It exercises
//! the two scenarios from the SEP #214 discussion on memory becoming the
//! bottleneck in stateful window correlation:
//!
//! - high-cardinality group keys (does the `max_state_entries` cap hold?), and
//! - long-lived chatty sessions (how do per-group deques grow within a window?).
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p rsigma-eval --bench correlation_memory
//! ```
//!
//! The full run takes roughly half a minute in release mode. Results print as
//! an aligned table; "peak" and "settled" are heap deltas over the engine
//! baseline (rules loaded, no events processed), so event construction and
//! engine setup are excluded. Alert conditions are set unreachably high so the
//! numbers isolate window-state maintenance rather than alert emission.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rsigma_eval::{CorrelationConfig, CorrelationEngine, JsonEvent, ProcessResultExt};
use rsigma_parser::parse_sigma_yaml;

// ---------------------------------------------------------------------------
// Counting allocator: tracks live and peak heap bytes
// ---------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let grow = new_size - layout.size();
                let live = LIVE.fetch_add(grow, Ordering::Relaxed) + grow;
                PEAK.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn reset_peak() {
    PEAK.store(live_bytes(), Ordering::Relaxed);
}

fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

// ---------------------------------------------------------------------------
// Rule and engine construction
// ---------------------------------------------------------------------------

/// Build a two-document collection: one base detection rule plus one
/// correlation rule with the requested type and window mode. The alert
/// threshold is unreachable so runs measure state maintenance only.
fn rules_yaml(corr_type: &str, window: &str, timespan: &str, gap: Option<&str>) -> String {
    let window_block = match window {
        // Sliding is the default; omit the keys to exercise the default path.
        "sliding" => String::new(),
        "session" => format!(
            "    window: session\n    gap: {}\n",
            gap.expect("session window requires a gap")
        ),
        other => format!("    window: {other}\n"),
    };
    let field_block = if corr_type == "value_count" {
        "        field: CommandLine\n"
    } else {
        ""
    };
    format!(
        r#"title: Base Rule
id: membench-base-001
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
    condition: selection
level: low
---
title: Window Memory Bench Corr
id: membench-corr-001
correlation:
    type: {corr_type}
    rules:
        - membench-base-001
    group-by:
        - User
    timespan: {timespan}
{window_block}    condition:
{field_block}        gte: 1000000
level: high
"#
    )
}

fn engine_for(yaml: &str, max_state_entries: usize) -> CorrelationEngine {
    let collection = parse_sigma_yaml(yaml).expect("bench rules parse");
    let config = CorrelationConfig {
        max_state_entries,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine
        .add_collection(&collection)
        .expect("bench rules load");
    engine
}

// ---------------------------------------------------------------------------
// Measurement plumbing
// ---------------------------------------------------------------------------

struct RunStats {
    events: usize,
    secs: f64,
    peak_delta: usize,
    settled_delta: usize,
    groups: usize,
    alerts: usize,
}

fn report(name: &str, s: &RunStats) {
    println!(
        "{name:<62} {:>9.0} ev/s  peak {:>7.1} MiB  settled {:>7.1} MiB  groups {:>9}  alerts {:>5}",
        s.events as f64 / s.secs,
        mib(s.peak_delta),
        mib(s.settled_delta),
        s.groups,
        s.alerts,
    );
}

// ---------------------------------------------------------------------------
// Scenario A: high-cardinality group keys
//
// One event per unique user key, session window. Exercises the
// `max_state_entries` hard cap and the stalest-first eviction path.
// ---------------------------------------------------------------------------

fn scenario_cardinality(n_keys: usize, max_state_entries: usize) -> RunStats {
    let yaml = rules_yaml("event_count", "session", "2h", Some("5m"));
    let mut engine = engine_for(&yaml, max_state_entries);

    let baseline = live_bytes();
    reset_peak();
    let start = Instant::now();
    let mut alerts = 0usize;

    let base_ts = 1_000_000_000i64;
    for i in 0..n_keys {
        let v = serde_json::json!({
            "EventType": "process_create",
            "User": format!("user_{i:08}"),
            "CommandLine": "whoami /all",
            "Image": "C:\\Windows\\System32\\whoami.exe",
        });
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, base_ts + i as i64);
        alerts += result.correlation_count();
    }

    RunStats {
        events: n_keys,
        secs: start.elapsed().as_secs_f64(),
        peak_delta: peak_bytes().saturating_sub(baseline),
        settled_delta: live_bytes().saturating_sub(baseline),
        groups: engine.state_count(),
        alerts,
    }
}

// ---------------------------------------------------------------------------
// Scenario B: long-lived chatty sessions
//
// `n_groups` hosts each emit one event every `interval_secs`, interleaved,
// for `duration_secs` of stream time. With gap > interval the session never
// closes from inactivity; it only rolls over at the `timespan` cap, so the
// per-group deque grows to timespan / interval entries.
// ---------------------------------------------------------------------------

struct ChattySpec {
    corr_type: &'static str,
    window: &'static str,
    n_groups: usize,
    interval_secs: i64,
    duration_secs: i64,
    timespan: &'static str,
    gap: Option<&'static str>,
    /// When true, every `CommandLine` value is distinct: the worst case for
    /// `value_count`, which stores each `(timestamp, value)` pair.
    distinct_values: bool,
}

fn scenario_chatty(spec: &ChattySpec) -> RunStats {
    let yaml = rules_yaml(spec.corr_type, spec.window, spec.timespan, spec.gap);
    let mut engine = engine_for(&yaml, 1_000_000);

    let users: Vec<String> = (0..spec.n_groups).map(|i| format!("host_{i:06}")).collect();

    let baseline = live_bytes();
    reset_peak();
    let start = Instant::now();
    let mut alerts = 0usize;
    let mut events = 0usize;

    let base_ts = 1_000_000_000i64;
    let ticks = spec.duration_secs / spec.interval_secs;
    for t in 0..ticks {
        let ts = base_ts + t * spec.interval_secs;
        for (g, user) in users.iter().enumerate() {
            let cmd = if spec.distinct_values {
                format!(
                    "cmd_{t}_{g} --with-realistic-arguments --target 10.0.0.{}",
                    g % 255
                )
            } else {
                "whoami /all".to_string()
            };
            let v = serde_json::json!({
                "EventType": "process_create",
                "User": user,
                "CommandLine": cmd,
            });
            let event = JsonEvent::borrow(&v);
            let result = engine.process_event_at(&event, ts);
            alerts += result.correlation_count();
            events += 1;
        }
    }

    RunStats {
        events,
        secs: start.elapsed().as_secs_f64(),
        peak_delta: peak_bytes().saturating_sub(baseline),
        settled_delta: live_bytes().saturating_sub(baseline),
        groups: engine.state_count(),
        alerts,
    }
}

// ---------------------------------------------------------------------------
// Scenario C: identical workload across the three window modes
// ---------------------------------------------------------------------------

fn scenario_mode(window: &'static str) -> RunStats {
    scenario_chatty(&ChattySpec {
        corr_type: "event_count",
        window,
        n_groups: 10_000,
        interval_secs: 100,
        duration_secs: 10_000, // 100 ticks x 10k groups = 1M events
        timespan: "1h",
        gap: if window == "session" {
            Some("10m")
        } else {
            None
        },
        distinct_values: false,
    })
}

// ---------------------------------------------------------------------------
// Scenario D: the same workload spread across many tenants
// ---------------------------------------------------------------------------

fn scenario_tenants(n_tenants: usize, n_events: usize, per_tenant_cap: Option<usize>) -> RunStats {
    let yaml = rules_yaml("event_count", "session", "2h", Some("5m"));
    let mut engine = engine_for(&yaml, 1_000_000);
    engine.set_max_state_entries_per_tenant(per_tenant_cap);

    // Build the inputs before the baseline so peak and settled memory measure
    // correlation state, not the event payloads.
    let tenants: Vec<Option<rsigma_eval::TenantId>> = (0..n_events)
        .map(|i| Some(rsigma_eval::TenantId::new(&format!("t{}", i % n_tenants)).unwrap()))
        .collect();
    let values: Vec<serde_json::Value> = (0..n_events)
        .map(|i| {
            serde_json::json!({
                "EventType": "process_create",
                "User": format!("user_{:08}", i % 1_000),
                "CommandLine": "whoami /all",
                "Image": "C:\\Windows\\System32\\whoami.exe",
            })
        })
        .collect();
    let events: Vec<JsonEvent> = values.iter().map(JsonEvent::borrow).collect();
    let refs: Vec<&JsonEvent> = events.iter().collect();

    let baseline = live_bytes();
    reset_peak();
    let start = Instant::now();
    let results = engine.process_batch_for_tenants(&refs, &tenants);
    let secs = start.elapsed().as_secs_f64();
    let alerts = results.iter().map(|r| r.correlation_count()).sum();
    drop(results);

    RunStats {
        events: n_events,
        secs,
        peak_delta: peak_bytes().saturating_sub(baseline),
        settled_delta: live_bytes().saturating_sub(baseline),
        groups: engine.state_count(),
        alerts,
    }
}

fn main() {
    println!(
        "\n=== A. High-cardinality session windows (1 event/key, event_count, gap 5m, cap 2h) ==="
    );
    for &(n_keys, cap, label) in &[
        (100_000usize, 100_000usize, "100k keys, default cap 100k"),
        (
            1_000_000,
            100_000,
            "1M keys, default cap 100k (eviction active)",
        ),
        (
            1_000_000,
            2_000_000,
            "1M keys, cap raised to 2M (no eviction)",
        ),
    ] {
        let stats = scenario_cardinality(n_keys, cap);
        report(&format!("session  {label}"), &stats);
    }

    println!("\n=== D. Tenant-keyed state (1, 100, 1000 tenants) ===");
    for &n_tenants in &[1usize, 100, 1_000] {
        let stats = scenario_tenants(n_tenants, 100_000, None);
        report(&format!("tenants {n_tenants}"), &stats);
    }
    let stats = scenario_tenants(1_000, 100_000, Some(10));
    report("tenants 1000, per-tenant cap 10", &stats);

    println!("\n=== B. Long-lived chatty sessions ===");
    let stats = scenario_chatty(&ChattySpec {
        corr_type: "event_count",
        window: "session",
        n_groups: 1_000,
        interval_secs: 30,
        duration_secs: 4 * 3600,
        timespan: "2h",
        gap: Some("5m"),
        distinct_values: false,
    });
    report(
        "event_count session  1k groups @ 30s (240 ev/window)",
        &stats,
    );

    let stats = scenario_chatty(&ChattySpec {
        corr_type: "event_count",
        window: "sliding",
        n_groups: 1_000,
        interval_secs: 30,
        duration_secs: 4 * 3600,
        timespan: "2h",
        gap: None,
        distinct_values: false,
    });
    report(
        "event_count sliding  1k groups @ 30s (240 ev/window)",
        &stats,
    );

    let stats = scenario_chatty(&ChattySpec {
        corr_type: "value_count",
        window: "session",
        n_groups: 1_000,
        interval_secs: 30,
        duration_secs: 4 * 3600,
        timespan: "2h",
        gap: Some("5m"),
        distinct_values: true,
    });
    report(
        "value_count session  1k groups @ 30s, distinct strings",
        &stats,
    );

    let stats = scenario_chatty(&ChattySpec {
        corr_type: "event_count",
        window: "session",
        n_groups: 100,
        interval_secs: 1,
        duration_secs: 4 * 3600,
        timespan: "2h",
        gap: Some("5m"),
        distinct_values: false,
    });
    report(
        "event_count session  100 groups @ 1 ev/s (7200 ev/window)",
        &stats,
    );

    // Scaled down (1h stream, 30m cap) so the full bench stays under a minute:
    // the distinct-count check is O(window) per event, so this case is slow by
    // nature -- that is the finding, not an accident of the bench.
    let stats = scenario_chatty(&ChattySpec {
        corr_type: "value_count",
        window: "session",
        n_groups: 100,
        interval_secs: 1,
        duration_secs: 3600,
        timespan: "30m",
        gap: Some("5m"),
        distinct_values: true,
    });
    report(
        "value_count session  100 groups @ 1 ev/s, distinct (1800/window)",
        &stats,
    );

    println!("\n=== C. Mode comparison, identical workload (10k groups, 1M events, 1h window) ===");
    for mode in ["sliding", "tumbling", "session"] {
        let stats = scenario_mode(mode);
        report(&format!("{mode:<8} 10k groups, 100 ev/group"), &stats);
    }

    println!();
}
