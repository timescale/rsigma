//! Fuzz push, replace, and delete bodies for a watchlist.
//!
//! The first byte selects the operation. The rest is JSON: an indicator
//! array, or an object with an `indicators` field. Limits stay small so a
//! huge input is rejected instead of allocating a large set.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_eval::pipeline::sources::{DynamicSource, ErrorPolicy, RefreshPolicy, SourceType};
use rsigma_runtime::{WatchlistItem, WatchlistRegistry};
use serde::Deserialize;

#[derive(Deserialize)]
struct PushBody {
    #[serde(default)]
    indicators: Vec<WatchlistItem>,
}

fn registry() -> WatchlistRegistry {
    WatchlistRegistry::from_sources(&[DynamicSource {
        id: "c2".into(),
        source_type: SourceType::Watchlist {
            max_indicators: 8,
            max_value_length: 32,
            default_ttl: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    }])
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_600, 0).expect("timestamp")
}

fn items(body: &[u8]) -> Option<Vec<WatchlistItem>> {
    if let Ok(push) = serde_json::from_slice::<PushBody>(body) {
        return Some(push.indicators);
    }
    serde_json::from_slice(body).ok()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let set = registry();
    let now = now();
    match data[0] % 3 {
        0 => {
            let Some(items) = items(&data[1..]) else {
                return;
            };
            let _ = set.add("c2", &items, None, now);
        }
        1 => {
            let Some(items) = items(&data[1..]) else {
                return;
            };
            let _ = set.replace("c2", &items, None, now);
        }
        _ => {
            let Ok(values) = serde_json::from_slice::<Vec<String>>(&data[1..]) else {
                return;
            };
            let _ = set.remove("c2", &values, now);
        }
    }
    let Ok(values) = set.values("c2", now) else {
        return;
    };
    let mut ordered = values.clone();
    ordered.sort();
    ordered.dedup();
    assert_eq!(values, ordered);
});
