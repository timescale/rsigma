//! Fuzz `POST /api/v1/silences` bodies through the API silence builder.
//!
//! Sizes are checked before anything compiles, every regex compiles within
//! the API regex limits, and a stored silence never takes the store past its
//! regex memory budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{
    MAX_SILENCE_MATCHERS, MAX_SILENCE_REGEX_MEMORY, MAX_SILENCE_REQUEST_BYTES, Silence,
    SilenceLimits, SilenceSpec, SilenceStore,
};

const NOW: i64 = 1_767_225_600;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_SILENCE_REQUEST_BYTES {
        return;
    }
    let Ok(spec) = serde_json::from_slice::<SilenceSpec>(data) else {
        return;
    };
    let matchers = spec.matchers.len();
    let Ok(silence) = Silence::build_api(spec, &SilenceLimits::default(), NOW) else {
        return;
    };
    assert!(matchers <= MAX_SILENCE_MATCHERS);
    let mut store = SilenceStore::default();
    let _ = store.insert_api(silence, usize::MAX, None);
    assert!(store.api_regex_memory() <= MAX_SILENCE_REGEX_MEMORY);
});
