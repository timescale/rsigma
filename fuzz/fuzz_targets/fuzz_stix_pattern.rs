#![no_main]
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rstix::core::StixTimestamp;
use rstix::model::{Bundle, StixObject};
use rstix::model::sco::ScoObject;
use rstix::pattern::{ObservationContext, TimestampedObservation};

/// Directories that all contain each other, plus SCOs with `_ref` and `_refs`
/// paths, so evaluation exercises dereference fan-out and its limits.
static BUNDLE: LazyLock<Bundle> = LazyLock::new(|| {
    let directory = |n: usize| format!("directory--00000000-0000-4000-8000-{n:012x}");
    let mesh: Vec<String> = (0..6).map(|n| format!("\"{}\"", directory(n))).collect();
    let mut objects: Vec<String> = (0..6)
        .map(|n| {
            format!(
                r#"{{"type":"directory","spec_version":"2.1","id":"{}","path":"/d{n}","contains_refs":[{}]}}"#,
                directory(n),
                mesh.join(",")
            )
        })
        .collect();
    objects.extend([
        r#"{"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--00000000-0000-4000-8000-000000000101","value":"198.51.100.3","resolves_to_refs":["mac-addr--00000000-0000-4000-8000-000000000102"]}"#.to_owned(),
        r#"{"type":"mac-addr","spec_version":"2.1","id":"mac-addr--00000000-0000-4000-8000-000000000102","value":"d2:fb:49:24:37:18"}"#.to_owned(),
        r#"{"type":"network-traffic","spec_version":"2.1","id":"network-traffic--00000000-0000-4000-8000-000000000103","src_ref":"ipv4-addr--00000000-0000-4000-8000-000000000101","dst_ref":"ipv4-addr--00000000-0000-4000-8000-000000000101","protocols":["tcp"],"src_port":443}"#.to_owned(),
        r#"{"type":"file","spec_version":"2.1","id":"file--00000000-0000-4000-8000-000000000104","name":"payload.exe","hashes":{"MD5":"79054025255fb1a26e4bc422aef54eb4"},"parent_directory_ref":"directory--00000000-0000-4000-8000-000000000000"}"#.to_owned(),
        r#"{"type":"process","spec_version":"2.1","id":"process--00000000-0000-4000-8000-000000000105","pid":42,"command_line":"payload.exe --run","image_ref":"file--00000000-0000-4000-8000-000000000104","opened_connection_refs":["network-traffic--00000000-0000-4000-8000-000000000103"]}"#.to_owned(),
    ]);
    Bundle::parse(&format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
        objects.join(",")
    ))
    .expect("fuzz bundle")
});

static OBSERVATIONS: LazyLock<Vec<(&'static ScoObject, StixTimestamp)>> = LazyLock::new(|| {
    BUNDLE
        .objects()
        .iter()
        .filter_map(|object| match object {
            StixObject::Sco(sco) => Some(sco),
            _ => None,
        })
        .enumerate()
        .map(|(n, sco)| {
            let at = StixTimestamp::parse(&format!("2024-01-01T00:00:{n:02}.000Z")).expect("ts");
            (sco, at)
        })
        .collect()
});

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(pattern) = rstix::Pattern::parse(text) else {
        return;
    };
    let _ = pattern.to_string();
    let _ = pattern.simple_observables();

    // Evaluation stays within its step, fan-out, and regex-cache limits, and a
    // repeat (which reuses the cached regexes) gives the same answer.
    let bundle = &*BUNDLE;
    for (sco, _) in OBSERVATIONS.iter() {
        let first = pattern.matches_single_with_bundle(sco, Some(bundle));
        assert_eq!(first, pattern.matches_single_with_bundle(sco, Some(bundle)));
    }
    let observations: Vec<TimestampedObservation<'_>> = OBSERVATIONS
        .iter()
        .map(|(sco, at)| TimestampedObservation {
            sco,
            at: Some(at.clone()),
        })
        .collect();
    let ctx = ObservationContext {
        observations: &observations,
        bundle: Some(bundle),
    };
    let first = pattern.evaluate(&ctx);
    assert_eq!(first, pattern.clone().evaluate(&ctx));
});
