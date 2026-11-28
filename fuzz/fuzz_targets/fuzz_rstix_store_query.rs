#![no_main]
//! Store text search with event-derived terms. The first byte picks the match
//! mode and page size; the rest is the search term. Exact matches must be
//! token matches, token matches must be substring matches, and paging through
//! a result must give the same ids as one unpaged query.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rstix::store::{MemoryStore, QueryCursor, StixQuery, StixStore, TextMatch};

static STORE: LazyLock<MemoryStore> = LazyLock::new(|| {
    let store = MemoryStore::new();
    for fixture in [
        include_str!("../../crates/rstix/tests/fixtures/store/multi-indicators.json"),
        include_str!("../../crates/rstix/tests/fixtures/store/attack-pattern-powershell-t1059.json"),
        include_str!("../../crates/rstix/tests/fixtures/store/sco-ipv4-a.json"),
        include_str!("../../crates/rstix/tests/fixtures/store/sco-ipv4-b.json"),
    ] {
        let bundle = rstix::parse_bundle(fixture).expect("fixture bundle");
        store.import_bundle(&bundle).expect("import fixture");
    }
    let values = [
        "10.0.0.1",
        "10.0.0.10",
        "evil.example",
        "notevil.example",
        "x-evil.example",
        "caf\u{e9}.example",
        "a.a.a",
    ];
    let objects: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(n, value)| {
            rstix::parse_object(&format!(
                r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"{value}","pattern":"[domain-name:value = '{value}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00.000Z"}}"#
            ))
            .expect("indicator")
        })
        .collect();
    store.import_objects(&objects).expect("import indicators");
    store
});

fn ids(store: &MemoryStore, query: &StixQuery) -> Vec<String> {
    store
        .query(query)
        .expect("query")
        .objects
        .iter()
        .map(|object| object.id().as_str().to_owned())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let Ok(term) = std::str::from_utf8(rest) else {
        return;
    };
    let store = &*STORE;
    let query = |mode| StixQuery::new().text_search(term).text_match(mode);
    let substring = ids(store, &query(TextMatch::Substring));
    let token = ids(store, &query(TextMatch::Token));
    let exact = ids(store, &query(TextMatch::Exact));
    for list in [&substring, &token, &exact] {
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]), "{list:?}");
    }
    assert!(token.iter().all(|id| substring.binary_search(id).is_ok()));
    assert!(exact.iter().all(|id| token.binary_search(id).is_ok()));

    let (mode, full) = match control % 3 {
        0 => (TextMatch::Substring, substring),
        1 => (TextMatch::Token, token),
        _ => (TextMatch::Exact, exact),
    };
    let page_size = usize::from(control / 3) % 7 + 1;
    let mut paged = Vec::new();
    let mut cursor: Option<QueryCursor> = None;
    for _ in 0..=full.len() {
        let mut page_query = query(mode).max_results(page_size);
        if let Some(cursor) = cursor.take() {
            page_query = page_query.cursor(cursor);
        }
        let page = store.query(&page_query).expect("page");
        assert!(page.objects.len() <= page_size);
        paged.extend(page.objects.iter().map(|object| object.id().as_str().to_owned()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert!(cursor.is_none(), "paging did not finish");
    assert_eq!(paged, full);
});
