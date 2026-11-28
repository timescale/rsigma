//! Field-key walks over hostile events stay within their budget: the work and
//! the memory they take do not grow with key length times leaf count, and the
//! `has_any_field` schema predicate builds no paths at all.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use rsigma_eval::{
    Event, FieldKeyBudget, FieldObserver, JsonEvent, SchemaClassifier, SchemaPredicate,
    SchemaSignature,
};
use serde_json::{Map, Value, json};

/// Counts the bytes the current thread allocates while counting is on.
struct CountingAlloc;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: forwards the caller's layout to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        // SAFETY: `ptr` was allocated by `System` with `layout`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn record(bytes: usize) {
    // `try_with` because the thread-locals may be gone during thread teardown.
    let _ = COUNTING.try_with(|counting| {
        if counting.get() {
            let _ = ALLOCATED.try_with(|total| total.set(total.get() + bytes));
        }
    });
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Bytes allocated on this thread while running `f`.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.with(|total| total.set(0));
    COUNTING.with(|counting| counting.set(true));
    let out = f();
    COUNTING.with(|counting| counting.set(false));
    (out, ALLOCATED.with(Cell::get))
}

/// One 100 KiB key holding 50,000 scalars. Joining the key onto every leaf
/// path, as an unbounded walk does, would build about 5 GB of strings.
fn long_key_event() -> Value {
    let scalars: Map<String, Value> = (0..50_000).map(|i| (format!("f{i}"), json!(i))).collect();
    let mut root = Map::new();
    root.insert("k".repeat(100 * 1024), Value::Object(scalars));
    Value::Object(root)
}

#[test]
fn a_long_key_over_many_leaves_allocates_nothing_per_leaf() {
    let value = long_key_event();
    let event = JsonEvent::borrow(&value);
    let mut visited = 0usize;
    let (overflow, bytes) =
        allocated_by(|| event.visit_field_keys(&FieldKeyBudget::default(), &mut |_| visited += 1));
    assert_eq!(visited, 0);
    assert_eq!(overflow.too_long, 1);
    assert!(bytes < 64 * 1024, "the walk allocated {bytes} bytes");
}

#[test]
fn many_leaves_under_a_long_but_allowed_prefix_stay_within_the_byte_budget() {
    let scalars: Map<String, Value> = (0..50_000).map(|i| (format!("f{i}"), json!(i))).collect();
    let mut root = Map::new();
    root.insert("p".repeat(400), Value::Object(scalars));
    let value = Value::Object(root);
    let event = JsonEvent::borrow(&value);

    let budget = FieldKeyBudget::default();
    let (keys, bytes) = allocated_by(|| event.field_keys());
    let total: usize = keys.iter().map(|k| k.len()).sum();
    assert!(total <= budget.max_total_bytes);
    assert!(keys.len() < 50_000);
    assert!(
        bytes < 2 * budget.max_total_bytes + budget.max_keys * 64,
        "collecting the keys allocated {bytes} bytes"
    );
}

#[test]
fn has_any_field_allocates_nothing() {
    let value = long_key_event();
    let event = JsonEvent::borrow(&value);
    let (found, bytes) = allocated_by(|| event.has_any_field());
    assert!(found);
    assert_eq!(bytes, 0);

    let empty = json!({"a": {}, "b": {"c": {}}});
    let (found, bytes) = allocated_by(|| JsonEvent::borrow(&empty).has_any_field());
    assert!(!found);
    assert_eq!(bytes, 0);
}

#[test]
fn the_has_any_field_predicate_builds_no_paths() {
    let classifier = SchemaClassifier::new(vec![SchemaSignature {
        name: "structured".to_string(),
        predicates: vec![SchemaPredicate::HasAnyField],
        specificity: 1,
    }]);
    let value = long_key_event();
    let event = JsonEvent::borrow(&value);
    let (matched, bytes) = allocated_by(|| classifier.classify(&event));
    assert_eq!(matched.map(|m| m.name).as_deref(), Some("structured"));
    assert!(
        bytes < 1024,
        "classifying with has_any_field allocated {bytes} bytes"
    );
}

#[test]
fn the_field_observer_stays_bounded_on_a_long_key() {
    let observer = FieldObserver::new(10_000);
    let value = long_key_event();
    let event = JsonEvent::borrow(&value);
    let ((), bytes) = allocated_by(|| observer.observe(&event));
    let snapshot = observer.snapshot();
    assert_eq!(snapshot.unique_keys, 0);
    assert_eq!(snapshot.oversized_keys, 1);
    assert!(bytes < 64 * 1024, "observing allocated {bytes} bytes");
}
