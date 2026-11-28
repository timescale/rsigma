#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::{Event, FieldKeyBudget, JsonEvent};

// The field and schema observers walk the field keys of untrusted events.
// A walk must stay within its budget, and `has_any_field`, which builds no
// paths, must agree with a walk that has no budget.
fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let event = JsonEvent::borrow(&value);

    let budget = FieldKeyBudget {
        max_keys: 16,
        max_key_bytes: 24,
        max_total_bytes: 128,
    };
    let (mut keys, mut bytes) = (0usize, 0usize);
    event.visit_field_keys(&budget, &mut |key| {
        assert!(key.len() <= budget.max_key_bytes);
        keys += 1;
        bytes += key.len();
    });
    assert!(keys <= budget.max_keys);
    assert!(bytes <= budget.max_total_bytes);

    let unbounded = FieldKeyBudget {
        max_keys: usize::MAX,
        max_key_bytes: usize::MAX,
        max_total_bytes: usize::MAX,
    };
    let mut any = false;
    let overflow = event.visit_field_keys(&unbounded, &mut |_| any = true);
    assert!(overflow.is_empty());
    assert_eq!(event.has_any_field(), any);
});
