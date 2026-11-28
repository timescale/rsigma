#![no_main]
//! TAXII response header values: `Retry-After`, the HTTP `Date` clock skew,
//! `X-TAXII-Date-Added-*` timestamps, and the cursor shifts applied to them.

use libfuzzer_sys::fuzz_target;
use rstix::core::TaxiiTimestamp;
use rstix::taxii::fuzzing::{date_skew, retry_after};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (delta, text) = match rest.split_first_chunk::<8>() {
        Some((delta, text)) => (i64::from_le_bytes(*delta), text),
        None => (0, rest),
    };
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };
    match selector % 3 {
        0 => {
            let _ = retry_after(text);
        }
        1 => {
            if let Some(skew) = date_skew(text) {
                for edge in ["0000-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z"] {
                    let shifted = TaxiiTimestamp::parse(edge).unwrap().adjust_seconds(skew);
                    assert!(TaxiiTimestamp::parse(&shifted.to_rfc3339()).is_ok());
                }
            }
        }
        _ => {
            if let Ok(cursor) = TaxiiTimestamp::parse(text) {
                for shifted in [
                    cursor.adjust_seconds(delta),
                    cursor.adjust_micros(delta),
                    cursor.adjust_micros(-1),
                ] {
                    let wire = shifted.to_rfc3339();
                    assert_eq!(TaxiiTimestamp::parse(&wire).unwrap(), shifted, "{wire}");
                }
                if let Some(checked) = cursor.checked_adjust_seconds(delta) {
                    assert_eq!(checked, cursor.adjust_seconds(delta));
                }
            }
        }
    }
});
