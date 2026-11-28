#![no_main]
//! DNS answers for TAXII discovery and DANE: SRV and TLSA record selection
//! under each DNSSEC proof state, and TLSA matching against presented chains.

use libfuzzer_sys::fuzz_target;
use rstix::taxii::TlsaRecord;
use rstix::taxii::fuzzing::{dns_answers, evaluate_tlsa};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let split = rest.len() / 2;
    let (message, certs) = rest.split_at(split);
    let proofs = &[flags, flags.rotate_left(2), flags.rotate_left(4)];

    if let Some((tlsa, srv)) = dns_answers(message, proofs, flags & 1 == 1) {
        if flags & 1 == 1
            && let Ok(targets) = &srv
        {
            assert!(targets.iter().all(|(_, _, secure)| *secure));
        }
        if let Ok(records) = tlsa {
            let (end_entity, intermediate) = certs.split_at(certs.len() / 2);
            let _ = evaluate_tlsa(&records, end_entity, &[intermediate]);
        }
    }

    if certs.len() >= 3 {
        let record = TlsaRecord {
            cert_usage: certs[0] % 5,
            selector: certs[1] % 3,
            matching: certs[2] % 3,
            cert_data: certs[3..].iter().take(64).copied().collect(),
        };
        let _ = evaluate_tlsa(&[record], &certs[3..], &[certs]);
    }
});
