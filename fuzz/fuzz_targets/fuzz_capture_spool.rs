#![no_main]
use libfuzzer_sys::fuzz_target;

// Manifest, provenance, and corpus documents are untrusted once they leave
// the daemon: `rule tune --from-dispositions` reads them from disk. Parsing
// must fail closed without panicking or allocating from an unbounded input.
fuzz_target!(|data: &[u8]| {
    let _ = rsigma_runtime::parse_manifest(data);
    let _ = rsigma_runtime::parse_provenance(data);
    let _ = rsigma_runtime::parse_corpus_events(data);
});
