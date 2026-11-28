#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{FramedLine, LineFramer};

const MAX: usize = 64;

fn frame(pieces: &[&[u8]]) -> Vec<FramedLine> {
    let mut framer = LineFramer::new(MAX);
    let mut out = Vec::new();
    for piece in pieces {
        framer.push(piece, &mut |line| out.push(line));
    }
    framer.finish(&mut |line| out.push(line));
    out
}

// Stdin, Unix sockets, and `POST /api/v1/events` cut untrusted byte streams
// into lines with a `LineFramer`. However the stream is split into reads, the
// lines must come out the same, none may exceed the cap, and the number of
// lines must match the newlines in the input.
fuzz_target!(|data: &[u8]| {
    let Some((&seed, input)) = data.split_first() else {
        return;
    };
    let whole = frame(&[input]);

    let mut pieces = Vec::new();
    let mut rest = input;
    let mut step = usize::from(seed % 17) + 1;
    while !rest.is_empty() {
        let cut = step.min(rest.len());
        pieces.push(&rest[..cut]);
        rest = &rest[cut..];
        step = step * 7 % 23 + 1;
    }
    assert_eq!(frame(&pieces), whole, "the read boundaries changed the lines");

    let newlines = input.iter().filter(|&&b| b == b'\n').count();
    let trailing = usize::from(!input.is_empty() && input.last() != Some(&b'\n'));
    assert_eq!(whole.len(), newlines + trailing);
    for line in &whole {
        if let FramedLine::Line { text, invalid_utf8 } = line {
            assert!(!text.contains('\n'));
            assert!(*invalid_utf8 || text.len() <= MAX);
        }
    }
});
