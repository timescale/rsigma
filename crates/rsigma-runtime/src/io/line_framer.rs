//! Newline framing for the byte-stream event sources (stdin and Unix
//! sockets): one event per line, with a cap on line length and lossy UTF-8
//! decoding, so neither an over-long line nor bytes that are not UTF-8 can
//! stop a source.

/// Longest line a byte-stream source accepts, not counting the line
/// terminator. Matches the per-line cap of `POST /api/v1/events`.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// One line cut from a byte stream by a [`LineFramer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramedLine {
    /// A complete line without its `\n` or `\r\n` terminator.
    Line {
        /// The line decoded as UTF-8, with each invalid sequence replaced by
        /// U+FFFD.
        text: String,
        /// Whether the line held bytes that are not valid UTF-8.
        invalid_utf8: bool,
    },
    /// A line longer than the framer's cap. Its bytes were discarded as they
    /// arrived, so it never occupied more than the cap in memory.
    TooLong,
}

/// Splits a byte stream into lines, fed in pieces of any size.
///
/// The framer holds at most one partial line, bounded by its cap: once a line
/// grows past the cap the rest of it is skipped up to the next newline and
/// reported as [`FramedLine::TooLong`]. Lines come out in stream order, and
/// how the stream is cut into pieces never changes them.
#[derive(Debug)]
pub struct LineFramer {
    max_line_bytes: usize,
    pending: Vec<u8>,
    discarding: bool,
}

impl Default for LineFramer {
    fn default() -> Self {
        Self::new(MAX_LINE_BYTES)
    }
}

impl LineFramer {
    /// A framer that accepts lines of up to `max_line_bytes` bytes, not
    /// counting the terminator.
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            pending: Vec::new(),
            discarding: false,
        }
    }

    /// Feed the next piece of the stream, passing every line it completes to
    /// `emit`.
    pub fn push(&mut self, mut bytes: &[u8], emit: &mut impl FnMut(FramedLine)) {
        while let Some(end) = memchr::memchr(b'\n', bytes) {
            self.take(&bytes[..end]);
            self.end_line(true, emit);
            bytes = &bytes[end + 1..];
        }
        self.take(bytes);
    }

    /// End the stream, passing a final line that has no terminator to `emit`.
    pub fn finish(&mut self, emit: &mut impl FnMut(FramedLine)) {
        if self.discarding || !self.pending.is_empty() {
            self.end_line(false, emit);
        }
    }

    fn take(&mut self, piece: &[u8]) {
        if self.discarding || piece.is_empty() {
            return;
        }
        // One byte past the cap leaves room for the `\r` of a `\r\n` ending.
        if self.pending.len() + piece.len() > self.max_line_bytes + 1 {
            self.discarding = true;
            self.pending = Vec::new();
        } else {
            self.pending.extend_from_slice(piece);
        }
    }

    fn end_line(&mut self, terminated: bool, emit: &mut impl FnMut(FramedLine)) {
        if std::mem::take(&mut self.discarding) {
            emit(FramedLine::TooLong);
            return;
        }
        if terminated && self.pending.last() == Some(&b'\r') {
            self.pending.pop();
        }
        if self.pending.len() > self.max_line_bytes {
            self.pending.clear();
            emit(FramedLine::TooLong);
            return;
        }
        let bytes = std::mem::take(&mut self.pending);
        emit(match String::from_utf8(bytes) {
            Ok(text) => FramedLine::Line {
                text,
                invalid_utf8: false,
            },
            Err(err) => FramedLine::Line {
                text: String::from_utf8_lossy(err.as_bytes()).into_owned(),
                invalid_utf8: true,
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(max: usize, pieces: &[&[u8]]) -> Vec<FramedLine> {
        let mut framer = LineFramer::new(max);
        let mut out = Vec::new();
        for piece in pieces {
            framer.push(piece, &mut |line| out.push(line));
        }
        framer.finish(&mut |line| out.push(line));
        out
    }

    fn line(text: &str) -> FramedLine {
        FramedLine::Line {
            text: text.to_string(),
            invalid_utf8: false,
        }
    }

    #[test]
    fn splits_on_newlines_and_strips_crlf() {
        assert_eq!(
            frame(64, &[b"a\r\nb\n\nc"]),
            [line("a"), line("b"), line(""), line("c")]
        );
    }

    #[test]
    fn a_final_carriage_return_without_a_newline_is_kept() {
        assert_eq!(frame(64, &[b"a\r"]), [line("a\r")]);
    }

    #[test]
    fn invalid_utf8_is_replaced_and_flagged() {
        assert_eq!(
            frame(64, &[b"{\"a\":1}\n\xff\xfe\n{\"b\":2}\n"]),
            [
                line("{\"a\":1}"),
                FramedLine::Line {
                    text: "\u{fffd}\u{fffd}".to_string(),
                    invalid_utf8: true,
                },
                line("{\"b\":2}"),
            ]
        );
    }

    #[test]
    fn a_line_at_the_cap_is_kept_and_one_past_it_is_dropped() {
        assert_eq!(
            frame(4, &[b"abcd\r\nabcde\nok\n"]),
            [line("abcd"), FramedLine::TooLong, line("ok")]
        );
    }

    #[test]
    fn an_over_long_line_never_holds_more_than_the_cap() {
        let mut framer = LineFramer::new(8);
        let mut out = Vec::new();
        for _ in 0..1000 {
            framer.push(b"xxxxxxxxxxxxxxxx", &mut |line| out.push(line));
            assert!(framer.pending.capacity() <= 9);
        }
        framer.push(b"\nnext\n", &mut |line| out.push(line));
        assert_eq!(out, [FramedLine::TooLong, line("next")]);
    }

    #[test]
    fn an_over_long_final_line_is_reported() {
        assert_eq!(
            frame(2, &[b"ok\nlonger"]),
            [line("ok"), FramedLine::TooLong]
        );
    }

    #[test]
    fn the_cut_points_do_not_change_the_lines() {
        let input = b"first\r\nsec\xffond\n\nlong-line-here\nlast";
        let whole = frame(8, &[input]);
        for cut in 0..input.len() {
            for second in cut..input.len() {
                let pieces: [&[u8]; 3] = [&input[..cut], &input[cut..second], &input[second..]];
                assert_eq!(frame(8, &pieces), whole, "cut at {cut} and {second}");
            }
        }
    }
}
