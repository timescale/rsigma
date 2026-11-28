use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use tokio::sync::mpsc;

use super::line_framer::{FramedLine, LineFramer};
use super::{AckToken, EventSource, RawEvent};
use crate::log_throttle::WarnThrottle;
use crate::metrics::MetricsHook;

/// Whether the stdin reader stopped on a read error instead of end of input.
#[derive(Debug, Clone, Default)]
pub struct StdinReadStatus(Arc<AtomicBool>);

impl StdinReadStatus {
    /// True once the reader has stopped on an I/O error. Final once the
    /// source has reported end of input.
    pub fn failed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Reads events from stdin, one per line.
///
/// Each line is cut by a [`LineFramer`]: a line longer than
/// [`MAX_LINE_BYTES`](super::MAX_LINE_BYTES) is dropped, and bytes that are
/// not valid UTF-8 are replaced with U+FFFD, so only an I/O error or the end
/// of input stops the source.
///
/// Reading happens on a dedicated OS thread (`std::thread`) that forwards
/// lines in chunks over a bounded channel, rather than via `tokio::io::stdin()`.
/// `tokio::io::stdin()` is implemented with an ordinary blocking read on a
/// runtime-managed thread that cannot be cancelled; when no input is pending,
/// that read parks until the next line or EOF and the Tokio runtime waits for
/// it during shutdown. That makes the daemon hang on Ctrl+C / SIGTERM until
/// more input arrives (see the `tokio::io::stdin` docs). Because a plain
/// `std::thread` is not a runtime blocking task, the runtime does not wait for
/// it at shutdown, so the daemon exits promptly even with an idle stdin.
pub struct StdinSource {
    rx: mpsc::Receiver<Vec<String>>,
    pending: VecDeque<String>,
    status: StdinReadStatus,
}

/// Most lines the reader thread forwards in one chunk.
const CHUNK_LINES: usize = 256;

/// A chunk is forwarded once its lines hold this many bytes, so the chunks
/// waiting in the channel stay bounded in size and not only in count.
const CHUNK_BYTES: usize = 1024 * 1024;

/// Bytes the reader asks for in one read.
const READ_BUFFER_BYTES: usize = 64 * 1024;

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinSource {
    pub fn new() -> Self {
        Self::with_metrics(None)
    }

    /// Like [`new`](Self::new), reporting dropped lines, lines that are not
    /// valid UTF-8, and a read error through `metrics`.
    pub fn with_metrics(metrics: Option<Arc<dyn MetricsHook>>) -> Self {
        // Bounded so a slow pipeline back-pressures the reader thread (which
        // then stops draining the OS stdin buffer) instead of buffering
        // unboundedly.
        let (tx, rx) = mpsc::channel(16);
        let status = StdinReadStatus::default();
        let thread_status = status.clone();
        std::thread::Builder::new()
            .name("rsigma-stdin".to_string())
            .spawn(move || {
                read_lines(
                    std::io::stdin().lock(),
                    &tx,
                    &thread_status,
                    metrics.as_deref(),
                );
            })
            .expect("failed to spawn stdin reader thread");
        StdinSource {
            rx,
            pending: VecDeque::new(),
            status,
        }
    }

    /// Take this before handing the source to [`spawn_source`](super::spawn_source).
    pub fn read_status(&self) -> StdinReadStatus {
        self.status.clone()
    }
}

/// Lines waiting to be forwarded to the source.
#[derive(Default)]
struct Chunk {
    lines: Vec<String>,
    bytes: usize,
}

impl Chunk {
    fn push(&mut self, line: String) {
        self.bytes += line.len();
        self.lines.push(line);
    }

    fn is_full(&self) -> bool {
        self.lines.len() >= CHUNK_LINES || self.bytes >= CHUNK_BYTES
    }

    /// Forward the chunk. `false` once the receiver is gone, i.e. the daemon
    /// is shutting down, so the reader can stop.
    fn send(&mut self, tx: &mpsc::Sender<Vec<String>>) -> bool {
        if self.lines.is_empty() {
            return true;
        }
        self.bytes = 0;
        let lines = std::mem::replace(&mut self.lines, Vec::with_capacity(CHUNK_LINES));
        tx.blocking_send(lines).is_ok()
    }
}

/// Read lines and forward them in chunks of at most [`CHUNK_LINES`] lines or
/// about [`CHUNK_BYTES`] bytes. The lines a read completes are forwarded
/// before the next read, so a line on a slow pipe never waits for more input.
fn read_lines<R: Read>(
    mut reader: R,
    tx: &mpsc::Sender<Vec<String>>,
    status: &StdinReadStatus,
    metrics: Option<&dyn MetricsHook>,
) {
    let mut buf = vec![0u8; READ_BUFFER_BYTES];
    let mut framer = LineFramer::default();
    let mut chunk = Chunk::default();
    let mut too_long_log = WarnThrottle::default();
    let mut open = true;
    let mut forward = |line: FramedLine, chunk: &mut Chunk, open: &mut bool| match line {
        FramedLine::Line { text, invalid_utf8 } => {
            if invalid_utf8 && let Some(m) = metrics {
                m.on_input_invalid_utf8("stdin");
            }
            chunk.push(text);
            if chunk.is_full() && *open {
                *open = chunk.send(tx);
            }
        }
        FramedLine::TooLong => {
            if let Some(m) = metrics {
                m.on_input_dropped("stdin", "too_long");
            }
            if let Some(n) = too_long_log.record(Instant::now()) {
                tracing::warn!(
                    max_bytes = super::MAX_LINE_BYTES,
                    dropped = n,
                    "Dropping over-long stdin lines"
                );
            }
        }
    };
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                tracing::error!(error = %e, "Error reading stdin");
                status.0.store(true, Ordering::Release);
                if let Some(m) = metrics {
                    m.on_input_source_failed("stdin");
                }
                // The partial line a failed read leaves behind is incomplete,
                // so only the whole lines read so far are forwarded.
                chunk.send(tx);
                return;
            }
        };
        framer.push(&buf[..n], &mut |line| forward(line, &mut chunk, &mut open));
        if !open || !chunk.send(tx) {
            return;
        }
    }
    framer.finish(&mut |line| forward(line, &mut chunk, &mut open));
    if open {
        chunk.send(tx);
    }
}

impl EventSource for StdinSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.pending.pop_front() {
                Some(line) if !line.trim().is_empty() => {
                    return Some(RawEvent {
                        payload: line,
                        ack_token: AckToken::Noop,
                        tenant: None,
                    });
                }
                Some(_) => continue,
                None => self.pending = self.rx.recv().await?.into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, Instant};

    use super::*;

    fn drain(rx: &mut mpsc::Receiver<Vec<String>>) -> Vec<Vec<String>> {
        let mut chunks = Vec::new();
        while let Ok(chunk) = rx.try_recv() {
            chunks.push(chunk);
        }
        chunks
    }

    #[derive(Default)]
    struct InputMetrics {
        too_long: AtomicU64,
        invalid_utf8: AtomicU64,
        failed: AtomicU64,
    }

    impl MetricsHook for InputMetrics {
        fn on_parse_error(&self) {}
        fn on_events_processed(&self, _count: u64) {}
        fn on_detection_matches(&self, _count: u64) {}
        fn on_correlation_matches(&self, _count: u64) {}
        fn observe_processing_latency(&self, _seconds: f64) {}
        fn on_input_queue_depth_change(&self, _delta: i64) {}
        fn on_back_pressure(&self) {}
        fn observe_batch_size(&self, _size: u64) {}
        fn on_output_queue_depth_change(&self, _delta: i64) {}
        fn observe_pipeline_latency(&self, _seconds: f64) {}
        fn set_correlation_state_entries(&self, _count: u64) {}
        fn on_input_dropped(&self, source: &'static str, reason: &'static str) {
            assert_eq!((source, reason), ("stdin", "too_long"));
            self.too_long.fetch_add(1, Ordering::Relaxed);
        }
        fn on_input_invalid_utf8(&self, source: &'static str) {
            assert_eq!(source, "stdin");
            self.invalid_utf8.fetch_add(1, Ordering::Relaxed);
        }
        fn on_input_source_failed(&self, source: &'static str) {
            assert_eq!(source, "stdin");
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn invalid_utf8_does_not_stop_the_reader() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        let metrics = InputMetrics::default();
        read_lines(
            Cursor::new(b"{\"a\":1}\n\xff\xfe\n{\"b\":2}\n"),
            &tx,
            &status,
            Some(&metrics),
        );
        assert_eq!(
            drain(&mut rx).concat(),
            vec![
                "{\"a\":1}".to_string(),
                "\u{fffd}\u{fffd}".to_string(),
                "{\"b\":2}".to_string()
            ]
        );
        assert!(!status.failed());
        assert_eq!(metrics.invalid_utf8.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_over_long_line_is_dropped_and_counted() {
        let mut input = b"{\"a\":1}\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', 2 * super::super::MAX_LINE_BYTES));
        input.extend_from_slice(b"\n{\"b\":2}\n");
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        let metrics = InputMetrics::default();
        read_lines(Cursor::new(input), &tx, &status, Some(&metrics));
        assert_eq!(
            drain(&mut rx).concat(),
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
        assert!(!status.failed());
        assert_eq!(metrics.too_long.load(Ordering::Relaxed), 1);
    }

    /// Hands out `data`, then fails every read.
    struct FailingReader {
        data: Cursor<Vec<u8>>,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.data.read(buf)? {
                0 => Err(std::io::Error::other("device gone")),
                n => Ok(n),
            }
        }
    }

    #[test]
    fn a_read_error_is_reported_after_the_whole_lines_before_it() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        let metrics = InputMetrics::default();
        read_lines(
            FailingReader {
                data: Cursor::new(b"{\"a\":1}\n{\"b\":".to_vec()),
            },
            &tx,
            &status,
            Some(&metrics),
        );
        assert_eq!(drain(&mut rx).concat(), vec!["{\"a\":1}".to_string()]);
        assert!(status.failed());
        assert_eq!(metrics.failed.load(Ordering::Relaxed), 1);
    }

    /// Fails the first read with `Interrupted`, then reads normally.
    struct InterruptedOnce {
        interrupted: bool,
        data: Cursor<Vec<u8>>,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(ErrorKind::Interrupted.into());
            }
            self.data.read(buf)
        }
    }

    #[test]
    fn an_interrupted_read_is_retried() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(
            InterruptedOnce {
                interrupted: false,
                data: Cursor::new(b"{\"a\":1}\n".to_vec()),
            },
            &tx,
            &status,
            None,
        );
        assert_eq!(drain(&mut rx).concat(), vec!["{\"a\":1}".to_string()]);
        assert!(!status.failed());
    }

    #[test]
    fn clean_input_is_not_a_failure() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(Cursor::new(b"{\"a\":1}\r\n{\"b\":2}\n"), &tx, &status, None);
        assert_eq!(
            drain(&mut rx).concat(),
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
        assert!(!status.failed());
    }

    #[test]
    fn lines_arrive_in_order_in_bounded_chunks() {
        let input: String = (0..50_000).map(|i| format!("{i}\n")).collect();
        let (tx, mut rx) = mpsc::channel(256);
        read_lines(
            Cursor::new(input.into_bytes()),
            &tx,
            &StdinReadStatus::default(),
            None,
        );
        let chunks = drain(&mut rx);
        assert!(chunks.iter().all(|chunk| chunk.len() <= CHUNK_LINES));
        assert!(chunks.len() > 1);
        assert_eq!(
            chunks.concat(),
            (0..50_000).map(|i| i.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn large_lines_are_forwarded_in_chunks_bounded_by_bytes() {
        let line = "y".repeat(300 * 1024);
        let input: String = (0..8).map(|_| format!("{line}\n")).collect();
        let (tx, mut rx) = mpsc::channel(16);
        read_lines(
            Cursor::new(input.into_bytes()),
            &tx,
            &StdinReadStatus::default(),
            None,
        );
        let chunks = drain(&mut rx);
        assert_eq!(chunks.concat().len(), 8);
        assert!(
            chunks.iter().all(|chunk| chunk.len() <= 4),
            "a chunk stops growing once it holds a mebibyte: {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    /// A reader that hands out each written piece and blocks until the next.
    struct Pipe(std::sync::mpsc::Receiver<Vec<u8>>);

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.recv() {
                Ok(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(_) => Ok(0),
            }
        }
    }

    fn recv_within(rx: &mut mpsc::Receiver<Vec<String>>, limit: Duration) -> Option<Vec<String>> {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if let Ok(chunk) = rx.try_recv() {
                return Some(chunk);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    #[test]
    fn a_line_is_forwarded_before_the_next_read_blocks() {
        let (writer, pipe) = std::sync::mpsc::channel();
        let (tx, mut rx) = mpsc::channel(8);
        let reader = std::thread::spawn(move || {
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default(), None);
        });
        writer.send(b"first\n".to_vec()).unwrap();
        assert_eq!(
            recv_within(&mut rx, Duration::from_secs(5)),
            Some(vec!["first".to_string()])
        );
        writer.send(b"second\n".to_vec()).unwrap();
        drop(writer);
        assert_eq!(
            recv_within(&mut rx, Duration::from_secs(5)),
            Some(vec!["second".to_string()])
        );
        reader.join().unwrap();
    }

    #[test]
    fn complete_lines_are_forwarded_before_a_partial_line_completes() {
        let (writer, pipe) = std::sync::mpsc::channel();
        let (tx, mut rx) = mpsc::channel(8);
        let reader = std::thread::spawn(move || {
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default(), None);
        });
        writer.send(b"first\nsecond\nthi".to_vec()).unwrap();
        assert_eq!(
            recv_within(&mut rx, Duration::from_secs(5)),
            Some(vec!["first".to_string(), "second".to_string()])
        );
        writer.send(b"rd\n".to_vec()).unwrap();
        drop(writer);
        assert_eq!(
            recv_within(&mut rx, Duration::from_secs(5)),
            Some(vec!["third".to_string()])
        );
        reader.join().unwrap();
    }

    #[test]
    fn each_write_forwards_the_lines_it_completes() {
        let (writer, pipe) = std::sync::mpsc::channel();
        let (tx, mut rx) = mpsc::channel(8);
        let reader = std::thread::spawn(move || {
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default(), None);
        });
        writer.send(b"line-0-he".to_vec()).unwrap();
        for i in 0..20 {
            let piece = format!("ad\nline-{i}-body\nline-{}-he", i + 1);
            writer.send(piece.into_bytes()).unwrap();
            assert_eq!(
                recv_within(&mut rx, Duration::from_secs(5)),
                Some(vec![format!("line-{i}-head"), format!("line-{i}-body")]),
                "write {i}"
            );
        }
        drop(writer);
        assert_eq!(
            recv_within(&mut rx, Duration::from_secs(5)),
            Some(vec!["line-20-he".to_string()])
        );
        reader.join().unwrap();
    }
}
