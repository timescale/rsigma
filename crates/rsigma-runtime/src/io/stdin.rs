use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use super::{AckToken, EventSource, RawEvent};

/// Whether the stdin reader stopped on a read error instead of end of input.
#[derive(Debug, Clone, Default)]
pub struct StdinReadStatus(Arc<AtomicBool>);

impl StdinReadStatus {
    /// True once the reader has stopped on an I/O error or a line that is
    /// not valid UTF-8. Final once the source has reported end of input.
    pub fn failed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Reads events from stdin, one per line.
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

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinSource {
    pub fn new() -> Self {
        // Bounded so a slow pipeline back-pressures the reader thread (which
        // then stops draining the OS stdin buffer) instead of buffering
        // unboundedly.
        let (tx, rx) = mpsc::channel(16);
        let status = StdinReadStatus::default();
        let thread_status = status.clone();
        std::thread::Builder::new()
            .name("rsigma-stdin".to_string())
            .spawn(move || {
                read_lines(std::io::stdin().lock(), &tx, &thread_status);
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

/// Read lines and forward them in chunks of at most [`CHUNK_LINES`]. A chunk
/// is also sent whenever the read buffer holds no further complete line, so a
/// line on a slow pipe is forwarded before the next read can block, even when
/// the buffer ends in part of the following line.
fn read_lines<R: Read>(reader: R, tx: &mpsc::Sender<Vec<String>>, status: &StdinReadStatus) {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut line = String::new();
    let mut chunk = Vec::with_capacity(CHUNK_LINES);
    // Bytes after the last newline in the read buffer. They stay the same
    // until the buffer refills, which only happens once no newline is left.
    let mut partial_tail: Option<usize> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.ends_with('\n') {
                    line.pop();
                    if line.ends_with('\r') {
                        line.pop();
                    }
                }
                chunk.push(line.clone());
                let buffered = reader.buffer();
                let tail = *partial_tail.get_or_insert_with(|| {
                    buffered
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map_or(buffered.len(), |last| buffered.len() - last - 1)
                });
                let line_ready = buffered.len() > tail;
                if !line_ready {
                    partial_tail = None;
                }
                if chunk.len() >= CHUNK_LINES || !line_ready {
                    // `blocking_send` only errors when the receiver is
                    // dropped, i.e. the daemon is shutting down; stop reading
                    // so the thread can exit.
                    let full = std::mem::replace(&mut chunk, Vec::with_capacity(CHUNK_LINES));
                    if tx.blocking_send(full).is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error reading stdin");
                status.0.store(true, Ordering::Release);
                break;
            }
        }
    }
    if !chunk.is_empty() {
        let _ = tx.blocking_send(chunk);
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
    use std::time::{Duration, Instant};

    use super::*;

    fn drain(rx: &mut mpsc::Receiver<Vec<String>>) -> Vec<Vec<String>> {
        let mut chunks = Vec::new();
        while let Ok(chunk) = rx.try_recv() {
            chunks.push(chunk);
        }
        chunks
    }

    #[test]
    fn read_error_is_reported() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(
            Cursor::new(b"{\"a\":1}\n\xff\xfe\n{\"b\":2}\n"),
            &tx,
            &status,
        );
        assert_eq!(drain(&mut rx), vec![vec!["{\"a\":1}".to_string()]]);
        assert!(status.failed());
    }

    #[test]
    fn clean_input_is_not_a_failure() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(Cursor::new(b"{\"a\":1}\r\n{\"b\":2}\n"), &tx, &status);
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
        );
        let chunks = drain(&mut rx);
        assert!(chunks.iter().all(|chunk| chunk.len() <= CHUNK_LINES));
        assert!(chunks.len() > 1);
        assert_eq!(
            chunks.concat(),
            (0..50_000).map(|i| i.to_string()).collect::<Vec<_>>()
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
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default());
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
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default());
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
            read_lines(Pipe(pipe), &tx, &StdinReadStatus::default());
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
