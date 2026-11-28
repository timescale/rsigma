//! Connection handling for the HTTP listeners (`http-server` feature).
//!
//! [`serve`] runs an axum [`Router`] on any [`Listener`] with the limits a
//! network-facing server needs and `axum::serve` does not set:
//!
//! - at most [`ServeLimits::max_connections`] open connections; past that the
//!   listener stops accepting and new clients wait in the kernel backlog;
//! - a client must send its first bytes, and each HTTP/1 request head, within
//!   [`ServeLimits::read_timeout`], which also closes idle keep-alive
//!   connections;
//! - a request body that stalls for longer than the read timeout fails;
//! - HTTP/2 connections are pinged so dead peers are dropped.
//!
//! Responses are not time-limited, so streaming endpoints keep working.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::serve::Listener;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::Sleep;
use tower::ServiceExt;
use tower_http::timeout::TimeoutBody;

/// Default for [`ServeLimits::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Default for [`ServeLimits::read_timeout`].
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Connection limits applied by [`serve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServeLimits {
    /// Open connections the server holds at once. Zero is treated as one.
    pub max_connections: usize,
    /// How long the server waits for a client's first bytes, for each HTTP/1
    /// request head (including the next request on an idle keep-alive
    /// connection), and between chunks of a request body.
    pub read_timeout: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

impl ServeLimits {
    /// Limits with the given connection cap and read timeout.
    pub fn new(max_connections: usize, read_timeout: Duration) -> Self {
        Self {
            max_connections,
            read_timeout,
        }
    }
}

/// Serve `router` on `listener` until `shutdown` resolves, then stop
/// accepting and wait for open connections to finish.
pub async fn serve<L, F>(mut listener: L, router: Router, limits: ServeLimits, shutdown: F)
where
    L: Listener,
    F: Future<Output = ()> + Send,
{
    let permits = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let read_timeout = limits.read_timeout;
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
        .enable_connect_protocol();
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            biased;
            () = &mut shutdown => break,
            permit = permits.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let (io, _addr) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            conn = listener.accept() => conn,
        };
        let io = TokioIo::new(FirstReadDeadline::new(io, read_timeout));
        let service = TowerToHyperService::new(router.clone().map_request(
            move |request: hyper::Request<Incoming>| {
                request.map(|body| TimeoutBody::new(read_timeout, body))
            },
        ));
        let conn = graceful.watch(
            builder
                .serve_connection_with_upgrades(io, service)
                .into_owned(),
        );
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::trace!(error = %e, "connection closed with an error");
            }
            drop(permit);
        });
    }

    drop(listener);
    graceful.shutdown().await;
}

/// An I/O stream that fails a read with [`io::ErrorKind::TimedOut`] when the
/// peer sends nothing within the deadline after the connection opens. Once
/// the first bytes (or end of stream) arrive, it is a plain pass-through.
pub struct FirstReadDeadline<I> {
    inner: I,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<I> FirstReadDeadline<I> {
    /// Wrap `inner`, starting the deadline now.
    pub fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(timeout))),
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for FirstReadDeadline<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let expired = this
                    .deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready());
                if expired {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client sent nothing before the read timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for FirstReadDeadline<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn start(limits: ServeLimits) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .route("/echo", post(|body: String| async move { body }));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(serve(listener, router, limits, async {
            let _ = rx.await;
        }));
        (addr, tx)
    }

    async fn get_ok(addr: SocketAddr) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    /// Read until the server closes the stream, returning how long it took.
    async fn time_until_closed(stream: &mut TcpStream) -> Duration {
        let started = Instant::now();
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return started.elapsed(),
                Ok(Ok(_)) => continue,
                Err(_) => panic!("server kept the connection open"),
            }
        }
    }

    #[tokio::test]
    async fn silent_connection_is_closed_after_the_read_timeout() {
        let (addr, _stop) = start(ServeLimits::new(16, Duration::from_millis(300))).await;
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let elapsed = time_until_closed(&mut silent).await;
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }

    #[tokio::test]
    async fn trickled_request_head_is_closed_after_the_read_timeout() {
        let (addr, _stop) = start(ServeLimits::new(16, Duration::from_millis(500))).await;
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /ok HTTP/1.1\r\n").await.unwrap();
        let writer = async {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if slow.write_all(b"X-Slow: 1\r\n").await.is_err() {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "server kept a trickling request open");
        assert!(!String::from_utf8_lossy(&buf).contains("200 OK"));
    }

    #[tokio::test]
    async fn stalled_request_body_fails_after_the_read_timeout() {
        let (addr, _stop) = start(ServeLimits::new(16, Duration::from_millis(300))).await;
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        stalled
            .write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nabc")
            .await
            .unwrap();
        let elapsed = time_until_closed(&mut stalled).await;
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }

    #[tokio::test]
    async fn connection_cap_holds_new_clients_until_a_slot_frees() {
        let (addr, _stop) = start(ServeLimits::new(1, Duration::from_millis(500))).await;
        let _held = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        let response = get_ok(addr).await;
        assert!(response.contains("200 OK"), "{response}");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "the second client was served while the only slot was taken"
        );
    }

    #[tokio::test]
    async fn active_clients_are_served_and_shutdown_stops_accepting() {
        let (addr, stop) = start(ServeLimits::default()).await;
        assert!(get_ok(addr).await.contains("200 OK"));
        stop.send(()).unwrap();
        let refused = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("listener still accepting after shutdown");
    }
}
