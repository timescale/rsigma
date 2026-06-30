//! Shared Unix domain socket helpers: scheme parsing, listener binding with
//! stale-socket recovery, and socket-file cleanup.
//!
//! Used by the `unix://` event source ([`super::UnixSocketSource`]) and the
//! daemon's `--api-addr unix://` listener. Gated behind
//! `#[cfg(all(unix, feature = "uds"))]`.

use std::io;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

/// Permission mode applied to a freshly bound socket file: owner read/write
/// only. The socket is the local trust boundary, so it must not be group- or
/// world-accessible by default.
const SOCKET_MODE: u32 = 0o600;

/// Strip a `unix://` scheme prefix, returning the socket path, or `None` when
/// `spec` is not a `unix://` URI.
pub fn parse_unix_scheme(spec: &str) -> Option<PathBuf> {
    spec.strip_prefix("unix://").map(PathBuf::from)
}

/// Unlinks a bound socket file when dropped.
///
/// The daemon listener and the event source hold one for the socket's lifetime
/// so a clean shutdown leaves no stale file behind. A crash leaves the file,
/// which [`bind_unix_listener`] removes on the next start.
#[derive(Debug)]
pub struct UnixSocketGuard {
    path: PathBuf,
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind a [`UnixListener`] at `path`, recovering from a stale socket file left
/// by a previously crashed run.
///
/// On `AddrInUse` the existing socket is probed by connecting to it: a
/// successful connect means another live process owns it (returned as an error
/// so two daemons never fight over one path), while a failed connect means the
/// file is stale and is removed and rebound. The socket file is then restricted
/// to `0600`.
///
/// Returns the listener plus a [`UnixSocketGuard`] that unlinks the socket on
/// drop; hold it for the listener's lifetime.
pub async fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, UnixSocketGuard)> {
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            if UnixStream::connect(path).await.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "unix socket {} is already in use by a running process",
                        path.display()
                    ),
                ));
            }
            tracing::warn!(path = %path.display(), "removing stale unix socket");
            std::fs::remove_file(path)?;
            UnixListener::bind(path)?
        }
        Err(e) => return Err(e),
    };

    set_socket_permissions(path)?;
    Ok((
        listener,
        UnixSocketGuard {
            path: path.to_path_buf(),
        },
    ))
}

/// Restrict the socket file to owner-only access.
///
/// There is a small window between `bind` and this `chmod` during which the
/// socket inherits the process umask; deployments that need to close it should
/// place the socket in a directory only the daemon's user can traverse.
fn set_socket_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_scheme_strips_prefix() {
        assert_eq!(
            parse_unix_scheme("unix:///run/rsigma.sock"),
            Some(PathBuf::from("/run/rsigma.sock"))
        );
        assert_eq!(parse_unix_scheme("stdin"), None);
        assert_eq!(parse_unix_scheme("nats://host/subject"), None);
    }

    #[tokio::test]
    async fn bind_creates_owner_only_socket_and_guard_unlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");

        let (listener, guard) = bind_unix_listener(&path).await.unwrap();
        assert!(path.exists());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);

        drop(listener);
        drop(guard);
        assert!(!path.exists(), "guard should unlink the socket on drop");
    }

    #[tokio::test]
    async fn bind_recovers_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");

        // First bind, then drop only the listener (leaving a stale file as if
        // the process had crashed without the guard running).
        let (listener, guard) = bind_unix_listener(&path).await.unwrap();
        std::mem::forget(guard); // skip the unlink-on-drop
        drop(listener);
        assert!(path.exists());

        // A fresh bind must reclaim the stale path rather than failing.
        let (_listener, _guard) = bind_unix_listener(&path).await.unwrap();
    }

    #[tokio::test]
    async fn bind_rejects_live_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");

        let (_listener, _guard) = bind_unix_listener(&path).await.unwrap();
        // A second bind while the first listener is alive must fail.
        let err = bind_unix_listener(&path).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }
}
