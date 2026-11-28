#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_runtime::HostGuard;

// The daemon API and the MCP HTTP transport check every request's `Host` and
// `Origin` headers with a `HostGuard` built from operator-supplied hosts. The
// input is newline-separated: comma-separated allowed hosts, then the `Host`
// header, the `Origin` header, and the HTTP/2 authority. Checking must never
// panic, must be deterministic, must answer only 400 or 403, and a guard must
// accept a host it was built from.
fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(4, |&b| b == b'\n');
    let entries = parts.next().unwrap_or_default();
    let host = parts.next();
    let origin = parts.next();
    let authority = parts.next().and_then(|a| std::str::from_utf8(a).ok());

    let entries = String::from_utf8_lossy(entries);
    let list: Vec<&str> = entries.split(',').filter(|e| !e.is_empty()).collect();
    let guards = [
        HostGuard::loopback(),
        HostGuard::any(),
        HostGuard::new(&list).unwrap_or_default(),
    ];
    for guard in &guards {
        let verdict = guard.check(host, authority, origin);
        assert_eq!(verdict, guard.check(host, authority, origin));
        if let Err(rejection) = verdict {
            assert!(matches!(rejection.status(), 400 | 403));
            assert!(!rejection.message().is_empty());
        }
    }
    assert_eq!(HostGuard::any().check(None, None, None), Ok(()));

    for entry in list.iter().map(|e| e.trim()) {
        if let Ok(guard) = HostGuard::new([entry]) {
            if entry.parse::<std::net::Ipv6Addr>().is_err() {
                assert_eq!(
                    guard.check(Some(entry.as_bytes()), None, None),
                    Ok(()),
                    "a guard refused its own entry {entry:?}"
                );
            }
            assert!(guard.hosts().is_some_and(|hosts| !hosts.is_empty()));
        }
    }
});
