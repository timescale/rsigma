//! A project config file cannot make the CLI download an input: a URL in
//! `coverage.atomics`, `coverage.baseline`, `visibility.mapping`,
//! `scorecard.metrics`, or `hygiene.metrics` from `./rsigma.yaml` is ignored
//! with a warning and nothing connects to it. The same URL from the user
//! config is fetched.

use crate::common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::rsigma;

/// A local HTTP listener that counts connections and answers each with 404.
struct Recorder {
    url: String,
    connections: Arc<AtomicUsize>,
}

impl Recorder {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}/input"),
            connections,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn fixture(dir: &str, name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// The key, the config section that holds it, and the command that reads it.
struct Case {
    key: &'static str,
    yaml: fn(&str) -> String,
    args: fn() -> Vec<String>,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            key: "coverage.atomics",
            yaml: |url| format!("coverage:\n  atomics: '{url}'\n"),
            args: || {
                vec![
                    "rule".into(),
                    "coverage".into(),
                    "--rules".into(),
                    fixture("coverage", "rules.yml"),
                ]
            },
        },
        Case {
            key: "coverage.baseline",
            yaml: |url| format!("coverage:\n  baseline: '{url}'\n"),
            args: || {
                vec![
                    "rule".into(),
                    "coverage".into(),
                    "--rules".into(),
                    fixture("coverage", "rules.yml"),
                ]
            },
        },
        Case {
            key: "visibility.mapping",
            yaml: |url| format!("visibility:\n  mapping: '{url}'\n"),
            args: || {
                vec![
                    "rule".into(),
                    "visibility".into(),
                    "--rules".into(),
                    fixture("visibility", "rules.yml"),
                    "--observed".into(),
                    fixture("visibility", "observed.json"),
                ]
            },
        },
        Case {
            key: "scorecard.metrics",
            yaml: |url| format!("scorecard:\n  metrics: '{url}'\n"),
            args: || {
                vec![
                    "rule".into(),
                    "scorecard".into(),
                    "--backtest".into(),
                    fixture("scorecard", "backtest.json"),
                    "--coverage".into(),
                    fixture("scorecard", "coverage.json"),
                ]
            },
        },
        Case {
            key: "hygiene.metrics",
            yaml: |url| format!("hygiene:\n  metrics: '{url}'\n"),
            args: || {
                vec![
                    "rule".into(),
                    "hygiene".into(),
                    "-r".into(),
                    fixture("hygiene", "rules.yml"),
                ]
            },
        },
    ]
}

/// Run `args` in `cwd` with `config_home` as the user config directory and
/// a private home and cache, returning stderr.
fn run(cwd: &Path, config_home: &Path, args: &[String]) -> String {
    let home: PathBuf = config_home.join("home");
    let output = rsigma()
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_project_config_cannot_make_a_command_download_an_input() {
    for case in cases() {
        let recorder = Recorder::start();
        let project = tempfile::tempdir().unwrap();
        let config_home = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("rsigma.yaml"),
            (case.yaml)(&recorder.url),
        )
        .unwrap();

        let stderr = run(project.path(), config_home.path(), &(case.args)());

        assert_eq!(recorder.connections(), 0, "{}: {stderr}", case.key);
        assert!(
            stderr.contains(&format!(
                "warning: ignoring '{}' from project config",
                case.key
            )),
            "{}: {stderr}",
            case.key
        );
    }
}

#[test]
fn the_user_config_can_still_name_a_remote_input() {
    for case in cases() {
        let recorder = Recorder::start();
        let project = tempfile::tempdir().unwrap();
        let config_home = tempfile::tempdir().unwrap();
        let user_dir = config_home.path().join("rsigma");
        std::fs::create_dir(&user_dir).unwrap();
        std::fs::write(user_dir.join("config.yaml"), (case.yaml)(&recorder.url)).unwrap();

        let stderr = run(project.path(), config_home.path(), &(case.args)());

        assert!(
            recorder.connections() >= 1,
            "{}: no connection; {stderr}",
            case.key
        );
        assert!(!stderr.contains("ignoring"), "{}: {stderr}", case.key);
    }
}
