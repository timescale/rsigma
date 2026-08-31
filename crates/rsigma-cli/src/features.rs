//! Compile-time inventory of optional Cargo features for the `rsigma` binary.
//!
//! `--help` is not a reliable detector: several features have no unique flag
//! (`evtx`, `logfmt`, `cef`, `daemon-otlp`), and `--input-format` is a free
//! string so clap never lists the gated values. This module is the source of
//! truth for `rsigma --features`, `rsigma --version`, and the `--help` footer.

/// Every optional Cargo feature the `rsigma` binary can be built with, in
/// sorted order. Keep in sync with `[features]` in this crate's `Cargo.toml`.
macro_rules! cli_features {
    ($($name:literal),+ $(,)?) => {
        #[cfg(test)]
        pub const ALL: &[&str] = &[$($name),+];

        pub const ENABLED: &[&str] = &[
            $(
                #[cfg(feature = $name)]
                $name,
            )+
        ];
    };
}

cli_features! {
    "cef",
    "daachorse-index",
    "daemon",
    "daemon-nats",
    "daemon-otlp",
    "daemon-tls",
    "evtx",
    "logfmt",
    "mcp",
}

pub fn print_enabled() {
    for name in ENABLED {
        println!("{name}");
    }
}

pub fn help_footer() -> &'static str {
    static FOOTER: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    FOOTER.get_or_init(|| leak(format!("Compiled-in features: {}", format_enabled())))
}

pub fn long_version() -> &'static str {
    static VERSION: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        leak(format!(
            "{}\nfeatures: {}",
            env!("CARGO_PKG_VERSION"),
            format_enabled(),
        ))
    })
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn format_enabled() -> String {
    ENABLED.join(", ")
}

/// True when argv asks for the feature list and does not name a subcommand.
///
/// clap still requires a subcommand, so `rsigma --features` has to be handled
/// before `get_matches`. A non-flag token (a command group) is left to clap.
pub fn requested(args: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
    let mut has_features = false;
    for arg in args {
        let arg = arg.as_ref();
        if arg == "--features" {
            has_features = true;
            continue;
        }
        if arg == "--" || !arg.starts_with('-') {
            return false;
        }
    }
    has_features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogues_are_sorted() {
        let mut all = ALL.to_vec();
        all.sort_unstable();
        assert_eq!(ALL, all.as_slice());
        let mut enabled = ENABLED.to_vec();
        enabled.sort_unstable();
        assert_eq!(ENABLED, enabled.as_slice());
    }

    #[test]
    fn enabled_is_a_subset_of_all() {
        for name in ENABLED {
            assert!(ALL.contains(name), "unknown feature {name}");
        }
    }

    #[test]
    fn daemon_tracks_the_cfg() {
        assert_eq!(ENABLED.contains(&"daemon"), cfg!(feature = "daemon"));
    }

    #[test]
    fn format_enabled_joins_enabled_names() {
        assert_eq!(format_enabled(), ENABLED.join(", "));
    }

    #[test]
    fn long_version_starts_with_the_crate_version() {
        let version = long_version();
        assert!(version.starts_with(env!("CARGO_PKG_VERSION")), "{version}");
        assert!(version.contains("features:"));
    }

    #[test]
    fn requested_is_true_only_without_a_subcommand() {
        assert!(requested(["--features"]));
        assert!(requested(["--quiet", "--features"]));
        assert!(!requested(["--features", "engine"]));
        assert!(!requested(["engine", "eval", "--features"]));
        assert!(!requested(["--help"]));
        assert!(!requested(Vec::<&str>::new()));
    }
}
