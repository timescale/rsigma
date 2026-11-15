//! Errors raised while resolving a named ruleset.

use std::path::PathBuf;

use thiserror::Error;

/// A failure while resolving a ruleset. Every variant maps to a configuration
/// error (exit 3) at the CLI, except source parse errors, which follow each
/// command's existing policy.
///
/// Errors returned by [`resolve_ruleset`](super::resolve_ruleset) and
/// [`resolve_loaded`](super::resolve_loaded) name the ruleset exactly once at
/// the start of their message. The list variants carry messages that are
/// already prefixed; the path variants carry the ruleset name in `ruleset`,
/// which is `None` only when they come straight from
/// [`load_sources`](super::load_sources) or an [`OverlayLoader`](super::OverlayLoader).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RulesetError {
    /// The spec failed static validation; one message per problem.
    #[error("{}", .0.join("; "))]
    InvalidSpec(Vec<String>),
    /// A declared source does not exist.
    #[error("{}source path does not exist: {}", prefix(ruleset), path.display())]
    MissingSource {
        /// The ruleset, once known.
        ruleset: Option<String>,
        /// The missing source.
        path: PathBuf,
    },
    /// A source or overlay file could not be read.
    #[error("{}cannot read {}: {source}", prefix(ruleset), path.display())]
    Io {
        /// The ruleset, once known.
        ruleset: Option<String>,
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A path resolved outside [`ResolveOptions::confine_to`](super::ResolveOptions::confine_to).
    #[error("{}path escapes the confined root: {}", prefix(ruleset), path.display())]
    Confinement {
        /// The ruleset, once known.
        ruleset: Option<String>,
        /// The offending path.
        path: PathBuf,
    },
    /// A selector could not be compiled.
    #[error("{0}")]
    Selector(String),
    /// Correlation references that do not resolve under the policy.
    #[error("{}", .0.join("; "))]
    Dependency(Vec<String>),
    /// Two kept documents share an id or name.
    #[error("{0}")]
    Duplicate(String),
    /// An overlay could not be loaded or applied.
    #[error("{0}")]
    Overlay(String),
    /// Overlays that match no kept document under `stale_overlays: error`.
    #[error("{}", .0.join("; "))]
    StaleOverlay(Vec<String>),
}

fn prefix(ruleset: &Option<String>) -> String {
    ruleset
        .as_deref()
        .map(|name| format!("ruleset '{name}': "))
        .unwrap_or_default()
}

impl RulesetError {
    /// Attach the ruleset name to a variant that does not carry it yet,
    /// keeping the variant itself.
    pub(crate) fn named(self, name: &str) -> Self {
        let label = format!("ruleset '{name}'");
        let prefixed = |message: String| {
            if message.starts_with(&label) {
                message
            } else {
                format!("{label}: {message}")
            }
        };
        match self {
            Self::MissingSource {
                ruleset: None,
                path,
            } => Self::MissingSource {
                ruleset: Some(name.to_string()),
                path,
            },
            Self::Io {
                ruleset: None,
                path,
                source,
            } => Self::Io {
                ruleset: Some(name.to_string()),
                path,
                source,
            },
            Self::Confinement {
                ruleset: None,
                path,
            } => Self::Confinement {
                ruleset: Some(name.to_string()),
                path,
            },
            Self::Selector(message) => Self::Selector(prefixed(message)),
            Self::Duplicate(message) => Self::Duplicate(prefixed(message)),
            Self::Overlay(message) => Self::Overlay(prefixed(message)),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keeps_the_variant_and_prefixes_once() {
        let error = RulesetError::MissingSource {
            ruleset: None,
            path: PathBuf::from("./nope"),
        }
        .named("edge");
        assert!(
            matches!(&error, RulesetError::MissingSource { ruleset: Some(name), .. } if name == "edge"),
            "{error:?}"
        );
        let expected = "ruleset 'edge': source path does not exist: ./nope";
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.named("edge").to_string(), expected);

        let overlay = RulesetError::Overlay("ruleset 'edge': bad".into()).named("edge");
        assert_eq!(overlay.to_string(), "ruleset 'edge': bad");
        let selector = RulesetError::Selector("unknown level 'huge'".into()).named("edge");
        assert_eq!(selector.to_string(), "ruleset 'edge': unknown level 'huge'");
    }
}
