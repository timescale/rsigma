//! Layer resolution: fold compiled defaults, config files, environment
//! variables, and (in the command-wiring phase) CLI flags into one effective
//! configuration, tracking which layer supplied each value.
//!
//! The merge is a generic JSON deep-merge so it needs no per-field table: each
//! layer is serialized to a `serde_json::Value`, higher layers override lower
//! ones key-by-key, and the winning layer for each leaf is recovered by
//! probing the layers top-down.
//!
//! ## Environment layer
//!
//! Non-secret settings can be supplied with a uniform `RSIGMA_*` scheme using
//! `__` as the nesting separator (single `_` stays inside a key), e.g.
//! `RSIGMA_DAEMON__API__ADDR`, `RSIGMA_DAEMON__INPUT__BUFFER_SIZE`,
//! `RSIGMA_GLOBAL__LOG_FORMAT`. Values are parsed as YAML scalars so types
//! (ints, bools, lists) coerce naturally. The legacy clap `env=` names
//! (`NATS_*`, `RSIGMA_CONSUMER_GROUP`, `RSIGMA_TLS_KEY_PASSWORD`) lack the `__`
//! separator and are intentionally ignored here; they continue to work at the
//! flag layer. Secrets are never read into the config tree.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

use super::schema::{Merge, RsigmaConfigPartial};

/// Which layer supplied a resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Source {
    Default,
    File,
    Env,
    /// A CLI flag. Serialized and displayed as `flag` so JSON and text agree.
    #[serde(rename = "flag")]
    Cli,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Env => "env",
            Source::Cli => "flag",
        };
        f.write_str(s)
    }
}

/// Read the uniform `RSIGMA_*__*` environment variables into a partial.
pub(crate) fn env_partial() -> RsigmaConfigPartial {
    env_partial_from(std::env::vars())
}

fn env_partial_from<I>(vars: I) -> RsigmaConfigPartial
where
    I: IntoIterator<Item = (String, String)>,
{
    // Deserialize each variable into its own single-key partial and fold them
    // together, so one malformed variable is skipped with a warning rather
    // than dropping the whole environment layer.
    let mut acc = RsigmaConfigPartial::default();
    for (key, raw) in vars {
        let Some(rest) = key.strip_prefix("RSIGMA_") else {
            continue;
        };
        // Require the `__` nesting separator so legacy single-underscore env
        // names (RSIGMA_CONSUMER_GROUP, RSIGMA_TLS_KEY_PASSWORD) are ignored.
        if !rest.contains("__") {
            continue;
        }
        let path: Vec<String> = rest.split("__").map(|s| s.to_ascii_lowercase()).collect();
        // Parse the value as a YAML scalar so ints/bools/lists coerce.
        let scalar: Value = yaml_serde::from_str(&raw).unwrap_or(Value::String(raw));
        let mut obj = Map::new();
        insert_nested(&mut obj, &path, scalar);
        match serde_json::from_value::<RsigmaConfigPartial>(Value::Object(obj)) {
            Ok(partial) => acc = acc.merge(partial),
            Err(e) => eprintln!("warning: ignoring environment variable {key}: {e}"),
        }
    }
    acc
}

fn insert_nested(obj: &mut Map<String, Value>, path: &[String], value: Value) {
    match path {
        [] => {}
        [leaf] => {
            obj.insert(leaf.clone(), value);
        }
        [head, tail @ ..] => {
            let entry = obj
                .entry(head.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(child) = entry {
                insert_nested(child, tail, value);
            }
        }
    }
}

/// Serialize a partial to JSON (null/None leaves are skipped by the schema).
pub(crate) fn to_value(partial: &RsigmaConfigPartial) -> Value {
    serde_json::to_value(partial).unwrap_or(Value::Null)
}

/// Deep-merge `over` onto `base`: objects merge key-by-key, everything else
/// (scalars, arrays) is replaced wholesale by `over`.
pub(crate) fn deep_merge(base: Value, over: Value) -> Value {
    match (base, over) {
        // An absent layer (Null) is a no-op rather than wiping the base.
        (base, Value::Null) => base,
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = match b.remove(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => v,
                };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        (_, over) => over,
    }
}

/// Return true if `root` has a non-null leaf at the dotted `path`.
fn leaf_present(root: &Value, path: &str) -> bool {
    let mut cur = root;
    for segment in path.split('.') {
        match cur {
            Value::Object(map) => match map.get(segment) {
                Some(next) => cur = next,
                None => return false,
            },
            _ => return false,
        }
    }
    !cur.is_null()
}

/// Get the value at the dotted `path`, if present.
pub(crate) fn value_at<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for segment in path.split('.') {
        match cur {
            Value::Object(map) => cur = map.get(segment)?,
            _ => return None,
        }
    }
    Some(cur)
}

/// Collect every leaf path in `value`, joined with `.`. Arrays are leaves.
fn walk_leaves(value: &Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk_leaves(v, &path, out);
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.push(prefix.to_string());
            }
        }
    }
}

/// The fully resolved effective config plus the source of each leaf.
pub(crate) struct Resolved {
    /// The merged effective config tree.
    pub merged: Value,
    /// Source of each leaf path, sorted by path.
    pub sources: BTreeMap<String, Source>,
}

/// Resolve all layers. Pass `Value::Null` for layers that do not apply (e.g.
/// the flag layer is `Null` for `config show`).
pub(crate) fn resolve_layers(
    default_v: Value,
    file_v: Value,
    env_v: Value,
    flag_v: Value,
) -> Resolved {
    let merged = deep_merge(
        deep_merge(deep_merge(default_v.clone(), file_v.clone()), env_v.clone()),
        flag_v.clone(),
    );

    let mut leaves = Vec::new();
    walk_leaves(&merged, "", &mut leaves);

    let mut sources = BTreeMap::new();
    for path in leaves {
        let source = if leaf_present(&flag_v, &path) {
            Source::Cli
        } else if leaf_present(&env_v, &path) {
            Source::Env
        } else if leaf_present(&file_v, &path) {
            Source::File
        } else {
            Source::Default
        };
        sources.insert(path, source);
    }

    Resolved { merged, sources }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parses_nested_and_coerces_scalars() {
        let vars = vec![
            (
                "RSIGMA_DAEMON__API__ADDR".to_string(),
                "127.0.0.1:7000".to_string(),
            ),
            (
                "RSIGMA_DAEMON__INPUT__BUFFER_SIZE".to_string(),
                "42".to_string(),
            ),
            ("RSIGMA_GLOBAL__LOG_FORMAT".to_string(), "json".to_string()),
            // legacy single-underscore name is ignored
            ("RSIGMA_CONSUMER_GROUP".to_string(), "x".to_string()),
            // unrelated var ignored
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let p = env_partial_from(vars);
        let daemon = p.daemon.expect("daemon");
        assert_eq!(daemon.api.expect("api").addr, Some("127.0.0.1:7000".into()));
        assert_eq!(daemon.input.expect("input").buffer_size, Some(42));
        assert_eq!(p.global.expect("global").log_format, Some("json".into()));
    }

    #[test]
    fn env_skips_only_the_malformed_var() {
        let vars = vec![
            (
                "RSIGMA_DAEMON__API__ADDR".to_string(),
                "127.0.0.1:7000".to_string(),
            ),
            // Bad: a scalar where the schema wants a list. Must not drop the
            // sibling api.addr value.
            (
                "RSIGMA_DAEMON__OUTPUT__SINKS".to_string(),
                "not-a-list".to_string(),
            ),
        ];
        let p = env_partial_from(vars);
        assert_eq!(
            p.daemon.expect("daemon").api.expect("api").addr,
            Some("127.0.0.1:7000".into())
        );
    }

    #[test]
    fn source_precedence_flag_over_env_over_file_over_default() {
        let default_v = serde_json::json!({"daemon": {"api": {"addr": "0.0.0.0:9090"}, "input": {"batch_size": 1}}});
        let file_v = serde_json::json!({"daemon": {"api": {"addr": "1.1.1.1:1"}}});
        let env_v = serde_json::json!({"daemon": {"input": {"batch_size": 5}}});
        let flag_v = serde_json::json!({"daemon": {"api": {"addr": "2.2.2.2:2"}}});

        let resolved = resolve_layers(default_v, file_v, env_v, flag_v);
        assert_eq!(resolved.sources["daemon.api.addr"], Source::Cli);
        assert_eq!(resolved.sources["daemon.input.batch_size"], Source::Env);
        assert_eq!(
            value_at(&resolved.merged, "daemon.api.addr").and_then(|v| v.as_str()),
            Some("2.2.2.2:2")
        );
    }

    #[test]
    fn file_wins_over_default_when_no_env_or_flag() {
        let default_v = serde_json::json!({"global": {"log_format": "text"}});
        let file_v = serde_json::json!({"global": {"log_format": "json"}});
        let resolved = resolve_layers(default_v, file_v, Value::Null, Value::Null);
        assert_eq!(resolved.sources["global.log_format"], Source::File);
    }
}
