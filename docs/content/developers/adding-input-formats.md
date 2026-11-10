---
description: "How to add an event input format to the RSigma streaming runtime: write a line parser adapter, wire it into the CLI, and gate it behind a feature flag."
---

# Adding an input format

The streaming runtime accepts events as raw text lines and dispatches them through `parse_line(line, format) -> Option<EventInputDecoded>`. Each variant of `InputFormat` corresponds to one adapter under `crates/rsigma-runtime/src/input/`. This page walks through adding a new one (a binary protocol, a vendor-specific log shape, a new structured-text format), wiring it into the CLI, and gating it behind a feature flag.

EVTX is not an `InputFormat` line parser: `EvtxFileReader` reads binary `.evtx` files and bypasses `parse_line`. Binary or file-oriented formats may need a similar dedicated reader path rather than a new `InputFormat` variant.

## Pick the right `EventInputDecoded` shape

`EventInputDecoded` is a three-arm enum that wraps a typed event payload:

| Variant | Backing type | Use when... |
|---------|--------------|-------------|
| `Json` | `rsigma_eval::JsonEvent` | The format maps cleanly onto a JSON object (CEF extensions, key/value with nested structure, GELF). |
| `Kv` | `rsigma_eval::KvEvent` | The format is a flat `Vec<(String, String)>` of string fields (logfmt, classic key=value lines). |
| `Plain` | `rsigma_eval::PlainEvent` | No structure available; only keyword matching makes sense (raw `/var/log/messages`). |

Pick the shape that minimizes copies. If your format already produces a `serde_json::Value`, use `Json` and bypass the conversion cost. If it produces a flat keyed string list, use `Kv` and the engine consumes it directly.

If you need a fourth shape (a structured non-JSON tree, a typed proto message), open an issue first; adding a new `EventInputDecoded` variant changes every match arm in this module.

## Walkthrough: adding `Lecf` (a hypothetical vendor format)

Step 1: scaffold the adapter module.

```text
crates/rsigma-runtime/src/input/
├── auto.rs
├── cef.rs
├── evtx.rs
├── json.rs
├── lecf.rs        ← new
├── logfmt.rs
├── mod.rs         ← register the new module here
├── plain.rs
└── syslog.rs
```

Step 2: write the parser. Convention: one public function `parse_<format>(line: &str) -> Option<EventInputDecoded>`. Return `None` if the line cannot be parsed as your format.

```rust
// crates/rsigma-runtime/src/input/lecf.rs
use rsigma_eval::JsonEvent;
use serde_json::Value;
use crate::input::EventInputDecoded;

pub fn parse_lecf(line: &str) -> Option<EventInputDecoded> {
    if !line.starts_with("LECF:") {
        return None;
    }
    let body = line.strip_prefix("LECF:")?.trim();

    let mut map = serde_json::Map::new();
    for pair in body.split('|') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            map.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        }
    }

    let value = Value::Object(map);
    Some(EventInputDecoded::Json(JsonEvent::owned(value)))
}
```

Keep the parser allocation-light on the happy path. CEF and logfmt are the existing high-throughput references; their parsers do not clone the input line.

Step 3: register the module and re-export the public parser.

```rust
// crates/rsigma-runtime/src/input/mod.rs

#[cfg(feature = "lecf")]
mod lecf;

#[cfg(feature = "lecf")]
pub use self::lecf::parse_lecf;
```

Step 4: extend the `InputFormat` enum.

```rust
pub enum InputFormat {
    Auto(SyslogConfig),
    Json,
    Syslog(SyslogConfig),
    Plain,
    #[cfg(feature = "logfmt")]
    Logfmt,
    #[cfg(feature = "cef")]
    Cef,
    #[cfg(feature = "lecf")]
    Lecf,                    // ← add
}
```

Step 5: extend the `parse_line` dispatch.

```rust
pub fn parse_line(line: &str, format: &InputFormat) -> Option<EventInputDecoded> {
    if line.trim().is_empty() {
        return None;
    }
    Some(match format {
        InputFormat::Auto(c) => auto_detect(line, c),
        InputFormat::Json => parse_json(line)?,
        InputFormat::Syslog(c) => parse_syslog(line, c),
        InputFormat::Plain => parse_plain(line),
        #[cfg(feature = "logfmt")]
        InputFormat::Logfmt => parse_logfmt(line),
        #[cfg(feature = "cef")]
        InputFormat::Cef => parse_cef(line)?,
        #[cfg(feature = "lecf")]
        InputFormat::Lecf => parse_lecf(line)?,    // ← add
    })
}
```

Step 6: optionally extend `auto_detect` so users on `--input-format auto` (the default) hit your format. Keep it cheap: a single byte or prefix check before the more expensive JSON parse. If your format does not have a cheap fingerprint, do not add it to auto; ship it as an explicit `--input-format <name>` opt-in.

`--input` selects the event source URL/mode (stdin, HTTP, NATS, and on Unix a unix-domain socket). `--input-format` selects the line parser. Do not conflate the two flags.

## Gate it behind a feature

In `crates/rsigma-runtime/Cargo.toml`:

```toml
[features]
lecf = []   # zero new deps, just unlocks the parser
```

If your parser pulls in a new crate, add it as an optional dependency and list it after the `=` sign:

```toml
[dependencies]
lecf-parser = { version = "0.3", optional = true }

[features]
lecf = ["dep:lecf-parser"]
```

Then in `crates/rsigma-cli/Cargo.toml`, add a **separate** CLI feature that forwards to the runtime feature. Do not stuff line-format features into the `daemon` feature:

```toml
[features]
default = []
daemon = ["rsigma-runtime", /* … daemon deps … */]
logfmt = ["rsigma-runtime/logfmt"]
cef = ["rsigma-runtime/cef"]
lecf = ["rsigma-runtime/lecf"]
```

The Docker image and release archives are built with `--all-features`; opt-in users that build from source can keep their binary lean by omitting the feature.

## Wire it into the CLI

The `--input-format` flag is parsed in `crates/rsigma-cli/src/commands/daemon.rs` (via `parse_input_format`). The current value-parser already accepts strings; add a `"lecf"` arm in the match that turns the string into an `InputFormat`. The existing `"cef"` and `"logfmt"` arms follow the same pattern. Mirror the same flag on `engine eval` and `rule backtest` if those commands should accept the format too.

## Test it

Three test layers:

1. **Unit tests** in `crates/rsigma-runtime/src/input/lecf.rs`:

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use rsigma_eval::{Event, EventValue};

       #[test]
       fn parses_basic_lecf() {
           let evt = parse_lecf("LECF: host=server1|action=denied").unwrap();
           let EventInputDecoded::Json(e) = evt else { panic!() };
           assert_eq!(e.get_field("host"), Some(EventValue::Str("server1".into())));
       }

       #[test]
       fn rejects_non_lecf() {
           assert!(parse_lecf("just some text").is_none());
       }
   }
   ```

2. **Integration test** in `crates/rsigma-runtime/tests/`:

   ```rust
   #[cfg(feature = "lecf")]
   #[test]
   fn lecf_end_to_end_match() {
       // build a tiny RuntimeEngine, parse_line with InputFormat::Lecf,
       // assert a rule matches.
   }
   ```

3. **Fuzz harness.** Add `fuzz/fuzz_targets/fuzz_lecf.rs` mirroring the existing `fuzz_input_formats.rs`; register it in `fuzz/Cargo.toml` and `.github/workflows/fuzz.yml`. See [Fuzzing](fuzzing.md).

## Document it

Three places:

1. **User guide** at `docs/content/guide/input-formats.md`. Add a section with the format description, a sample input line, and any caveats.
2. **CLI reference** at `docs/content/cli/engine/daemon.md` (the `--input-format` flag accepts a new value).
3. **Feature flags reference** at `docs/content/reference/feature-flags.md`. Add `lecf` to the `rsigma-runtime` and `rsigma-cli` rows.

## Checklist

- [ ] `crates/rsigma-runtime/src/input/<name>.rs` adapter module.
- [ ] Module registered and (if applicable) public parser re-exported from `input/mod.rs`.
- [ ] `InputFormat::<Name>` variant added (feature-gated if optional).
- [ ] `parse_line` dispatch extended.
- [ ] `auto_detect` extended (only if your format has a cheap fingerprint).
- [ ] Feature flag added to `rsigma-runtime/Cargo.toml` and a separate passthrough feature in `rsigma-cli` (not folded into `daemon`).
- [ ] CLI `--input-format` value-parser extended.
- [ ] Unit + integration tests in `rsigma-runtime`.
- [ ] Fuzz harness for the new parser (if it ingests untrusted bytes).
- [ ] Guide, CLI reference, and feature-flags reference updated.
- [ ] CHANGELOG entry.

## See also

- [`rsigma-runtime` input/mod.rs](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/src/input/mod.rs) for the existing adapters as reference.
- [Input Formats guide](../guide/input-formats.md) for the user-facing description.
- [Fuzzing](fuzzing.md) for the harness conventions.
