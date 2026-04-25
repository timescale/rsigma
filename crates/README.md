# crates

This directory contains `rsigma`'s various crates.

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`][rsigma-parser-dir] | Parser for Sigma detection rules, correlations, and filters. |
| [`rsigma-eval`][rsigma-eval-dir] | Evaluator for Sigma detection rules that matches rules against events. |
| [`rsigma-convert`][rsigma-convert-dir] | Conversion engine that transforms rules into backend-native query strings. |
| [`rsigma-runtime`][rsigma-runtime-dir] | Streaming runtime with input adapters, log processor, and hot-reload. |
| [`rsigma`][rsigma-cli-dir] | CLI for parsing, validating, evaluating, converting rules, and running a detection daemon. |
| [`rsigma-lsp`][rsigma-lsp-dir] | Language Server Protocol (LSP) server for Sigma detection rules. |

[rsigma-parser-dir]: ./rsigma-parser
[rsigma-eval-dir]: ./rsigma-eval
[rsigma-convert-dir]: ./rsigma-convert
[rsigma-runtime-dir]: ./rsigma-runtime
[rsigma-cli-dir]: ./rsigma-cli
[rsigma-lsp-dir]: ./rsigma-lsp
