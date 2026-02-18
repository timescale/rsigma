# rsigma-lsp

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-lsp` is a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) (LSP) server that brings real-time [Sigma](https://github.com/SigmaHQ/sigma) rule development support to any editor — VSCode, Neovim, Helix, Zed, Emacs, and more. Built on the same parser, linter, and compiler as the CLI.

This binary is part of [rsigma].

## Installation

```bash
cargo install --path crates/rsigma-lsp
```

## LSP Capabilities

| Capability | Details |
|------------|---------|
| Text document sync | Full (entire document on every change) |
| Diagnostics | Lint (65 rules), parse errors, compile errors |
| Code actions | Quick-fix actions for auto-fixable lint warnings |
| Completions | Context-aware; trigger characters: `\|`, `:`, ` `, `\n` |
| Hover | Field modifiers, MITRE ATT&CK tactics and techniques |
| Document symbols | Hierarchical outline of rule structure |

## Diagnostics

Diagnostics run through three layers, each adding errors from a different stage:

### Layer 1 — Lint

Runs all 65 lint rules from `rsigma-parser` (Sigma spec v2.1.0). Loads `.rsigma-lint.yml` config from ancestor directories and respects inline `# rsigma-disable` comments.

| Lint severity | LSP severity |
|---------------|-------------|
| Error | `DiagnosticSeverity::ERROR` |
| Warning | `DiagnosticSeverity::WARNING` |
| Info | `DiagnosticSeverity::INFORMATION` |
| Hint | `DiagnosticSeverity::HINT` |

Diagnostic `code`: the lint rule name (e.g. `missing_title`, `invalid_level`).

### Layer 2 — Parse errors

YAML and condition expression parse failures from `rsigma-parser`.

| | |
|-|-|
| Severity | `ERROR` |
| Code | `parse_error` |
| Range | Extracted from `"at line X column Y"` in the error message, or falls back to the first content line |

### Layer 3 — Compile errors

Per-rule compilation errors from `rsigma-eval` (unknown selections, invalid modifier combos).

| | |
|-|-|
| Severity | `ERROR` |
| Code | `compile_error` |
| Range | For `"unknown detection identifier: X"`, highlights `X` in the `condition:` line; otherwise falls back to `/detection/condition` |

All diagnostics have `source: "rsigma"`.

### Timing

| Event | Behavior |
|-------|----------|
| Document open | Diagnostics run immediately |
| Document change | Diagnostics debounced at **150 ms** |
| Document save | Diagnostics run immediately |
| Document close | Pending diagnostics aborted; existing diagnostics cleared |

## Code Actions

Quick-fix code actions for lint warnings with auto-fix suggestions. When the cursor is on a diagnostic that has a safe fix, the editor offers a one-click action to apply it.

| Fixable rule | Action |
|--------------|--------|
| `non_lowercase_key` | Rename key to lowercase |
| `logsource_value_not_lowercase` | Lowercase the value |
| `invalid_status` | Replace with closest valid status |
| `invalid_level` | Replace with closest valid level |
| `unknown_key` | Rename to closest known key (typo correction) |
| `duplicate_tags` | Remove duplicate tag entry |
| `duplicate_references` | Remove duplicate reference entry |
| `duplicate_fields` | Remove duplicate field entry |
| `all_with_re` | Remove redundant `\|all` modifier |
| `single_value_all_modifier` | Remove redundant `\|all` modifier |
| `wildcard_only_value` | Replace with `\|exists: true` |
| `filter_has_level` / `filter_has_status` | Remove the field |

All code actions are marked as `quickfix` with `isPreferred: true`. Only `Safe` disposition fixes are offered.

## Completions

Context-aware completions triggered by `|`, `:`, ` ` (space), and newline. Contexts are evaluated in priority order:

### 1. Modifier completions

**Trigger:** `|` character in the current line.

Offers all 25 field modifiers matching the typed prefix, with descriptions. Completion kind: `ENUM_MEMBER`.

### 2. Tag completions

**Trigger:** Inside the `tags` section, on a line starting with `- `.

Offers all 14 MITRE ATT&CK tactic tags (`attack.initial_access`, `attack.execution`, ...) plus extra tags:

- `cve.`
- `detection.dfir`
- `detection.emerging_threats`
- `detection.threat_hunting`
- `tlp.white`, `tlp.green`, `tlp.amber`, `tlp.red`

Completion kind: `VALUE`.

### 3. Condition completions

**Trigger:** Line starts with `condition:` or cursor is within the `condition` section.

Offers:
- **Selection names** extracted from the current rule's `detection` section (kind: `VARIABLE`)
- **Condition keywords**: `and`, `or`, `not`, `1 of`, `all of`, `1 of them`, `all of them` (kind: `KEYWORD`)

### 4. Value completions

**Trigger:** After `:` for known keys.

| Key | Offered values |
|-----|----------------|
| `status` | `stable`, `test`, `experimental`, `deprecated`, `unsupported` |
| `level` | `informational`, `low`, `medium`, `high`, `critical` |
| `product` | `windows`, `linux`, `macos`, `aws`, `azure`, `gcp`, `m365`, `okta`, `github` |
| `category` | 27 values (`process_creation`, `file_event`, `network_connection`, `image_load`, `registry_event`, `dns_query`, `file_access`, `file_change`, `file_delete`, `file_rename`, `driver_load`, `pipe_created`, `process_access`, `process_tampering`, `process_termination`, `ps_classic_start`, `ps_module`, `ps_script`, `registry_add`, `registry_delete`, `registry_set`, `sysmon_error`, `sysmon_status`, `wmi_event`, `clipboard_capture`, `create_remote_thread`, `create_stream_hash`) |
| `service` | 20 values (`sysmon`, `security`, `system`, `powershell`, `powershell-classic`, `taskscheduler`, `wmi`, `application`, `dns-server`, `driver-framework`, `firewall-as`, `ldap_debug`, `msexchange-management`, `ntlm`, `openssh`, `printservice-admin`, `printservice-operational`, `smbclient-security`, `terminalservices-localsessionmanager`, `windefend`) |

Completion kind: `ENUM_MEMBER`.

### 5. Top-level key completions

**Trigger:** Indent level 0, no `:` on the line.

Offers all 17 top-level keys with snippet placeholders: `title`, `id`, `related`, `status`, `description`, `references`, `author`, `date`, `modified`, `tags`, `logsource`, `detection`, `falsepositives`, `level`, `fields`, `correlation`, `filter`.

Completion kind: `PROPERTY`. Insert format: `SNIPPET` (with `$0`, `$1`, etc.).

### 6. Logsource sub-key completions

**Trigger:** Inside `logsource` section, indent > 0, no `:`.

Offers: `category`, `product`, `service`, `definition`.

### 7. Detection sub-key completions

**Trigger:** Inside `detection` section, indent > 0, no `:`.

Offers: `selection`, `filter`, `condition`.

## Hover

Hover provides documentation at the cursor position. The server checks (in priority order):

### MITRE ATT&CK techniques

Pattern: `attack.t*` (e.g. `attack.t1059`, `attack.t1059.001`).

Shows technique ID as a heading with a link to `https://attack.mitre.org/techniques/{id}`.

### MITRE ATT&CK tactics

Any of the 14 tactic names (e.g. `attack.execution`, `attack.persistence`).

Shows the tactic description.

### Field modifiers

Any of the 25 modifier names (e.g. `contains`, `base64`, `windash`).

Shows the modifier name and description in Markdown.

## Document Symbols

Provides a hierarchical outline of the rule structure:

| Symbol | Kind | Condition |
|--------|------|-----------|
| `title` | `STRING` | When present |
| `logsource` | `NAMESPACE` | When present |
| `correlation` | `NAMESPACE` | When present |
| `detection` | `NAMESPACE` | When present; includes child symbols |

### Detection children

Child keys within `detection` at the first indented level:

| Key | Kind |
|-----|------|
| `condition` | `BOOLEAN` |
| Other keys (selections) | `FIELD` |

Each child has a `range` (full section) and `selection_range` (key line only).

## Document Lifecycle

| Event | Behavior |
|-------|----------|
| `textDocument/didOpen` | If `.yml`/`.yaml`: run diagnostics immediately, store document |
| `textDocument/didChange` | Full sync (entire document replaced). If Sigma file: schedule debounced diagnostics (150 ms) |
| `textDocument/didSave` | If Sigma file: run diagnostics immediately (no debounce) |
| `textDocument/didClose` | Abort pending diagnostics, remove document, publish empty diagnostics to clear |

Only `.yml` and `.yaml` files trigger diagnostics. Non-Sigma files are stored for document state but produce no diagnostics.

## Error Recovery

All handler functions (`completion`, `hover`, `document_symbol`, diagnostics) are wrapped in `catch_unwind`. On panic:

- An error is logged.
- Completions return empty; hover returns `None`; symbols return empty; diagnostics return empty.
- The server continues operating.

If a document URI is not found in the store, handlers return `None` or empty results.

## Editor Setup

### Neovim (native LSP)

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = 'yaml',
  callback = function()
    vim.lsp.start({
      name = 'rsigma-lsp',
      cmd = { 'rsigma-lsp' },
    })
  end,
})
```

### VSCode / Cursor

A thin extension wrapper is provided in [`editors/vscode/`](../../editors/vscode/). To use it:

```bash
cd editors/vscode
npm install
npm run package              # builds with esbuild + creates .vsix
code --install-extension rsigma-0.1.0.vsix    # VSCode
cursor --install-extension rsigma-0.1.0.vsix  # Cursor
```

The extension launches `rsigma-lsp` from your `$PATH` by default. Override via the `rsigma.serverPath` setting.

### Helix (`~/.config/helix/languages.toml`)

```toml
[language-server.rsigma-lsp]
command = "rsigma-lsp"

[[language]]
name = "yaml"
language-servers = ["yaml-language-server", "rsigma-lsp"]
```

## Debugging

Set the `RUST_LOG` environment variable to enable logging:

```bash
RUST_LOG=rsigma_lsp=debug rsigma-lsp
```

Log messages include initialization, diagnostics errors, and handler panics.

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
