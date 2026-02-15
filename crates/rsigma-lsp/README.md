# rsigma-lsp

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-lsp` is a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) (LSP) server that brings real-time [Sigma](https://github.com/SigmaHQ/sigma) rule development support to any editor — VSCode, Neovim, Helix, Zed, Emacs, and more. Built on the same parser, linter, and compiler as the CLI.

This binary is part of [rsigma].

## Installation

```bash
cargo install --path crates/rsigma-lsp
```

## Features

- **Diagnostics**: real-time validation from three layers — 64 lint rules (Sigma spec v2.1.0) with four severity levels (Error/Warning/Info/Hint), parser errors (YAML and condition expressions), and compiler errors (unknown selections, invalid modifier combos). Loads `.rsigma-lint.yml` config and respects inline `# rsigma-disable` comments. Debounced at 150ms for responsive editing
- **Completions**: context-aware suggestions for field modifiers (`|contains`, `|base64`, etc.), top-level keys, status/level enums, logsource category/product/service values, detection keys, MITRE ATT&CK tags, condition keywords, and selection names from the current rule. Triggers on `|`, `:`, ` `, and newline
- **Hover**: documentation for all 27 field modifiers and MITRE ATT&CK tactics/techniques with links
- **Document symbols**: navigable outline of rule structure (title, logsource, correlation, detection with child selections)

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

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
