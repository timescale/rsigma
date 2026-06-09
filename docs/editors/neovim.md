# Neovim, Helix, Zed

Any editor that speaks the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) can drive `rsigma-lsp`. This page covers the three you are most likely to use; the same pattern works for Emacs, Sublime Text, Kakoune, and anything else with an LSP client.

The capability matrix is the same as the [VS Code](vscode.md) extension: diagnostics, code actions, completions, hover, and document symbols. Differences are about how each editor surfaces them.

## Prerequisites

Install the server. Either:

```bash
cargo install rsigma-lsp
```

or pick `rsigma-lsp` out of the [release archive](../getting-started/installation.md) (it ships alongside the `rsigma` CLI). Confirm it is on your `$PATH`:

```bash
rsigma-lsp --version
```

## Neovim

The native LSP client lands you with the smallest setup. Drop this in your config (works as-is in Lua, no plugin manager required):

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = 'yaml',
  callback = function()
    vim.lsp.start({
      name = 'rsigma-lsp',
      cmd = { 'rsigma-lsp' },
      root_dir = vim.fs.dirname(vim.fs.find({ '.rsigma-lint.yml', '.git' }, { upward = true })[1]),
    })
  end,
})
```

Restart Neovim, open a `.yml` Sigma rule, and `:LspInfo` should show `rsigma-lsp` attached.

### With `nvim-lspconfig`

If you use [`nvim-lspconfig`](https://github.com/neovim/nvim-lspconfig), there is no upstream config yet; add one inline:

```lua
local configs = require('lspconfig.configs')

if not configs.rsigma then
  configs.rsigma = {
    default_config = {
      cmd = { 'rsigma-lsp' },
      filetypes = { 'yaml' },
      root_dir = require('lspconfig.util').root_pattern('.rsigma-lint.yml', '.git'),
      settings = {},
    },
  }
end

require('lspconfig').rsigma.setup({})
```

### Coexisting with `yaml-language-server`

If you also run [`yaml-language-server`](https://github.com/redhat-developer/yaml-language-server) for generic YAML support, both servers attach to the same buffer. That is fine, but you will see duplicate diagnostics for keys that the YAML schema does not know about. Two ways to silence the noise:

```lua
require('lspconfig').yamlls.setup({
  settings = {
    yaml = {
      validate = false,
      customTags = { '!!python/name' },
    },
  },
})
```

Or only attach `yaml-language-server` outside Sigma directories:

```lua
require('lspconfig').yamlls.setup({
  root_dir = function(fname)
    if fname:match('/rules/') or fname:match('%.sigma%.yml$') then
      return nil
    end
    return require('lspconfig.util').root_pattern('.git')(fname)
  end,
})
```

### Code actions and quick-fixes

Default bindings differ per distro; the canonical mapping is `vim.lsp.buf.code_action()`. In Lazyvim / Astrovim, `<leader>ca` is the standard. The 13 fixable rules from the [Lint Rules reference](../reference/lint-rules.md) all surface as `quickfix`-kind actions marked `isPreferred`.

## Helix

Helix has built-in LSP support; just register the server:

```toml
# ~/.config/helix/languages.toml

[language-server.rsigma-lsp]
command = "rsigma-lsp"

[[language]]
name = "yaml"
language-servers = ["yaml-language-server", "rsigma-lsp"]
```

Listing `yaml-language-server` first means generic YAML diagnostics come first in the picker; remove it if you want `rsigma-lsp` to be the only voice on Sigma files. The Helix code-action picker (`<space>a` by default) lists rsigma fixes alongside any other LSP's.

## Zed

Zed shipped LSP-from-config support in [v0.150](https://zed.dev/blog/zed-decoded-language-extensions). Add the server in your `settings.json`:

```json
{
  "lsp": {
    "rsigma": {
      "binary": {
        "path": "rsigma-lsp"
      }
    }
  },
  "languages": {
    "YAML": {
      "language_servers": ["yaml-language-server", "rsigma"]
    }
  }
}
```

There is no Zed extension package yet; the inline config above is the supported path. If you build one, point it at this page and we will link back.

## Emacs (`eglot`)

```elisp
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
               '(yaml-mode . ("rsigma-lsp"))))
```

`lsp-mode` users can register the same with `lsp-register-client`; the API surface is the same as any other LSP.

## Sublime Text (`LSP` package)

In `Preferences -> Package Settings -> LSP -> Settings`:

```json
{
  "clients": {
    "rsigma-lsp": {
      "enabled": true,
      "command": ["rsigma-lsp"],
      "selector": "source.yaml"
    }
  }
}
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Server not attaching. | Check the editor's LSP log (`:LspLog` in Neovim, `~/.cache/helix/helix.log` in Helix, `Cmd+Shift+P -> zed: open log` in Zed). |
| `rsigma-lsp: command not found`. | Server binary not on `$PATH`. Use an absolute path in your editor config. |
| The server crashes on a specific rule. | Run `RUST_LOG=rsigma_lsp=debug rsigma-lsp` from the same shell your editor inherits, reproduce, attach the log to a bug report. |
| Stale diagnostics after editing `.rsigma-lint.yml`. | Close and reopen the buffer. The server caches config per document. |

## See also

- [`rsigma-lsp` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-lsp/README.md) for the full protocol-level capability list (sync mode, debounce, completion contexts, hover sources, document-symbol shape).
- [Lint Rules reference](../reference/lint-rules.md) for the catalogue of {{ rsigma.lint.rules }} lint rules and which ones have safe auto-fixes.
- [VS Code and Cursor](vscode.md) for the equivalent setup with the wrapping extension.
