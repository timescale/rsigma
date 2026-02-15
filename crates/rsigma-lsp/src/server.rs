//! LSP server implementation for Sigma detection rules.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use rsigma_parser::lint::LintConfig;

use crate::completion;
use crate::data;
use crate::diagnostics;

/// Debounce delay for diagnostics on text changes (milliseconds).
const DIAGNOSTICS_DEBOUNCE_MS: u64 = 150;

/// In-memory document state: latest text and version for each open file.
#[derive(Debug, Clone)]
struct DocumentState {
    text: String,
    version: i32,
}

/// The Sigma Language Server.
pub struct SigmaLanguageServer {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, DocumentState>>>,
    /// Abort handles for pending debounced diagnostic tasks.
    pending_diagnostics: Arc<Mutex<HashMap<Url, tokio::task::AbortHandle>>>,
}

impl SigmaLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: Arc::new(RwLock::new(HashMap::new())),
            pending_diagnostics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Load lint config for a document by walking ancestors from the file URI.
    fn load_lint_config(uri: &Url) -> LintConfig {
        if let Ok(path) = uri.to_file_path()
            && let Some(config_path) = LintConfig::find_in_ancestors(&path)
            && let Ok(config) = LintConfig::load(&config_path)
        {
            return config;
        }
        LintConfig::default()
    }

    /// Run diagnostics immediately on a blocking thread and publish results.
    async fn publish_diagnostics_now(&self, uri: &Url, text: &str, version: i32) {
        let text = text.to_string();
        let config = Self::load_lint_config(uri);
        let diags = match tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                diagnostics::diagnose_with_config(&text, &config)
            }))
        })
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => {
                log::error!("panic in diagnostics::diagnose");
                vec![]
            }
            Err(e) => {
                log::error!("diagnostics task error: {e}");
                vec![]
            }
        };
        self.client
            .publish_diagnostics(uri.clone(), diags, Some(version))
            .await;
    }

    /// Schedule diagnostics with debounce. Cancels any pending run for this URI.
    async fn schedule_diagnostics(&self, uri: Url, text: String, version: i32) {
        let client = self.client.clone();
        let pending = self.pending_diagnostics.clone();
        let uri_for_task = uri.clone();
        let config = Self::load_lint_config(&uri);

        // Abort any existing pending task, then spawn the new one while holding
        // the lock so no concurrent call can slip in between.
        let mut guard = self.pending_diagnostics.lock().await;
        if let Some(handle) = guard.remove(&uri) {
            handle.abort();
        }

        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(DIAGNOSTICS_DEBOUNCE_MS)).await;

            let diags = match tokio::task::spawn_blocking(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    diagnostics::diagnose_with_config(&text, &config)
                }))
            })
            .await
            {
                Ok(Ok(d)) => d,
                Ok(Err(_)) => {
                    log::error!("panic in diagnostics::diagnose");
                    vec![]
                }
                Err(_) => return, // task was cancelled
            };

            client
                .publish_diagnostics(uri_for_task.clone(), diags, Some(version))
                .await;

            pending.lock().await.remove(&uri_for_task);
        });

        guard.insert(uri, task.abort_handle());
    }

    /// Check if a URI looks like a Sigma YAML file.
    fn is_sigma_file(uri: &Url) -> bool {
        let path = uri.path();
        path.ends_with(".yml") || path.ends_with(".yaml")
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for SigmaLanguageServer {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                // Full text sync — we get the entire document on every change.
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                // Completions
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec!["|".into(), ":".into(), " ".into(), "\n".into()]),
                    resolve_provider: Some(false),
                    ..Default::default()
                }),
                // Hover
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                // Document symbols
                document_symbol_provider: Some(OneOf::Left(true)),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "rsigma-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        log::info!("rsigma-lsp initialized");
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    // ── Document synchronization ────────────────────────────────────────

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let version = params.text_document.version;

        if Self::is_sigma_file(&uri) {
            self.publish_diagnostics_now(&uri, &text, version).await;
        }

        self.documents
            .write()
            .await
            .insert(uri, DocumentState { text, version });
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = params.text_document.version;

        // FULL sync: the last content change has the full text.
        if let Some(change) = params.content_changes.into_iter().last() {
            let text = change.text;

            if Self::is_sigma_file(&uri) {
                self.schedule_diagnostics(uri.clone(), text.clone(), version)
                    .await;
            }

            self.documents
                .write()
                .await
                .insert(uri, DocumentState { text, version });
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        // Re-lint on save (belt and suspenders — didChange already does it).
        if Self::is_sigma_file(&uri) {
            let docs = self.documents.read().await;
            if let Some(doc) = docs.get(&uri) {
                self.publish_diagnostics_now(&uri, &doc.text, doc.version)
                    .await;
            }
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;

        // Cancel any pending diagnostics for this file.
        {
            let mut pending = self.pending_diagnostics.lock().await;
            if let Some(handle) = pending.remove(&uri) {
                handle.abort();
            }
        }

        self.documents.write().await.remove(&uri);

        // Clear diagnostics for the closed file.
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    // ── Completions ─────────────────────────────────────────────────────

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        let docs = self.documents.read().await;
        let Some(doc) = docs.get(uri) else {
            return Ok(None);
        };

        let text = doc.text.clone();
        let items = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            completion::complete(&text, position)
        })) {
            Ok(items) => items,
            Err(_) => {
                log::error!("panic in completion::complete");
                vec![]
            }
        };
        if items.is_empty() {
            Ok(None)
        } else {
            Ok(Some(CompletionResponse::Array(items)))
        }
    }

    // ── Hover ───────────────────────────────────────────────────────────

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let docs = self.documents.read().await;
        let Some(doc) = docs.get(uri) else {
            return Ok(None);
        };

        let text = doc.text.clone();
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hover_at(&text, position)
        })) {
            Ok(r) => r,
            Err(_) => {
                log::error!("panic in hover_at");
                None
            }
        };
        Ok(result)
    }

    // ── Document symbols ────────────────────────────────────────────────

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        let docs = self.documents.read().await;
        let Some(doc) = docs.get(uri) else {
            return Ok(None);
        };

        let text = doc.text.clone();
        let symbols = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            document_symbols(&text)
        })) {
            Ok(s) => s,
            Err(_) => {
                log::error!("panic in document_symbols");
                vec![]
            }
        };
        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Nested(symbols)))
        }
    }
}

// =============================================================================
// Hover — MITRE ATT&CK tags, modifier help
// =============================================================================

fn hover_at(text: &str, position: Position) -> Option<Hover> {
    let line = text.lines().nth(position.line as usize)?;
    let word = word_at(line, position.character as usize)?;

    // MITRE ATT&CK tag hover
    if let Some(info) = mitre_hover(word) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: info,
            }),
            range: None,
        });
    }

    // Modifier hover
    if let Some(info) = modifier_hover(word) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: info,
            }),
            range: None,
        });
    }

    None
}

/// Extract the word at a given column position (UTF-8 safe).
fn word_at(line: &str, col: usize) -> Option<&str> {
    // LSP columns are UTF-16 offsets; approximate as byte offset but clamp
    // to the nearest char boundary to avoid panics.
    let col = col.min(line.len());

    // Snap to nearest char boundary
    let col = if line.is_char_boundary(col) {
        col
    } else {
        // Walk backward to find a valid boundary
        (0..col)
            .rev()
            .find(|&i| line.is_char_boundary(i))
            .unwrap_or(0)
    };

    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-';

    let bytes = line.as_bytes();

    let mut start = col;
    while start > 0 && start <= bytes.len() && is_word_byte(bytes[start - 1]) {
        start -= 1;
    }

    let mut end = col;
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }

    if start == end {
        return None;
    }

    // Final boundary check
    if line.is_char_boundary(start) && line.is_char_boundary(end) {
        Some(&line[start..end])
    } else {
        None
    }
}

fn mitre_hover(word: &str) -> Option<String> {
    // Match patterns like attack.t1059, attack.t1059.001, etc.
    let lower = word.to_lowercase();
    if lower.starts_with("attack.t") {
        let technique = &lower["attack.".len()..];
        return Some(format!(
            "**MITRE ATT&CK Technique**\n\n\
             `{}`\n\n\
             [View on MITRE ATT&CK](https://attack.mitre.org/techniques/{})",
            technique.to_uppercase(),
            technique.to_uppercase().replace('.', "/")
        ));
    }

    // Tactic hover from shared data
    data::MITRE_TACTICS
        .iter()
        .find(|(tag, _)| lower == *tag)
        .map(|(_, description)| format!("**MITRE ATT&CK Tactic**\n\n{description}"))
}

fn modifier_hover(word: &str) -> Option<String> {
    data::MODIFIERS
        .iter()
        .find(|(name, _)| *name == word)
        .map(|(name, desc)| format!("**`{name}`** \u{2014} {desc}"))
}

// =============================================================================
// Document symbols (hierarchical DocumentSymbol tree)
// =============================================================================

/// Build a hierarchical document symbol tree from the Sigma YAML text.
#[allow(deprecated)] // DocumentSymbol::deprecated field is itself deprecated
fn document_symbols(text: &str) -> Vec<DocumentSymbol> {
    let lines: Vec<&str> = text.lines().collect();
    let mut symbols = Vec::new();
    let sections = find_top_level_sections(&lines);

    for (key, value, start, end) in &sections {
        match key.as_str() {
            "title" => {
                let title = value.trim();
                if !title.is_empty() {
                    let sel = symbol_line_range(*start, lines[*start]);
                    symbols.push(DocumentSymbol {
                        name: title.to_string(),
                        detail: Some("title".to_string()),
                        kind: SymbolKind::STRING,
                        tags: None,
                        deprecated: None,
                        range: sel,
                        selection_range: sel,
                        children: None,
                    });
                }
            }
            "logsource" | "correlation" => {
                let sel = symbol_line_range(*start, lines[*start]);
                let full = symbol_section_range(*start, *end, &lines);
                symbols.push(DocumentSymbol {
                    name: key.clone(),
                    detail: None,
                    kind: SymbolKind::NAMESPACE,
                    tags: None,
                    deprecated: None,
                    range: full,
                    selection_range: sel,
                    children: None,
                });
            }
            "detection" => {
                let sel = symbol_line_range(*start, lines[*start]);
                let full = symbol_section_range(*start, *end, &lines);
                let children = detection_children(&lines, *start, *end);
                symbols.push(DocumentSymbol {
                    name: "detection".to_string(),
                    detail: None,
                    kind: SymbolKind::NAMESPACE,
                    tags: None,
                    deprecated: None,
                    range: full,
                    selection_range: sel,
                    children: if children.is_empty() {
                        None
                    } else {
                        Some(children)
                    },
                });
            }
            _ => {}
        }
    }

    symbols
}

/// Find top-level YAML sections: `(key, value_after_colon, start_line, end_line)`.
fn find_top_level_sections(lines: &[&str]) -> Vec<(String, String, usize, usize)> {
    let mut sections = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            i += 1;
            continue;
        }

        let indent = line.len() - trimmed.len();
        if indent == 0
            && let Some(colon_pos) = trimmed.find(':')
        {
            let key = trimmed[..colon_pos].to_string();
            let value = trimmed[colon_pos + 1..].to_string();
            let start_line = i;

            // Find end of section: next top-level key or EOF
            let mut end_line = i;
            let mut j = i + 1;
            while j < lines.len() {
                let jline = lines[j];
                let jtrimmed = jline.trim();
                if jtrimmed.is_empty() || jtrimmed.starts_with('#') {
                    j += 1;
                    continue;
                }
                let jindent = jline.len() - jtrimmed.len();
                if jindent == 0 && jtrimmed.contains(':') {
                    break;
                }
                end_line = j;
                j += 1;
            }

            sections.push((key, value, start_line, end_line));
            i = j;
            continue;
        }

        i += 1;
    }

    sections
}

/// Build child symbols for the detection block, dynamically detecting indent.
#[allow(deprecated)]
fn detection_children(
    lines: &[&str],
    section_start: usize,
    section_end: usize,
) -> Vec<DocumentSymbol> {
    let mut children = Vec::new();
    let mut detection_indent: Option<usize> = None;

    let mut i = section_start + 1;
    while i <= section_end {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        let indent = line.len() - trimmed.len();

        // First indented line with a colon sets the detection indent level
        if detection_indent.is_none() && indent > 0 && trimmed.contains(':') {
            detection_indent = Some(indent);
        }

        if let Some(det_indent) = detection_indent
            && indent == det_indent
            && let Some(colon_pos) = trimmed.find(':')
        {
            let key = trimmed[..colon_pos].trim();
            if key.is_empty() {
                i += 1;
                continue;
            }

            // Find the end of this child section
            let child_start = i;
            let mut child_end = i;
            let mut j = i + 1;
            while j <= section_end {
                let jline = lines[j];
                let jtrimmed = jline.trim();
                if jtrimmed.is_empty() || jtrimmed.starts_with('#') {
                    j += 1;
                    continue;
                }
                let jindent = jline.len() - jtrimmed.len();
                if jindent <= det_indent {
                    break;
                }
                child_end = j;
                j += 1;
            }

            let kind = if key == "condition" {
                SymbolKind::BOOLEAN
            } else {
                SymbolKind::FIELD
            };

            let sel = symbol_line_range(child_start, lines[child_start]);
            let full = symbol_section_range(child_start, child_end, lines);

            children.push(DocumentSymbol {
                name: key.to_string(),
                detail: None,
                kind,
                tags: None,
                deprecated: None,
                range: full,
                selection_range: sel,
                children: None,
            });

            i = j;
            continue;
        }

        i += 1;
    }

    children
}

/// Range covering a single line.
fn symbol_line_range(line_idx: usize, line: &str) -> Range {
    let start = Position::new(line_idx as u32, 0);
    let end_col = line.len().min(u32::MAX as usize) as u32;
    Range::new(start, Position::new(line_idx as u32, end_col))
}

/// Range covering from `start_line` to `end_line` (inclusive).
fn symbol_section_range(start_line: usize, end_line: usize, lines: &[&str]) -> Range {
    let start = Position::new(start_line as u32, 0);
    let end_col = lines[end_line].len().min(u32::MAX as usize) as u32;
    Range::new(start, Position::new(end_line as u32, end_col))
}
