//! LSP server implementation for Sigma detection rules.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use crate::completion;
use crate::diagnostics;

/// In-memory document state: we keep the latest text for each open file.
#[derive(Debug, Clone)]
struct DocumentState {
    text: String,
}

/// The Sigma Language Server.
pub struct SigmaLanguageServer {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, DocumentState>>>,
}

impl SigmaLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Re-lint a document and publish diagnostics.
    async fn publish_diagnostics(&self, uri: &Url, text: &str) {
        let diags = diagnostics::diagnose(text);
        self.client
            .publish_diagnostics(uri.clone(), diags, None)
            .await;
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

        if Self::is_sigma_file(&uri) {
            self.publish_diagnostics(&uri, &text).await;
        }

        self.documents
            .write()
            .await
            .insert(uri, DocumentState { text });
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;

        // FULL sync: the last content change has the full text.
        if let Some(change) = params.content_changes.into_iter().last() {
            let text = change.text;

            if Self::is_sigma_file(&uri) {
                self.publish_diagnostics(&uri, &text).await;
            }

            self.documents
                .write()
                .await
                .insert(uri, DocumentState { text });
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        // Re-lint on save (belt and suspenders — didChange already does it).
        if Self::is_sigma_file(&uri) {
            let docs = self.documents.read().await;
            if let Some(doc) = docs.get(&uri) {
                self.publish_diagnostics(&uri, &doc.text).await;
            }
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
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

        let items = completion::complete(&doc.text, position);
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

        Ok(hover_at(&doc.text, position))
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

        let symbols = document_symbols(&doc.text);
        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Flat(symbols)))
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

/// Extract the word at a given column position.
fn word_at(line: &str, col: usize) -> Option<&str> {
    if col > line.len() {
        return None;
    }

    let bytes = line.as_bytes();
    let is_word_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-';

    let mut start = col;
    while start > 0 && is_word_char(bytes[start - 1]) {
        start -= 1;
    }

    let mut end = col;
    while end < bytes.len() && is_word_char(bytes[end]) {
        end += 1;
    }

    if start == end {
        return None;
    }

    Some(&line[start..end])
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

    // Tactic hover
    let tactics: &[(&str, &str)] = &[
        ("attack.initial_access", "Initial Access (TA0001)"),
        ("attack.execution", "Execution (TA0002)"),
        ("attack.persistence", "Persistence (TA0003)"),
        (
            "attack.privilege_escalation",
            "Privilege Escalation (TA0004)",
        ),
        ("attack.defense_evasion", "Defense Evasion (TA0005)"),
        ("attack.credential_access", "Credential Access (TA0006)"),
        ("attack.discovery", "Discovery (TA0007)"),
        ("attack.lateral_movement", "Lateral Movement (TA0008)"),
        ("attack.collection", "Collection (TA0009)"),
        ("attack.exfiltration", "Exfiltration (TA0010)"),
        ("attack.command_and_control", "Command and Control (TA0011)"),
        ("attack.impact", "Impact (TA0040)"),
        (
            "attack.resource_development",
            "Resource Development (TA0042)",
        ),
        ("attack.reconnaissance", "Reconnaissance (TA0043)"),
    ];

    for (tag, description) in tactics {
        if lower == *tag {
            return Some(format!("**MITRE ATT&CK Tactic**\n\n{description}"));
        }
    }

    None
}

fn modifier_hover(word: &str) -> Option<String> {
    let info = match word {
        "contains" => "**`contains`** — Match substring anywhere in the field value.",
        "startswith" => "**`startswith`** — Match prefix of the field value.",
        "endswith" => "**`endswith`** — Match suffix of the field value.",
        "all" => "**`all`** — All values in the list must match (AND logic instead of OR).",
        "base64" => "**`base64`** — Match the base64-encoded form of the value.",
        "base64offset" => "**`base64offset`** — Match any of the three base64 offset variants.",
        "wide" | "utf16le" => "**`wide`** / **`utf16le`** — Match the UTF-16LE encoded form.",
        "utf16be" => "**`utf16be`** — Match the UTF-16BE encoded form.",
        "utf16" => "**`utf16`** — Match both UTF-16LE and UTF-16BE encoded forms.",
        "windash" => "**`windash`** — Expand `-` to `- /` dash variants for Windows CLI.",
        "re" => "**`re`** — Treat the value as a regular expression.",
        "cidr" => "**`cidr`** — Match IP addresses against a CIDR range.",
        "cased" => "**`cased`** — Case-sensitive matching (default is case-insensitive).",
        "exists" => "**`exists`** — Check if the field exists (`true`) or is absent (`false`).",
        "expand" => "**`expand`** — Expand placeholders in the value.",
        "fieldref" => "**`fieldref`** — Value references another field name.",
        "gt" => "**`gt`** — Field value must be greater than the specified value.",
        "gte" => "**`gte`** — Field value must be greater than or equal.",
        "lt" => "**`lt`** — Field value must be less than the specified value.",
        "lte" => "**`lte`** — Field value must be less than or equal.",
        "neq" => "**`neq`** — Field value must not equal the specified value.",
        _ => return None,
    };
    Some(info.to_string())
}

// =============================================================================
// Document symbols
// =============================================================================

#[allow(deprecated)] // SymbolInformation::deprecated is itself deprecated
fn document_symbols(text: &str) -> Vec<SymbolInformation> {
    let mut symbols = Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    let make_loc = |i: usize, line: &str| {
        let pos = Position::new(i as u32, 0);
        let range = Range::new(pos, Position::new(i as u32, line.len() as u32));
        Location::new(Url::parse("file:///unknown").unwrap(), range)
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Top-level keys that are interesting for navigation
        if let Some(value) = trimmed.strip_prefix("title:") {
            symbols.push(SymbolInformation {
                name: value.trim().to_string(),
                kind: SymbolKind::STRING,
                tags: None,
                deprecated: None,
                location: make_loc(i, line),
                container_name: None,
            });
        } else if trimmed == "detection:" {
            symbols.push(SymbolInformation {
                name: "detection".to_string(),
                kind: SymbolKind::NAMESPACE,
                tags: None,
                deprecated: None,
                location: make_loc(i, line),
                container_name: None,
            });
        } else if trimmed == "logsource:" {
            symbols.push(SymbolInformation {
                name: "logsource".to_string(),
                kind: SymbolKind::NAMESPACE,
                tags: None,
                deprecated: None,
                location: make_loc(i, line),
                container_name: None,
            });
        } else if trimmed == "correlation:" {
            symbols.push(SymbolInformation {
                name: "correlation".to_string(),
                kind: SymbolKind::NAMESPACE,
                tags: None,
                deprecated: None,
                location: make_loc(i, line),
                container_name: None,
            });
        } else if trimmed == "filter:" {
            symbols.push(SymbolInformation {
                name: "filter".to_string(),
                kind: SymbolKind::NAMESPACE,
                tags: None,
                deprecated: None,
                location: make_loc(i, line),
                container_name: None,
            });
        } else if trimmed.starts_with("condition:") {
            // Could be under detection or at top-level for correlations
            let indent = line.len() - trimmed.len();
            if indent > 0 {
                symbols.push(SymbolInformation {
                    name: "condition".to_string(),
                    kind: SymbolKind::BOOLEAN,
                    tags: None,
                    deprecated: None,
                    location: make_loc(i, line),
                    container_name: Some("detection".to_string()),
                });
            }
        }

        // Detection selection identifiers (indented keys under detection:)
        // Look for lines like "    selection:" or "    filter_foo:" under detection
        if trimmed.ends_with(':') && !trimmed.starts_with('#') && !trimmed.starts_with('-') {
            let indent = line.len() - trimmed.len();
            let key = &trimmed[..trimmed.len() - 1];
            if indent == 4
                && key != "condition"
                && (key.starts_with("selection")
                    || key.starts_with("filter")
                    || key.starts_with("keyword"))
            {
                symbols.push(SymbolInformation {
                    name: key.to_string(),
                    kind: SymbolKind::FIELD,
                    tags: None,
                    deprecated: None,
                    location: make_loc(i, line),
                    container_name: Some("detection".to_string()),
                });
            }
        }
    }

    symbols
}
