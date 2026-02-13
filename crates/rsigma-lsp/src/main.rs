//! rsigma-lsp — Language Server Protocol server for Sigma detection rules.
//!
//! Provides real-time diagnostics, completions, hover, and document symbols
//! for `.yml`/`.yaml` Sigma files by leveraging the rsigma-parser linter
//! and rsigma-eval compiler.

mod completion;
mod data;
mod diagnostics;
mod position;
mod server;

use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    env_logger::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(server::SigmaLanguageServer::new);

    Server::new(stdin, stdout, socket).serve(service).await;
}
