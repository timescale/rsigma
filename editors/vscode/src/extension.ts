import * as path from "path";
import { workspace, ExtensionContext, window } from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  Executable,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: ExtensionContext): void {
  const config = workspace.getConfiguration("rsigma");
  const serverPath: string = config.get("serverPath", "rsigma-lsp");

  // Resolve the server binary path
  const command = path.isAbsolute(serverPath) ? serverPath : serverPath;

  const run: Executable = {
    command,
    args: [],
    options: {
      env: { ...process.env, RUST_LOG: "info" },
    },
  };

  const serverOptions: ServerOptions = {
    run,
    debug: {
      ...run,
      options: {
        ...run.options,
        env: { ...process.env, RUST_LOG: "debug" },
      },
    },
  };

  const clientOptions: LanguageClientOptions = {
    // Activate for YAML files — Sigma rules are YAML
    documentSelector: [
      { scheme: "file", language: "yaml" },
      { scheme: "file", pattern: "**/*.yml" },
      { scheme: "file", pattern: "**/*.yaml" },
    ],
    synchronize: {
      // Watch for changes to .yml/.yaml files
      fileEvents: workspace.createFileSystemWatcher("**/*.{yml,yaml}"),
    },
    outputChannelName: "rsigma",
  };

  client = new LanguageClient(
    "rsigma",
    "rsigma Language Server",
    serverOptions,
    clientOptions
  );

  client.start().catch((err) => {
    window.showErrorMessage(
      `Failed to start rsigma language server: ${err.message}. ` +
        `Make sure 'rsigma-lsp' is installed and available in your PATH, ` +
        `or set 'rsigma.serverPath' in your settings.`
    );
  });

  context.subscriptions.push({
    dispose: () => {
      if (client) {
        client.stop();
      }
    },
  });
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
