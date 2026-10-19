// docmd emits page-relative asset and link URLs anchored by the <base href> tag.
// The site is published at https://rsigma.io/ (GitHub Pages custom domain); base
// stays "/". Override with DOCMD_BASE only for local experiments.
const base = process.env.DOCMD_BASE || "/";

export default {
  title: "RSigma",
  url: "https://rsigma.io/",
  src: "content",
  out: "site",
  base,
  logo: {
    light: "/assets/images/logo.svg",
    dark: "/assets/images/logo-dark.svg",
    alt: "RSigma",
    height: "2.75rem",
  },
  favicon: "/assets/images/favicon.svg",
  theme: {
    appearance: "dark",
    customCss: ["/assets/css/extra.css"],
  },
  layout: {
    optionsMenu: {
      components: {
        search: true,
        themeSwitch: true,
      },
    },
  },
  cookie: {
    enabled: true,
    message: "We use optional analytics cookies to understand how this documentation is used.",
    acceptText: "Accept analytics",
    declineText: "Decline",
    policyUrl: "/privacy",
    position: "bottom-right",
  },
  plugins: {
    analytics: {
      googleV4: {
        measurementId: "G-6XM09PXCEY",
      },
      autoEvents: true,
      trackSearch: true,
    },
    git: {
      repo: "https://github.com/timescale/rsigma",
      branch: "main",
      editLink: true,
      lastUpdated: true,
      commitHistory: true,
    },
    mermaid: {},
    // The AI chat plugin is on by default and sends reader questions to
    // api.docmd.io, a processor the privacy page does not cover.
    ai: { enabled: false },
    // docmd prefixes plugin keys with `@docmd/plugin-` for its registry check,
    // so this local plugin always logs "not found in official registry". It
    // still loads.
    "docmd-plugin-rsigma": {},
  },
  // Pages that moved keep their old URLs working; external links point at them.
  redirects: {
    "/getting-started/detection-loop": `${base}guide/detection-loop/`,
  },
  navigation: [
    { title: "Home", path: "/", icon: "home" },
    {
      title: "Getting Started",
      icon: "rocket",
      collapsible: true,
      children: [
        { title: "Installation", path: "/getting-started/installation" },
        { title: "Quick Start", path: "/getting-started/quick-start" },
        { title: "Core Concepts", path: "/getting-started/concepts" },
        { title: "Troubleshooting", path: "/getting-started/troubleshooting" },
      ],
    },
    {
      title: "User Guide",
      path: "/guide/detection-engineering-loop",
      icon: "book-open",
      collapsible: true,
      children: [
        { title: "Tutorial: The Detection Loop", path: "/guide/detection-loop" },
        {
          title: "Author and Test",
          collapsible: true,
          children: [
            { title: "Evaluating Rules", path: "/guide/evaluating-rules" },
            { title: "Array Matching", path: "/guide/array-matching" },
            { title: "Drafting Rules from Logs", path: "/guide/rule-drafting" },
            { title: "Rule Tuning", path: "/guide/rule-tuning" },
            { title: "Linting Rules", path: "/guide/linting-rules" },
            { title: "Rule Hygiene", path: "/guide/rule-hygiene" },
            { title: "Detection Strategy", path: "/guide/detection-strategy" },
          ],
        },
        {
          title: "Deploy and Detect",
          collapsible: true,
          children: [
            { title: "Streaming Detection", path: "/guide/streaming-detection" },
            { title: "Processing Pipelines", path: "/guide/processing-pipelines" },
            { title: "Schema Routing", path: "/guide/schema-routing" },
            { title: "Logsource-Aware Evaluation", path: "/guide/logsource-routing" },
            { title: "Enrichers", path: "/guide/enrichers" },
            { title: "Input Formats", path: "/guide/input-formats" },
            { title: "NATS Streaming", path: "/guide/nats-streaming" },
            { title: "OTLP Integration", path: "/guide/otlp-integration" },
          ],
        },
        {
          title: "Alert and Respond",
          collapsible: true,
          children: [
            { title: "Alert Pipeline", path: "/guide/alert-pipeline" },
            { title: "Risk-Based Alerting", path: "/guide/risk-based-alerting" },
            { title: "OCSF Findings", path: "/guide/ocsf-findings" },
            { title: "Webhooks", path: "/guide/webhooks" },
            { title: "Triage Feedback Loop", path: "/guide/triage-feedback" },
            { title: "Verdict-Driven Corpora", path: "/guide/verdict-to-corpus" },
            { title: "Disposition Source Recipes", path: "/guide/disposition-recipes" },
          ],
        },
        {
          title: "Measure and Hunt",
          collapsible: true,
          children: [
            { title: "Detection Scorecard", path: "/guide/detection-scorecard" },
            { title: "ATT&CK Coverage", path: "/guide/attack-coverage" },
            { title: "Visibility and Data Sources", path: "/guide/visibility-and-data-sources" },
            { title: "Rule Conversion", path: "/guide/rule-conversion" },
            { title: "Hunting in the Archive", path: "/guide/hunting" },
          ],
        },
        {
          title: "Operate",
          collapsible: true,
          children: [
            { title: "CI/CD", path: "/guide/ci-cd" },
            { title: "Performance Tuning", path: "/guide/performance-tuning" },
            { title: "Observability", path: "/guide/observability" },
          ],
        },
        {
          title: "Integrate",
          collapsible: true,
          children: [
            {
              title: "Cloud Collection Recipes",
              path: "/guide/cloud-collection-recipes",
              collapsible: true,
              children: [
                { title: "Cloud Platforms", path: "/guide/cloud-collection-platforms" },
                { title: "Identity and SaaS", path: "/guide/cloud-collection-identity-saas" },
                { title: "Containers and Hosts", path: "/guide/cloud-collection-containers-hosts" },
              ],
            },
            { title: "MCP Server", path: "/guide/mcp-server" },
          ],
        },
      ],
    },
    {
      title: "CLI Reference",
      path: "/cli",
      icon: "terminal",
      collapsible: true,
      children: [
        {
          title: "engine",
          collapsible: true,
          children: [
            { title: "eval", path: "/cli/engine/eval" },
            { title: "explain", path: "/cli/engine/explain" },
            { title: "classify", path: "/cli/engine/classify" },
            { title: "discover-schemas", path: "/cli/engine/discover-schemas" },
            { title: "status", path: "/cli/engine/status" },
            {
              title: "incidents export",
              path: "/cli/engine/incidents-export",
            },
            { title: "tap", path: "/cli/engine/tap" },
            { title: "tail", path: "/cli/engine/tail" },
            { title: "daemon", path: "/cli/engine/daemon" },
          ],
        },
        {
          title: "rule",
          collapsible: true,
          children: [
            { title: "parse", path: "/cli/rule/parse" },
            { title: "validate", path: "/cli/rule/validate" },
            { title: "lint", path: "/cli/rule/lint" },
            { title: "fields", path: "/cli/rule/fields" },
            { title: "draft", path: "/cli/rule/draft" },
            { title: "tune", path: "/cli/rule/tune" },
            { title: "reverse", path: "/cli/rule/reverse" },
            { title: "doc", path: "/cli/rule/doc" },
            { title: "test", path: "/cli/rule/test" },
            { title: "backtest", path: "/cli/rule/backtest" },
            { title: "coverage", path: "/cli/rule/coverage" },
            { title: "scorecard", path: "/cli/rule/scorecard" },
            { title: "visibility", path: "/cli/rule/visibility" },
            { title: "hygiene", path: "/cli/rule/hygiene" },
            { title: "condition", path: "/cli/rule/condition" },
            { title: "stdin", path: "/cli/rule/stdin" },
            { title: "migrate-sources", path: "/cli/rule/migrate-sources" },
          ],
        },
        {
          title: "backend",
          collapsible: true,
          children: [
            { title: "convert", path: "/cli/backend/convert" },
            { title: "targets", path: "/cli/backend/targets" },
            { title: "formats", path: "/cli/backend/formats" },
          ],
        },
        {
          title: "pipeline",
          collapsible: true,
          children: [
            { title: "diff", path: "/cli/pipeline/diff" },
            { title: "resolve", path: "/cli/pipeline/resolve" },
          ],
        },
        {
          title: "hunt",
          collapsible: true,
          children: [{ title: "run", path: "/cli/hunt/run" }],
        },
        {
          title: "taxii",
          collapsible: true,
          children: [
            { title: "sync", path: "/cli/taxii/sync" },
            { title: "store", path: "/cli/taxii/store" },
          ],
        },
        {
          title: "mcp",
          collapsible: true,
          children: [{ title: "serve", path: "/cli/mcp/serve" }],
        },
        {
          title: "config",
          collapsible: true,
          children: [
            { title: "init", path: "/cli/config/init" },
            { title: "validate", path: "/cli/config/validate" },
            { title: "show", path: "/cli/config/show" },
            { title: "schema", path: "/cli/config/schema" },
            { title: "path", path: "/cli/config/path" },
            { title: "reload", path: "/cli/config/reload" },
          ],
        },
      ],
    },
    {
      title: "Library",
      path: "/library",
      icon: "package",
      collapsible: true,
      children: [
        { title: "rsigma-parser", path: "/library/parser" },
        { title: "rsigma-ir", path: "/library/ir" },
        { title: "rsigma-eval", path: "/library/eval" },
        { title: "rsigma-convert", path: "/library/convert" },
        { title: "rsigma-runtime", path: "/library/runtime" },
        { title: "rsigma-mcp", path: "/library/mcp" },
        { title: "rstix", path: "/library/rstix" },
      ],
    },
    {
      title: "Reference",
      icon: "book-marked",
      collapsible: true,
      children: [
        { title: "Lint Rules", path: "/reference/lint-rules" },
        { title: "Schema Signatures", path: "/reference/schema-signatures" },
        { title: "Configuration", path: "/reference/configuration" },
        { title: "Output Formats", path: "/reference/output" },
        {
          title: "Backends",
          collapsible: true,
          children: [
            { title: "PostgreSQL/TimescaleDB", path: "/reference/backends/postgres" },
            { title: "LynxDB", path: "/reference/backends/lynxdb" },
            { title: "Fibratus", path: "/reference/backends/fibratus" },
            { title: "sigma-cli delegation", path: "/reference/backends/sigma-cli" },
          ],
        },
        { title: "Prometheus Metrics", path: "/reference/metrics" },
        {
          title: "HTTP API",
          path: "/reference/http-api",
          collapsible: true,
          children: [
            { title: "Detection State", path: "/reference/http-api-state" },
            { title: "Live Observability", path: "/reference/http-api-observability" },
          ],
        },
        { title: "Exit Codes", path: "/reference/exit-codes" },
        { title: "Environment Variables", path: "/reference/environment-variables" },
        { title: "Feature Flags", path: "/reference/feature-flags" },
        { title: "Value Modifiers", path: "/reference/modifiers" },
        { title: "Keywords and Conditions", path: "/reference/conditions" },
        { title: "Custom Attributes", path: "/reference/custom-attributes" },
        { title: "Builtin Pipelines", path: "/reference/builtin-pipelines" },
        { title: "Dynamic Pipeline Sources", path: "/reference/dynamic-sources" },
        { title: "Security Hardening", path: "/reference/security" },
        { title: "WASM ABI", path: "/reference/wasm-abi" },
        { title: "Architecture", path: "/reference/architecture" },
        { title: "Benchmarks", path: "/benchmarks" },
      ],
    },
    {
      title: "Deployment",
      icon: "container",
      collapsible: true,
      children: [
        { title: "Docker", path: "/deployment/docker" },
        { title: "Kubernetes", path: "/deployment/kubernetes" },
        { title: "systemd", path: "/deployment/systemd" },
      ],
    },
    {
      title: "Integrations",
      icon: "plug",
      collapsible: true,
      children: [
        {
          title: "Editors",
          collapsible: true,
          children: [
            { title: "VS Code and Cursor", path: "/editors/vscode" },
            { title: "Neovim, Helix, Zed", path: "/editors/neovim" },
          ],
        },
        {
          title: "Ecosystem",
          collapsible: true,
          children: [
            { title: "Helr (HTTP API log collector)", path: "/ecosystem/helr" },
          ],
        },
      ],
    },
    {
      title: "Developers",
      path: "/developers",
      icon: "code",
      collapsible: true,
      children: [
        { title: "Testing", path: "/developers/testing" },
        { title: "Fuzzing", path: "/developers/fuzzing" },
        { title: "Adding Backends", path: "/developers/adding-backends" },
        { title: "Adding Input Formats", path: "/developers/adding-input-formats" },
        { title: "Adding Enrichers", path: "/developers/adding-enrichers" },
        { title: "Adding Dynamic Sources", path: "/developers/adding-sources" },
        { title: "Linter and LSP", path: "/developers/linter-and-lsp" },
      ],
    },
    {
      title: "Project",
      icon: "folder",
      collapsible: true,
      children: [
        { title: "Release Notes", path: "/release-notes" },
        { title: "Contributing", path: "/contributing" },
        { title: "Security Policy", path: "/security-policy" },
      ],
    },
  ],
};
