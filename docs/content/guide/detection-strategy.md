# Detection Strategy (ADS)

A production detection is more than its logic. The [Palantir Alerting and Detection Strategy (ADS) framework](https://github.com/palantir/alerting-detection-strategy-framework) captures the durable, peer-reviewed context every alert should carry: a goal, an ATT&CK categorization, a strategy abstract, technical context, stated blind spots and assumptions, false-positive notes, a true-positive validation recipe, a priority, and a response plan.

RSigma stores that context on the rule itself (standard fields plus `rsigma.ads.*`) so authoring, lint, and CI stay on one artifact instead of a separate wiki that can drift.

## The nine sections

Four ADS sections reuse standard Sigma fields; the rest live under the [`rsigma.ads.*`](../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) custom-attribute namespace.

| ADS section | Carrier | New or reused |
|-------------|---------|---------------|
| Goal | `description` | reused |
| Categorization | `attack.*` `tags` | reused |
| Strategy abstract | `rsigma.ads.strategy` | new |
| Technical context | `rsigma.ads.technical_context` | new |
| Blind spots and assumptions | `rsigma.ads.blind_spots` | new |
| False positives | `falsepositives` | reused |
| Validation | `rsigma.ads.validation`, or at least one structurally valid `expect: match` [exemplar](../reference/custom-attributes.md#rsigmaexemplars) | new |
| Priority | `level` plus `rsigma.ads.priority` (rationale) | reused plus new |
| Response | `rsigma.ads.response` | new |

The new values are plain YAML scalars and sequences written inline under `custom_attributes:`, exactly like the other `rsigma.*` engine attributes. They are pure documentation: the engine never interprets them, so they carry zero runtime cost.

Validation has an executable half. Embed events under [`rsigma.exemplars`](../reference/custom-attributes.md#rsigmaexemplars) with `expect: match` or `expect: no-match`, then run [`rule test`](../cli/rule/test.md). A structurally valid match exemplar satisfies ADS validation *presence* when the prose field is absent. Presence means a recipe exists; only a passing `rule test` proves the current rule still matches it. ADS lint stays static and never executes events.

## Authoring

Scaffold the missing sections for a rule, prefilled from what it already has:

```bash
rsigma rule doc --scaffold rules/windows/whoami.yml --in-place
```

That merges a `rsigma.ads.*` template into the rule's `custom_attributes:` block (reused fields such as `description` are left alone). Fill in the placeholders, then confirm the document reads well:

```bash
rsigma rule doc rules/windows/whoami.yml --format markdown
```

Without `--format markdown`, the default render goes through the global `--output-format` layer (`table` on a TTY). Against a bare stable rule with no ADS content yet:

```text
Rules: 1 | below ADS bar: 1 | shown: 1

RULE              STATUS  MISSING                                                                                                  VERDICT
----------------  ------  -------------------------------------------------------------------------------------------------------  ---------
Bare Stable Rule  stable  goal,categorization,strategy,technical_context,blind_spots,false_positives,validation,priority,response  below-bar
```

AI agents are a natural author of this content. The [MCP server](mcp-server.md) exposes an `author_ads` tool that returns a rule's current sections, the sections it is missing under the active config, and a scaffold to complete, and a `rsigma://ads/schema` resource that lists the section vocabulary.

A rule that is intentionally undocumented (for example a vendor import a team has not reviewed) opts out with a single attribute:

```yaml
custom_attributes:
    rsigma.ads.exempt: true
```

## Enforcing in CI

There are two gates. They share the same ADS bar when a `.rsigma-lint.yml` `ads:` block is present, but they differ when no config is found:

| Gate | Without `.rsigma-lint.yml` `ads:` | With `ads:` configured |
|------|----------------------------------|-------------------------|
| `rule lint` | No ADS findings (opt-in). | Emits `ads_missing_*`, `ads_empty_section`, and `ads_unknown_section` for enforced rules. |
| `rule doc --fail-on-missing` | Built-in defaults: enforce `stable`, require all nine sections. | Uses the same `enforce_status` / `required` / severity bar. |

Add an `ads:` block to your layered [`.rsigma-lint.yml`](../reference/lint-rules.md#ads-detection-strategy-metadata-11) when you want lint and doc to share an explicit policy:

```yaml
ads:
  enforce_status: [stable]   # statuses that require ADS sections
  required:                  # mandatory sections (defaults to all nine)
    - goal
    - categorization
    - strategy
    - technical_context
    - blind_spots
    - false_positives
    - validation
    - priority
    - response
  severity: warning          # one severity for every ADS finding (optional)
```

With that in place, `rule lint` emits an `ads_missing_*` finding per missing required section on any rule whose `status` is in `enforce_status`, plus `ads_empty_section` (`info`) for a present-but-blank section and `ads_unknown_section` for a mistyped `rsigma.ads.*` key (with a safe `--fix` rename). Ratchet the bar over time: widen `enforce_status` from `[stable]` to `[stable, test]`, grow `required` from a thin start (goal, validation, response), or flip `severity` to `error` for a hard gate.

`rule doc` is also a standalone gate, for teams that want the ADS check as its own CI step rather than folding it into `rule lint`:

```bash
rsigma rule doc rules/ --fail-on-missing
rsigma rule doc rules/ --fail-on-missing --lint-config .rsigma-lint.yml
```

It exits 1 when any rule whose status is enforced is below the bar, and `--missing-only` narrows the report to exactly those rules. A section whose `rsigma.ads.*` key is present but blank counts as undocumented here (the Markdown render shows "_Not documented._"), whereas `rule lint` reports it as the `info`-level `ads_empty_section`; run `rule lint --fail-level info` to make the lint step fail on blanks too.

## At response time

ADS content written for review is worth more when it reaches the person handling the alert. An [incident bundle](alert-pipeline.md#incident-bundles) carries the same nine sections for every rule that contributed to an incident, resolved from the rules the daemon currently has loaded, so the response plan and the blind spots arrive with the incident rather than waiting to be looked up:

```bash
rsigma engine incidents export f8bcd62a829b1126 --bundle-format markdown
```

Each contributing rule in the bundle reports how its key resolved (`unique`, `ambiguous`, or `missing`) against that loaded set, so a ruleset change while an incident was open does not silently drop documentation.

## See also

- [`rule doc`](../cli/rule/doc.md) for every flag and exit code.
- [`engine incidents export`](../cli/engine/incidents-export.md) for shipping these sections with an incident.
- [Lint Rules: ADS detection-strategy metadata](../reference/lint-rules.md#ads-detection-strategy-metadata-11) for the enforcement checks and config.
- [Custom Attributes: `rsigma.ads.*`](../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) for the attribute reference.
- [Rule Hygiene](rule-hygiene.md) for the `incomplete-ads` retirement signal.
- [Drafting Rules from Logs](rule-drafting.md#drafting-correlations) to create verified temporal rules with an embedded match exemplar.
- [CI/CD](ci-cd.md) for wiring the gate into a pipeline.
