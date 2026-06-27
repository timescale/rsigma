# Detection Strategy (ADS)

A production detection is more than its logic. The [Palantir Alerting and Detection Strategy (ADS) framework](https://github.com/palantir/alerting-detection-strategy-framework) captures the durable, peer-reviewed context every alert should carry so it does not rot into an unexplained, un-tunable line in a ruleset: a goal, an ATT&CK categorization, a strategy abstract, technical context, stated blind spots and assumptions, false-positive notes, a true-positive validation recipe, a priority, and a response plan.

RSigma bakes that rigor into the rule format and into CI, with none of it living in a separate wiki that drifts from the rules.

## The nine sections

RSigma already homes four ADS sections on standard Sigma fields and carries the rest under the [`rsigma.ads.*`](../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) custom-attribute namespace.

| ADS section | Carrier | New or reused |
|-------------|---------|---------------|
| Goal | `description` | reused |
| Categorization | `attack.*` `tags` | reused |
| Strategy abstract | `rsigma.ads.strategy` | new |
| Technical context | `rsigma.ads.technical_context` | new |
| Blind spots and assumptions | `rsigma.ads.blind_spots` | new |
| False positives | `falsepositives` | reused |
| Validation | `rsigma.ads.validation` | new |
| Priority | `level` plus `rsigma.ads.priority` (rationale) | reused plus new |
| Response | `rsigma.ads.response` | new |

The new values are plain YAML scalars and sequences written inline under `custom_attributes:`, exactly like the other `rsigma.*` engine attributes. They are pure documentation: the engine never interprets them, so they carry zero runtime cost.

## Authoring

Scaffold the missing sections for a rule, prefilled from what it already has:

```bash
rsigma rule doc --scaffold rules/windows/whoami.yml --in-place
```

That merges a `rsigma.ads.*` template into the rule's `custom_attributes:` block. Fill in the placeholders, then confirm the document reads well:

```bash
rsigma rule doc rules/windows/whoami.yml --format markdown
```

AI agents are a natural author of this content. The [MCP server](mcp-server.md) exposes an `author_ads` tool that returns a rule's current sections, the sections it is missing under the active config, and a scaffold to complete, and a `rsigma://ads/schema` resource that lists the section vocabulary.

A rule that is intentionally undocumented (for example a vendor import a team has not reviewed) opts out with a single attribute:

```yaml
custom_attributes:
    rsigma.ads.exempt: true
```

## Enforcing in CI

ADS enforcement is opt-in. Add an `ads:` block to your layered [`.rsigma-lint.yml`](../reference/lint-rules.md#ads-detection-strategy-metadata-11):

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

With that in place, `rule lint` emits an `ads_missing_*` finding per missing required section on any rule whose `status` is in `enforce_status`, plus `ads_empty_section` for a present-but-blank section and `ads_unknown_section` for a typo'd `rsigma.ads.*` key (with a safe `--fix` rename). Ratchet the bar over time: widen `enforce_status` from `[stable]` to `[stable, test]`, grow `required` from a thin start (goal, validation, response), or flip `severity` to `error` for a hard gate.

`rule doc` is also a standalone gate, for teams that want the ADS check as its own CI step rather than folding it into `rule lint`:

```bash
rsigma rule doc rules/ --fail-on-missing
```

It exits 1 when any rule whose status is enforced is below the bar, and `--missing-only` narrows the report to exactly those rules. A section whose `rsigma.ads.*` key is present but blank counts as undocumented here (the Markdown render shows "_Not documented._"), whereas `rule lint` reports it as the `info`-level `ads_empty_section`; run `rule lint --fail-level info` to make the lint step fail on blanks too.

## See also

- [`rule doc`](../cli/rule/doc.md) for every flag and exit code.
- [Lint Rules: ADS detection-strategy metadata](../reference/lint-rules.md#ads-detection-strategy-metadata-11) for the enforcement checks and config.
- [Custom Attributes: `rsigma.ads.*`](../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) for the attribute reference.
- [CI/CD](ci-cd.md) for wiring the gate into a pipeline.
