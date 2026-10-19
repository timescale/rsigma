# Tutorial: The Detection Loop

This tutorial takes one detection around the whole loop on a laptop: draft a rule from incident events, test it, deploy it to the daemon, triage its alerts, tune away the false positives the triage surfaced, measure it, and hunt an archive with it. Every step runs on the small sample files created below. The [Detection Engineering Loop](detection-engineering-loop.md) guide is the map of the stages; this page walks them with real commands.

You need `rsigma` with the default features (the [prebuilt binaries](../getting-started/installation.md#prebuilt-binaries) and the Docker image have them), `curl`, and `jq`. The last step also uses Docker for a throwaway PostgreSQL. If you have not seen RSigma before, the [Quick Start](../getting-started/quick-start.md) is a shorter introduction.

## 0. Sample data

The scenario is ransomware preparation: an attacker deletes Windows volume shadow copies with `vssadmin` so the victim cannot roll back. Create a working directory with three incident events and a day of normal activity:

```bash
mkdir -p loop/rules loop/corpus/malicious loop/corpus/benign && cd loop

cat > corpus/malicious/incident.ndjson <<'EOF'
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-014","User":"CORP\\alice","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /all /quiet","ParentImage":"C:\\Windows\\System32\\cmd.exe","ProcessId":4412}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-022","User":"CORP\\bob","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /all /quiet","ParentImage":"C:\\Users\\bob\\AppData\\Local\\Temp\\setup.exe","ProcessId":7710}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"srv-db01","User":"CORP\\svc_sql","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /all /quiet","ParentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessId":1288}
EOF

cat > corpus/benign/normal-day.ndjson <<'EOF'
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-014","User":"CORP\\alice","Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c dir","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":3001}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-022","User":"CORP\\bob","Image":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","CommandLine":"chrome.exe --type=renderer","ParentImage":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","ProcessId":3002}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"srv-bk01","User":"CORP\\svc_backup","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe list shadows","ParentImage":"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe","ProcessId":3003}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"srv-db01","User":"CORP\\svc_sql","Image":"C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe","CommandLine":"sqlservr.exe -sMSSQLSERVER","ParentImage":"C:\\Windows\\System32\\services.exe","ProcessId":3004}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-031","User":"CORP\\carol","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -NoProfile Get-Service","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":3005}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"ws-031","User":"CORP\\carol","Image":"C:\\Windows\\System32\\whoami.exe","CommandLine":"whoami.exe","ParentImage":"C:\\Windows\\System32\\cmd.exe","ProcessId":3006}
EOF
```

The events use Sysmon's native field names, so no processing pipeline is involved anywhere in this tutorial.

## 1. Author: draft the rule

[`rule draft`](../cli/rule/draft.md) profiles the incident events against the baseline and proposes a selection that matches every exemplar and as little of the baseline as possible:

```bash
rsigma rule draft -e @corpus/malicious/incident.ndjson \
  --baseline @corpus/benign/normal-day.ndjson \
  --exclude-field Computer \
  --title "Shadow copy deletion with vssadmin" > draft.yml
```

The report on stderr explains each field choice:

```text
Drafted from 3 exemplar(s); matches 3/3 exemplars, 0/6 baseline events (0.0%)
  * CommandLine: vssadmin.exe delete shadows /all /quiet [constant] baseline 0.0%
  * Image: C:\Windows\System32\vssadmin.exe [constant] baseline 16.7%
  * Channel: Microsoft-Windows-Sysmon/Operational [constant] baseline 100.0%
  * EventID: 1 [constant] baseline 100.0%
    ParentImage: *.exe [patterned] baseline 100.0%
    User: CORP\* [patterned] baseline 100.0%
    ProcessId: 4412, 7710, 1288 [volatile]
```

`--exclude-field Computer` keeps the draft from listing the three affected hosts, which would make it match only this incident. The draft is deliberately literal: it matches the exact command line the attacker ran. Turn it into a detection by generalizing the values and filling in the metadata. Save the result as the rule, with two [exemplars](../reference/custom-attributes.md#rsigmaexemplars) that pin its intended behavior:

```bash
cat > rules/shadow-copy-deletion.yml <<'EOF'
title: Shadow copy deletion with vssadmin
id: 5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a
status: experimental
description: Detects vssadmin deleting volume shadow copies, a common step before ransomware encryption.
author: Your Name
date: 2026-09-30
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - delete
            - shadows
    condition: selection
falsepositives:
    - Backup software pruning its own old shadow copies
level: high
custom_attributes:
    rsigma.exemplars:
        - name: ransomware wipes every shadow copy
          expect: match
          event:
              Image: 'C:\Windows\System32\vssadmin.exe'
              CommandLine: vssadmin.exe delete shadows /all /quiet
        - name: listing shadow copies is benign
          expect: no-match
          event:
              Image: 'C:\Windows\System32\vssadmin.exe'
              CommandLine: vssadmin.exe list shadows
EOF
```

## 2. Test: lint, exemplars, and a backtest

[`rule lint`](../cli/rule/lint.md) checks the rule against the Sigma specification and RSigma's own lint rules, and [`rule test`](../cli/rule/test.md) runs the exemplars embedded in it:

```bash
rsigma rule lint rules/
rsigma rule test --rules rules/
```

```text
Exemplars: 2 | passed: 2 | failed: 0 | missing rules: 0
RULE                                  KIND       INDEX  NAME                                EXPECT    ACTUAL    RESULT
------------------------------------  ---------  -----  ----------------------------------  --------  --------  ------
5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a  detection      0  ransomware wipes every shadow copy  match     match     pass
5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a  detection      1  listing shadow copies is benign     no-match  no-match  pass
```

Exemplars cover single events. A [backtest](../cli/rule/backtest.md) covers corpora: it replays the sample files and checks per-rule fire counts against an expectations file. The rule must fire on every incident event and never on the normal day, and any other rule that fires fails the run:

```bash
cat > expectations.yml <<'EOF'
defaults:
  unexpected_detections: fail
expectations:
  - rule: 5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a
    corpus: malicious/incident.ndjson
    at_least: 3
  - rule: 5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a
    corpus: benign/normal-day.ndjson
    exactly: 0
EOF

rsigma rule backtest -r rules/ --corpus corpus/ --expectations expectations.yml
```

The per-rule fire counts print on stdout as NDJSON, followed by the summary on stderr:

```text
Backtest: 2 corpus files, 9 events, 2/2 expectations passed, 0 unexpected fires across 0 rules (policy: fail).
```

These three commands are what a [CI pipeline](ci-cd.md) runs on every rule change.

## 3. Deploy: run the daemon

Run the rule in the streaming daemon with the pieces the next step needs: an [alert pipeline](alert-pipeline.md) that groups detections into one incident per rule and host, [dispositions](triage-feedback.md) for analyst verdicts, and [capture](verdict-to-corpus.md), which keeps the events behind each verdict as tuning evidence.

```bash
cat > alert-pipeline.yml <<'EOF'
group:
  mode: group_by
  by:
    - rule
    - event.Computer
  group_wait: 1s
  resolve_timeout: 1h
EOF

cat > rsigma.yaml <<'EOF'
version: 1
daemon:
  rules: rules/
  alert_pipeline: alert-pipeline.yml
  api:
    addr: "127.0.0.1:9090"
  input:
    source: http
  output:
    sinks: ["file://detections.ndjson"]
  dispositions:
    enabled: true
  capture:
    enabled: true
    spool_dir: capture
  state:
    db: state.db
EOF

rsigma engine daemon --config rsigma.yaml 2> daemon.log &
sleep 1
curl -s http://127.0.0.1:9090/readyz
```

```json
{"status":"ready","rules_loaded":true}
```

The project file `rsigma.yaml` is also picked up by the other commands run from this directory, through the [config discovery chain](../reference/configuration.md#discovery). For production layouts, see [Docker](../deployment/docker.md), [Kubernetes](../deployment/kubernetes.md), and [systemd](../deployment/systemd.md).

## 4. Detect: send events

Replay the incident, plus the nightly backup job that nobody mentioned while writing the rule. The backup agent prunes its oldest shadow copies with the same `vssadmin delete shadows` command:

```bash
cat > backup-window.ndjson <<'EOF'
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"srv-bk01","User":"CORP\\svc_backup","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /for=D: /oldest /quiet","ParentImage":"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe","ProcessId":5101}
{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"srv-bk02","User":"CORP\\svc_backup","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /for=E: /oldest /quiet","ParentImage":"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe","ProcessId":5102}
EOF

curl -s -X POST http://127.0.0.1:9090/api/v1/events --data-binary @corpus/malicious/incident.ndjson
curl -s -X POST http://127.0.0.1:9090/api/v1/events --data-binary @backup-window.ndjson
sleep 2
```

All five events fire the rule. `detections.ndjson` holds the five detections followed by five open incidents, one per host; the same incidents are live at the API:

```bash
curl -s http://127.0.0.1:9090/api/v1/incidents \
  | jq -r '.incidents[] | [.group_by["event.Computer"], .incident_id] | @tsv' | sort
```

```text
srv-bk01	48cc261cd074df8f
srv-bk02	48cc271cd074e142
srv-db01	4ea64b0b2974d516
ws-014	d099e6d4360c35b5
ws-022	d09ce6d4360e6b8c
```

Incident ids are a fingerprint of the grouping values, so you get the same ids.

## 5. Alert and triage: record verdicts

An analyst works the five incidents: the two on the backup servers are the backup job, the other three are the attack. Post one verdict per incident. In production these arrive from your case tool through the same endpoint or a [disposition source](disposition-recipes.md):

```bash
curl -s http://127.0.0.1:9090/api/v1/incidents \
  | jq -c '.incidents[] | {
      scope: "incident",
      incident_id,
      verdict: (if (.group_by["event.Computer"] | startswith("srv-bk")) then "false_positive" else "true_positive" end),
      analyst: "alice"
    }' > verdicts.ndjson

curl -s -X POST http://127.0.0.1:9090/api/v1/dispositions --data-binary @verdicts.ndjson
```

```json
{"accepted":5,"duplicate":0,"rejected":0,"capture":["queued","queued","queued","queued","queued"]}
```

The rule's live false-positive ratio is now 40 percent, and the `capture/` directory holds one bundle per verdict: `capture/fp/` for the backup job and `capture/tp/` for the attack.

```bash
curl -s http://127.0.0.1:9090/api/v1/dispositions > triage.json
jq -c '.rules[] | {rule_id, true_positives, false_positives, fp_ratio}' triage.json
```

```json
{"rule_id":"5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a","true_positives":3,"false_positives":2,"fp_ratio":0.4}
```

## 6. Tune: filter the false positives

[`rule tune`](../cli/rule/tune.md) reads the captured bundles, finds what separates the false positives from the true positives, and emits a Sigma filter rule. It refuses to emit a filter that would suppress any true positive:

```bash
rsigma rule tune -r rules/ --from-dispositions capture > veeam-filter.yml
```

```text
suppressed 2/2 false positives; protected 3/3 true positives
```

`veeam-filter.yml` contains the filter (its `id` is generated, so yours differs):

```yaml
title: Tuning filter for Shadow copy deletion with vssadmin
id: 85ae8e76-fd81-4541-b0f6-d7cb62b51d98
description: 'Suppresses 2 observed false-positive exemplars; verified against 3 true-positive exemplars.'
author: 'rsigma rule tune'
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a
    selection:
        ParentImage: 'C:\Program Files\Veeam\Backup\VeeamAgent.exe'
        User: 'CORP\svc_backup'
    condition: not selection
```

The filter keys on the backup agent and its service account rather than on the command line, so an attacker running the same command from anywhere else still fires. Write it outside `rules/` first, as above, so the shell does not create an empty rule file that the command then tries to load. Then move it into place; the running daemon's file watcher reloads within half a second:

```bash
mv veeam-filter.yml rules/
```

Keep the backup window as a regression fixture, so a future edit that reintroduces the false positive fails the backtest:

```bash
mv backup-window.ndjson corpus/benign/
cat >> expectations.yml <<'EOF'
  - rule: 5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a
    corpus: benign/backup-window.ndjson
    exactly: 0
EOF

rsigma rule backtest -r rules/ --corpus corpus/ --expectations expectations.yml
```

```text
Backtest: 3 corpus files, 11 events, 3/3 expectations passed, 0 unexpected fires across 0 rules (policy: fail).
```

Move `rules/veeam-filter.yml` out and run the backtest again to see the new expectation fail.

## 7. Measure: coverage and the scorecard

[`rule coverage`](../cli/rule/coverage.md) maps the ruleset onto MITRE ATT&CK, and [`rule scorecard`](../cli/rule/scorecard.md) combines the backtest, the coverage, and the live triage feed into a keep, tune, or retire verdict per rule:

```bash
rsigma rule backtest -r rules/ --corpus corpus/ --expectations expectations.yml --output-format json > backtest.json
rsigma rule coverage -r rules/ --output-format json > coverage.json
rsigma rule scorecard --backtest backtest.json --coverage coverage.json --triage triage.json --output-format json \
  | jq '.records[] | {verdict, reason, precision_proxy, live_fp_ratio, attack}'
```

```json
{
  "verdict": "keep",
  "reason": "precision proxy 1.00 at or above the 0.80 keep floor and firing within the window",
  "precision_proxy": 1.0,
  "live_fp_ratio": 0.4,
  "attack": {
    "techniques": [
      "T1490"
    ],
    "tactics": [
      "impact"
    ],
    "sole_coverage": true,
    "sole_techniques": [
      "T1490"
    ]
  }
}
```

`live_fp_ratio` still reports the verdicts recorded before the filter existed; it falls as new verdicts arrive over the rolling window. `sole_coverage` flags that this is the only rule covering T1490, which makes it expensive to retire. The [Detection Scorecard](detection-scorecard.md) guide explains every signal.

Stop the daemon when you are done with it:

```bash
kill %1
```

## 8. Hunt: search the archive

A new rule only sees events from now on. [`hunt run`](../cli/hunt/run.md) runs the same rule over a PostgreSQL or TimescaleDB archive to find the attack in the past. Start a throwaway database with one old event in it:

```bash
docker run -d --name rsigma-hunt -e POSTGRES_PASSWORD=hunt -p 15432:5432 postgres:17
sleep 5
docker exec -i rsigma-hunt psql -q -U postgres <<'EOF'
CREATE TABLE security_events (time timestamptz NOT NULL DEFAULT now(), data jsonb NOT NULL);
INSERT INTO security_events (data) VALUES
  ('{"Computer":"ws-040","User":"CORP\\dave","Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe delete shadows /all /quiet","ParentImage":"C:\\Windows\\System32\\cmd.exe"}'),
  ('{"Computer":"ws-041","User":"CORP\\erin","Image":"C:\\Windows\\System32\\notepad.exe","CommandLine":"notepad.exe","ParentImage":"C:\\Windows\\explorer.exe"}');
EOF
```

Hunt the last week, reading each event from the `data` JSONB column:

```bash
rsigma hunt run -r rules/ -t postgres -O json_field=data --since 7d \
  --dsn postgres://postgres:hunt@127.0.0.1:15432/postgres \
  -o corpus/malicious/hunt.ndjson
```

```text
rule 'Shadow copy deletion with vssadmin': 1 row(s)
hunted 1 row(s) from 1 rule(s) in 2.73ms against postgres://postgres@127.0.0.1:15432/postgres
```

`corpus/malicious/hunt.ndjson` now holds the event from `ws-040`, a host nobody knew was affected. Hunt output is plain NDJSON events, so it goes straight back into the loop: add it to the backtest corpus, use it as more exemplars for `rule draft`, or add it as true positives for `rule tune`. Add `--emit sql` to see the query without connecting; the [PostgreSQL backend](../reference/backends/postgres.md) reference covers flat-column tables and TimescaleDB.

Clean up the database:

```bash
docker rm -f rsigma-hunt
```

## What next

- [Rule Drafting](rule-drafting.md) and [Rule Tuning](rule-tuning.md) cover both commands in depth, including correlation drafting and tuning without captures.
- [Triage Feedback Loop](triage-feedback.md) and [Verdict-Driven Corpora](verdict-to-corpus.md) cover dispositions and capture in production.
- [Hunting](hunting.md) covers time windows, limits, and read-only enforcement.
- [CI/CD](ci-cd.md) turns lint, exemplar tests, and backtests into merge gates.
- [MCP Server](mcp-server.md) runs the same loop from an AI agent.
