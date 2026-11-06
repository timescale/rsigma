#!/usr/bin/env bash
# Smoke-test the global --output-format contract against a built rsigma binary.
#
# Covers structured reports, AST fallbacks, fixed-wire warnings, convert
# envelopes, and config precedence. This is a post-build sanity check; crate
# integration tests remain the source of correctness.
#
# Usage:
#   cargo build --locked -p rsigma --all-features
#   ./scripts/output-format-smoke.sh --bin target/debug/rsigma
#
# Exits 0 on full success, 1 otherwise.

set -euo pipefail

RSIGMA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      RSIGMA="${2:-}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$RSIGMA" ]]; then
  if [[ -x ./target/debug/rsigma ]]; then
    RSIGMA=./target/debug/rsigma
  elif [[ -x ./target/release/rsigma ]]; then
    RSIGMA=./target/release/rsigma
  else
    echo "error: pass --bin <path> or build rsigma first" >&2
    exit 2
  fi
fi
if [[ ! -x "$RSIGMA" ]]; then
  echo "error: binary not executable: $RSIGMA" >&2
  exit 2
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

RULE="$TMP/rule.yml"
cat > "$RULE" <<'EOF'
title: Test Rule
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
EOF

EVENTS="$TMP/events.ndjson"
printf '%s\n' '{"CommandLine":"malware.exe"}' '{"CommandLine":"benign"}' > "$EVENTS"

PIPE="$TMP/pipe.yml"
cat > "$PIPE" <<'EOF'
name: rename
priority: 10
transformations:
  - id: rename_cmd
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
EOF

CFG="$TMP/rsigma.yaml"
cat > "$CFG" <<'EOF'
version: 1
global:
  color: never
EOF

RULEDIR="$TMP/rules"
mkdir -p "$RULEDIR"
cp "$RULE" "$RULEDIR/"

MIGPIPE="$TMP/mig.yml"
cat > "$MIGPIPE" <<'EOF'
name: mig
priority: 1
sources:
  - id: feed
    type: file
    path: /tmp/does-not-matter.json
    format: json
transformations:
  - type: field_name_mapping
    mapping:
      a: b
EOF

SRC="$TMP/sources.yml"
cat > "$SRC" <<'EOF'
sources:
  - id: feed
    type: file
    path: /tmp/rsigma-missing-feed.json
    format: json
    required: false
EOF

# Deterministic sigma-cli stand-in for delegated target/format listings. This
# exercises rsigma's real subprocess and table-parsing path without adding a
# Python package/plugin dependency to CI.
FAKE_SIGMA_CLI="$TMP/sigma"
cat > "$FAKE_SIGMA_CLI" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "list targets")
    cat <<'TABLE'
+------------+-----------------------+------------------------------+
| Identifier | Target Query Language | Processing Pipeline Required |
+------------+-----------------------+------------------------------+
| loki       | Grafana Loki          | No                           |
+------------+-----------------------+------------------------------+
TABLE
    ;;
  "list formats loki")
    cat <<'TABLE'
+---------+--------------------------------------------------+
| Format  | Description                                      |
+---------+--------------------------------------------------+
| default | Plain Loki queries                               |
| ruler   | Loki ruler output format for generating alerts  |
+---------+--------------------------------------------------+
TABLE
    ;;
  *)
    echo "unsupported fake sigma-cli invocation: $*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$FAKE_SIGMA_CLI"
export RSIGMA_SIGMA_CLI="$FAKE_SIGMA_CLI"

pass=0
fail=0

note() { printf '\n======== %s ========\n' "$1"; }

check() {
  local name="$1"
  local expect_pat="$2"
  shift 2
  local out ec err
  set +e
  out=$("$RSIGMA" "$@" 2>"$TMP/err.txt")
  ec=$?
  set -e
  err=$(cat "$TMP/err.txt")
  if [[ "$ec" -eq 0 ]] && printf '%s' "$out$err" | grep -qE "$expect_pat"; then
    echo "OK  $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name (expected /$expect_pat/) exit=$ec"
    echo "  stdout: ${out:0:220}"
    echo "  stderr: ${err:0:220}"
    fail=$((fail + 1))
  fi
}

check_failure() {
  local name="$1"
  local expect_pat="$2"
  shift 2
  local out ec err
  set +e
  out=$("$RSIGMA" "$@" 2>"$TMP/err.txt")
  ec=$?
  set -e
  err=$(cat "$TMP/err.txt")
  if [[ "$ec" -ne 0 ]] && printf '%s' "$out$err" | grep -qE "$expect_pat"; then
    echo "OK  $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name (expected non-zero and /$expect_pat/) exit=$ec"
    echo "  stdout: ${out:0:220}"
    echo "  stderr: ${err:0:220}"
    fail=$((fail + 1))
  fi
}

note "engine eval"
check "eval json" '"rule_title"' engine eval -r "$RULE" -e @"$EVENTS" --output-format json --quiet
check "eval ndjson" '"rule_title"' engine eval -r "$RULE" -e @"$EVENTS" --output-format ndjson --quiet
check "eval table" 'LEVEL' engine eval -r "$RULE" -e @"$EVENTS" --output-format table --quiet
check "eval csv" 'LEVEL,RULE' engine eval -r "$RULE" -e @"$EVENTS" --output-format csv --quiet
check "eval tsv" $'LEVEL\tRULE' engine eval -r "$RULE" -e @"$EVENTS" --output-format tsv --quiet

note "engine explain / classify / discover"
check "explain table" 'Test Rule' engine explain -r "$RULE" -e '{"CommandLine":"malware"}' --output-format table --color never
check "explain csv" ',' engine explain -r "$RULE" -e '{"CommandLine":"malware"}' --output-format csv --color never
check "explain json" 'selection|"rule_title"|matched' engine explain -r "$RULE" -e '{"CommandLine":"malware"}' --output-format json --color never
check "classify csv" ',' engine classify -e @"$EVENTS" --output-format csv --quiet
check "classify json" '\{' engine classify -e @"$EVENTS" --output-format json --quiet
check "discover csv header" 'NAME,SUPPORT' engine discover-schemas -e @"$EVENTS" --output-format csv --quiet
check "discover json" '"candidates"' engine discover-schemas -e @"$EVENTS" --output-format json --quiet

note "rule parse / condition / stdin"
check "parse json" '"title"' rule parse "$RULE" --output-format json
check "parse table warn" 'not supported by `rule parse`' rule parse "$RULE" --output-format table
check "condition ndjson" '\{' rule condition 'selection' --output-format ndjson
set +e
stdin_out=$("$RSIGMA" rule stdin --output-format json <"$RULE" 2>"$TMP/err.txt")
stdin_ec=$?
set -e
if [[ "$stdin_ec" -eq 0 ]] && printf '%s' "$stdin_out" | grep -q '"title"'; then
  echo "OK  stdin json"
  pass=$((pass + 1))
else
  echo "FAIL stdin json"
  fail=$((fail + 1))
fi

note "rule validate / lint / fields"
check "validate human" 'Detection rules' rule validate "$RULEDIR"
check "validate json" '"summary"' rule validate "$RULEDIR" --output-format json
check "validate csv" 'PATH,STATUS,ERRORS' rule validate "$RULEDIR" --output-format csv
check "lint json" '"findings"' rule lint "$RULE" --output-format json --color never
check "lint csv" 'PATH,SEVERITY' rule lint "$RULE" --output-format csv --color never
check "fields csv" 'FIELD,RULES' rule fields -r "$RULE" --output-format csv
check "fields table" 'FIELD' rule fields -r "$RULE" --output-format table

note "rule draft / reverse / migrate"
check "draft yaml warn" 'not supported by `rule draft`' rule draft -e @"$EVENTS" --output-format csv
check "draft report csv" '^SELECTED,FIELD,SCORE,STABILITY,MODIFIER,VALUES,BASELINE' \
  rule draft -e @"$EVENTS" --emit report --output-format csv
check "reverse yaml warn" 'not supported by `rule reverse`' \
  rule reverse --from lucene 'EventID:1' --logsource-product windows --output-format csv
check "reverse yaml keep" 'title:|detection:' \
  rule reverse --from lucene 'EventID:1' --logsource-product windows --output-format csv --quiet
check "migrate warn" 'not supported by `rule migrate-sources`' \
  rule migrate-sources -p "$MIGPIPE" -o "$TMP/out-sources.yml" --dry-run --output-format csv
check "fmt text warn" 'not supported by `rule fmt`' rule fmt "$RULE" --output-format csv

note "backend convert / targets / formats"
check "convert raw" 'CommandLine|malware' backend convert "$RULE" -t test
check "convert json" '"queries"' backend convert "$RULE" -t test --output-format json
check "convert ndjson" '"query"' backend convert "$RULE" -t test --output-format ndjson
check "convert csv warn" 'not supported by `backend convert`' backend convert "$RULE" -t test --output-format csv
check "targets csv" 'PROVIDER,NAME,DESCRIPTION' backend targets --output-format csv
check "targets native row" 'native,postgres' backend targets --output-format csv
check "targets delegated row" 'sigma-cli,loki,Grafana Loki' backend targets --output-format csv
set +e
chrome=$("$RSIGMA" backend targets --output-format csv 2>/dev/null | grep -E '^\+|Identifier|----+' || true)
set -e
if [[ -z "$chrome" ]]; then
  echo "OK  targets no ascii chrome"
  pass=$((pass + 1))
else
  echo "FAIL targets ascii chrome: $chrome"
  fail=$((fail + 1))
fi
check "formats postgres csv" 'TARGET,KIND,NAME' backend formats postgres --output-format csv
check "formats loki csv" '^TARGET,KIND,NAME,DESCRIPTION' backend formats loki --output-format csv
check "formats loki row" 'loki,format,default,Plain Loki queries' \
  backend formats loki --output-format csv

note "pipeline diff / resolve"
check "diff human" 'Test Rule|transformations|no change' pipeline diff -r "$RULE" -p "$PIPE" --color never
check "diff csv" 'RULE_TITLE,RULE_ID,CHANGED' pipeline diff -r "$RULE" -p "$PIPE" --output-format csv --color never
check "diff json" '"before"' pipeline diff -r "$RULE" -p "$PIPE" --output-format json --color never
check "resolve dry-run csv" '^PIPELINE,SOURCE_ID,SOURCE_TYPE,STATUS,DATA_OR_ERROR' \
  pipeline resolve -p "$PIPE" --source-file "$SRC" --dry-run --output-format csv

note "config group"
check "config path csv" 'SOURCE,PATH' config path -c "$CFG" --output-format csv
check "config validate text" 'Config is valid' config validate -c "$CFG"
check "config validate json" '"ok"' config validate -c "$CFG" --format json
check "config validate global csv" 'KIND,FILE,DETAIL' config validate -c "$CFG" --output-format csv
check "config show text" '=' config show -c "$CFG"
check "config show json" '"config"' config show -c "$CFG" --format json
check "config show global csv" 'PATH,VALUE,SOURCE' config show -c "$CFG" --output-format csv
check "config schema json" 'properties|\$schema' config schema --output-format json
check "config schema table warn" 'not supported by `config schema`' config schema --output-format table
check "config init warn" 'not supported by `config init`' config init -o "$TMP/init.yaml" --force --output-format csv

note "report commands"
check "hygiene csv" ',' rule hygiene -r "$RULE" --output-format csv --quiet
check "coverage json" '\{|coverage|rules' rule coverage -r "$RULEDIR" --output-format json --quiet
check "doc table" 'TITLE|title|Test Rule|,' rule doc "$RULE" --output-format table --color never

note "fixed-wire warnings"
check_failure "tap format warn before unreachable" 'not supported by `engine tap`' \
  engine tap --duration 1s --output-format csv --addr 127.0.0.1:9

note "SUMMARY"
echo "passed=$pass failed=$fail binary=$RSIGMA"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
