#!/usr/bin/env bash
# Run the offline `engine eval` throughput matrix over the perf fixture lanes
# and print one TSV row per run (lane, flags, events, matches, load seconds,
# eval seconds, events/sec).
#
# Usage:
#   scripts/perf/baseline-eval.sh [FIXTURES_DIR] [LANES...]
#
# FIXTURES_DIR defaults to target/perf-fixtures (see fetch-fixtures.sh).
# LANES defaults to "raw_windows structured_windows". The binary is expected
# at target/release/rsigma, built with --all-features.
#
# Environment:
#   REPEAT    times to concatenate each lane (default 10). Loading the pinned
#             SigmaHQ corpus costs ~0.3 s, which swamps a single 10k-event pass,
#             so the lane is repeated to push the eval share of wall time up.
#   RSIGMA    override the binary under test (default target/release/rsigma),
#             so a pre-change build can be measured with the same harness.
#
# Reported events/sec is net of rule load: the harness times a load-only run
# (empty stdin) and subtracts it, because load is a fixed startup cost and
# leaving it in the per-event figure makes a faster evaluator look slower than
# it is. Both the load and eval columns are printed so the split stays visible.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixtures="${1:-${repo_root}/target/perf-fixtures}"
shift || true
lanes=("${@:-raw_windows structured_windows}")
if [ "${#lanes[@]}" -eq 1 ]; then
    # Allow a single space-separated argument.
    read -r -a lanes <<<"${lanes[0]}"
fi

bin="${RSIGMA:-${repo_root}/target/release/rsigma}"
rules="${fixtures}/sigma/rules"
repeat="${REPEAT:-10}"
[ -x "${bin}" ] || { echo "build first: cargo build --release --all-features --bin rsigma" >&2; exit 1; }
[ -d "${rules}" ] || { echo "fixtures missing: run scripts/perf/fetch-fixtures.sh" >&2; exit 1; }

variants=(
    "baseline|"
    "logsource|--logsource-routing"
    "ac|--cross-rule-ac"
    "logsource+ac|--logsource-routing --cross-rule-ac"
)

now() { python3 -c 'import time; print(time.time())'; }

# Median of three load-only runs, one warm-up discarded.
"${bin}" engine eval -r "${rules}" --quiet --output-format ndjson </dev/null >/dev/null
load_samples=()
for _ in 1 2 3; do
    start="$(now)"
    "${bin}" engine eval -r "${rules}" --quiet --output-format ndjson </dev/null >/dev/null
    end="$(now)"
    load_samples+=("$(python3 -c "print(${end}-${start})")")
done
load="$(printf '%s\n' "${load_samples[@]}" | sort -g | sed -n 2p)"

echo -e "lane\tvariant\tevents\tmatches\tload_s\teval_s\teps"
for lane in "${lanes[@]}"; do
    events_file="${fixtures}/events/${lane}.ndjson"
    [ -f "${events_file}" ] || { echo "missing lane ${events_file}" >&2; continue; }
    stream="${TMPDIR:-/tmp}/rsigma-perf-${lane}.ndjson"
    : >"${stream}"
    for _ in $(seq 1 "${repeat}"); do cat "${events_file}" >>"${stream}"; done
    n_events="$(wc -l <"${stream}" | tr -d ' ')"
    for spec in "${variants[@]}"; do
        name="${spec%%|*}"
        flags="${spec#*|}"
        start="$(now)"
        # shellcheck disable=SC2086
        matches="$("${bin}" engine eval \
            -r "${rules}" ${flags} --quiet --output-format ndjson \
            <"${stream}" | wc -l | tr -d ' ')"
        end="$(now)"
        python3 - "${lane}" "${name}" "${n_events}" "${matches}" "${load}" "${start}" "${end}" <<'PY'
import sys
lane, name, n_events, matches = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
load, start, end = float(sys.argv[5]), float(sys.argv[6]), float(sys.argv[7])
evaluated = max(end - start - load, 1e-9)
print(f"{lane}\t{name}\t{n_events}\t{matches}\t{load:.2f}\t{evaluated:.2f}\t{n_events / evaluated:.0f}")
PY
    done
    rm -f "${stream}"
done
