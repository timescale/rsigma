#!/usr/bin/env bash
# Run the offline `engine eval` throughput matrix over the perf fixture lanes
# and print one TSV row per run (lane, flags, threads, events, matches,
# wall seconds, events/sec).
#
# Usage:
#   scripts/perf/baseline-eval.sh [FIXTURES_DIR] [LANES...]
#
# FIXTURES_DIR defaults to target/perf-fixtures (see fetch-fixtures.sh).
# LANES defaults to "raw_windows structured_windows". The binary is expected
# at target/release/rsigma, built with --all-features.
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

bin="${repo_root}/target/release/rsigma"
rules="${fixtures}/sigma/rules"
[ -x "${bin}" ] || { echo "build first: cargo build --release --all-features --bin rsigma" >&2; exit 1; }
[ -d "${rules}" ] || { echo "fixtures missing: run scripts/perf/fetch-fixtures.sh" >&2; exit 1; }

variants=(
    "baseline|"
    "logsource|--logsource-routing"
    "ac|--cross-rule-ac"
    "logsource+ac|--logsource-routing --cross-rule-ac"
)

physical_cores="$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || nproc)"

echo -e "lane\tvariant\tthreads\tevents\tmatches\twall_s\teps"
for lane in "${lanes[@]}"; do
    events_file="${fixtures}/events/${lane}.ndjson"
    [ -f "${events_file}" ] || { echo "missing lane ${events_file}" >&2; continue; }
    n_events="$(wc -l <"${events_file}" | tr -d ' ')"
    for threads in 1 "${physical_cores}"; do
        for spec in "${variants[@]}"; do
            name="${spec%%|*}"
            flags="${spec#*|}"
            start="$(python3 -c 'import time; print(time.time())')"
            # shellcheck disable=SC2086
            matches="$(RAYON_NUM_THREADS="${threads}" "${bin}" engine eval \
                -r "${rules}" ${flags} --quiet --output-format ndjson \
                <"${events_file}" | wc -l | tr -d ' ')"
            end="$(python3 -c 'import time; print(time.time())')"
            wall="$(python3 -c "print(f'{${end}-${start}:.2f}')")"
            eps="$(python3 -c "print(f'{${n_events}/max(${end}-${start},1e-9):.0f}')")"
            echo -e "${lane}\t${name}\t${threads}\t${n_events}\t${matches}\t${wall}\t${eps}"
        done
    done
done
