#!/usr/bin/env bash
# Daemon HTTP end-to-end throughput baseline over a fixture lane.
#
# Starts the daemon, drives it with k6 (scripts/perf/daemon-load.js), and
# reports events/sec from the daemon's own rsigma_events_processed_total
# metric delta, so HTTP accept vs processing backlog cannot skew the number.
#
# Usage:
#   scripts/perf/baseline-daemon.sh [FIXTURES_DIR] [LANE] [EXTRA_DAEMON_FLAGS...]
# Environment: BATCH (500), VUS (4), DURATION (30s), BATCH_SIZE (512),
#              RSIGMA (binary under test, default target/release/rsigma),
#              RULES (rule tree, default pinned SigmaHQ rules),
#              LOAD_DRIVER (auto, python, or k6; default auto)
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixtures="$(cd "${1:-${repo_root}/target/perf-fixtures}" && pwd)"
lane="${2:-raw_windows}"
shift 2 2>/dev/null || shift $# || true

bin="${RSIGMA:-${repo_root}/target/release/rsigma}"
rules="${RULES:-${fixtures}/sigma/rules}"
lane_file="${fixtures}/events/${lane}.ndjson"
addr="127.0.0.1:19090"
metrics="http://${addr}/metrics"
phases=(parse decode_merge observe evaluate result_merge dispatch)

[ -x "${bin}" ] || { echo "build first: cargo build --release --all-features --bin rsigma" >&2; exit 1; }
[ -f "${lane_file}" ] || { echo "missing lane ${lane_file}" >&2; exit 1; }

"${bin}" engine daemon -r "${rules}" --input http --api-addr "${addr}" \
    --batch-size "${BATCH_SIZE:-512}" --output "file:///dev/null" "$@" \
    >/tmp/rsigma-baseline-daemon.log 2>&1 &
daemon_pid=$!
trap 'kill "${daemon_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 120); do
    curl -sf "http://${addr}/readyz" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "http://${addr}/readyz" >/dev/null || { echo "daemon did not become ready" >&2; exit 1; }

count_processed() {
    curl -sf "${metrics}" | awk '/^rsigma_events_processed_total/ {sum += $2} END {printf "%d", sum}'
}

phase_seconds() {
    curl -sf "${metrics}" | awk -v phase="$1" '
        $1 == "rsigma_batch_phase_duration_seconds_sum{phase=\"" phase "\"}" {
            print $2
            found = 1
        }
        END {if (!found) print 0}
    '
}

before="$(count_processed)"
phase_before=()
for phase in "${phases[@]}"; do
    phase_before+=("$(phase_seconds "${phase}")")
done
start="$(python3 -c 'import time; print(time.time())')"

load_driver="${LOAD_DRIVER:-auto}"
if [ "${load_driver}" = "auto" ]; then
    if command -v k6 >/dev/null 2>&1; then
        load_driver=k6
    else
        load_driver=python
    fi
fi
case "${load_driver}" in
    k6)
        LANE="${lane_file}" URL="http://${addr}/api/v1/events" \
            k6 run --quiet "${script_dir}/daemon-load.js" >/tmp/rsigma-baseline-load.log 2>&1
        ;;
    python)
        LANE="${lane_file}" URL="http://${addr}/api/v1/events" \
            python3 "${script_dir}/daemon-load.py" >/tmp/rsigma-baseline-load.log 2>&1
        ;;
    *)
        echo "unknown LOAD_DRIVER=${load_driver}; expected auto, python, or k6" >&2
        exit 1
        ;;
esac

# Let the daemon drain its queue before reading the final counter.
prev=-1
for _ in $(seq 1 60); do
    now="$(count_processed)"
    [ "${now}" = "${prev}" ] && break
    prev="${now}"
    sleep 1
done
end="$(python3 -c 'import time; print(time.time())')"
after="$(count_processed)"
phase_after=()
for phase in "${phases[@]}"; do
    phase_after+=("$(phase_seconds "${phase}")")
done

python3 - "$before" "$after" "$start" "$end" "$lane" "${phases[@]}" -- \
    "${phase_before[@]}" -- "${phase_after[@]}" <<'PY'
import sys

args = sys.argv[1:]
before = int(args.pop(0))
after = int(args.pop(0))
start = float(args.pop(0))
end = float(args.pop(0))
lane = args.pop(0)

sep = args.index("--")
phases = args[:sep]
args = args[sep + 1 :]
sep = args.index("--")
before_vals = [float(v) for v in args[:sep]]
after_vals = [float(v) for v in args[sep + 1 :]]

n = after - before
secs = end - start
deltas = [after_vals[i] - before_vals[i] for i in range(len(phases))]
measured = sum(deltas)
shares = [
    (delta / measured if measured > 0 else 0.0) for delta in deltas
]
phase_parts = " ".join(
    f"{phase}={delta:.3f}s({share:.1%})"
    for phase, delta, share in zip(phases, deltas, shares)
)
print(
    f"lane={lane} processed={n} wall={secs:.1f}s eps={n / max(secs, 1e-9):.0f} "
    f"{phase_parts}"
)
PY
