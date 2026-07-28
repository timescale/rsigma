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
#              RSIGMA (binary under test, default target/release/rsigma)
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixtures="$(cd "${1:-${repo_root}/target/perf-fixtures}" && pwd)"
lane="${2:-raw_windows}"
shift 2 2>/dev/null || shift $# || true

bin="${RSIGMA:-${repo_root}/target/release/rsigma}"
rules="${fixtures}/sigma/rules"
lane_file="${fixtures}/events/${lane}.ndjson"
addr="127.0.0.1:19090"
metrics="http://${addr}/metrics"

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

before="$(count_processed)"
start="$(python3 -c 'import time; print(time.time())')"

LANE="${lane_file}" URL="http://${addr}/api/v1/events" \
    k6 run --quiet "${script_dir}/daemon-load.js" >/tmp/rsigma-baseline-k6.log 2>&1

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

python3 - "$before" "$after" "$start" "$end" "$lane" <<'PY'
import sys
before, after, start, end = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
lane = sys.argv[5]
n = after - before
secs = end - start
print(f"lane={lane} processed={n} wall={secs:.1f}s eps={n / max(secs, 1e-9):.0f}")
PY
