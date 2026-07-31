#!/usr/bin/env bash
# Compare two detection-only in-flight depths on one release artifact.
#
# Usage:
#   scripts/perf/inflight-compare.sh FIXTURES BINARY [EXTRA_DAEMON_FLAGS...]
#
# Environment: BASE_DEPTH (4), CANDIDATE_DEPTH (5), RUNS (5),
#              MINIMUM_RATIO (1.0), MAX_BACKPRESSURE_DELTA (0.008), and all
#              baseline-daemon.sh load controls.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="${1:?fixtures directory required}"
binary="${2:?release binary required}"
shift 2

base_depth="${BASE_DEPTH:-4}"
candidate_depth="${CANDIDATE_DEPTH:-5}"
runs="${RUNS:-5}"
minimum_ratio="${MINIMUM_RATIO:-1.0}"
max_backpressure_delta="${MAX_BACKPRESSURE_DELTA:-0.008}"
results="$(mktemp)"
trap 'rm -f "${results}"' EXIT

[ -x "${binary}" ] || { echo "binary is not executable: ${binary}" >&2; exit 1; }

run_one() {
    local depth="$1" run="$2" line eps processed backpressure
    shift 2
    line="$(
        RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-8}" \
        RSIGMA_DETECT_INFLIGHT="${depth}" \
        LOAD_DRIVER="${LOAD_DRIVER:-python}" \
        RSIGMA="${binary}" \
            "${script_dir}/baseline-daemon.sh" \
            "${fixtures}" raw_windows --logsource-routing "$@"
    )"
    echo "${line}" >&2
    eps="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^eps=/) {sub("eps=", "", $i); print $i; exit}}' <<<"${line}")"
    processed="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^processed=/) {sub("processed=", "", $i); print $i; exit}}' <<<"${line}")"
    backpressure="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^backpressure=/) {sub("backpressure=", "", $i); print $i; exit}}' <<<"${line}")"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "${depth}" "${run}" "${eps}" "${processed}" "${backpressure}" >>"${results}"
}

for run in $(seq 1 "${runs}"); do
    if ((run % 2 == 1)); then
        run_one "${base_depth}" "${run}" "$@"
        run_one "${candidate_depth}" "${run}" "$@"
    else
        run_one "${candidate_depth}" "${run}" "$@"
        run_one "${base_depth}" "${run}" "$@"
    fi
done

python3 - "${results}" "${base_depth}" "${candidate_depth}" \
    "${minimum_ratio}" "${max_backpressure_delta}" <<'PY'
import statistics
import sys

path, base_depth, candidate_depth, minimum_ratio, max_bp_delta = sys.argv[1:]
rows = {base_depth: [], candidate_depth: []}
with open(path, encoding="utf-8") as source:
    for line in source:
        depth, run, eps, processed, backpressure = line.rstrip().split("\t")
        rows[depth].append(
            {
                "run": int(run),
                "eps": float(eps),
                "processed": int(processed),
                "backpressure": int(backpressure),
            }
        )

for depth, samples in rows.items():
    if not samples:
        raise SystemExit(f"no samples for depth {depth}")

def med(depth, key):
    return statistics.median(sample[key] for sample in rows[depth])

base_eps = med(base_depth, "eps")
candidate_eps = med(candidate_depth, "eps")
base_bp = statistics.median(
    sample["backpressure"] / max(sample["processed"], 1)
    for sample in rows[base_depth]
)
candidate_bp = statistics.median(
    sample["backpressure"] / max(sample["processed"], 1)
    for sample in rows[candidate_depth]
)
ratio = candidate_eps / base_eps
bp_delta = candidate_bp - base_bp

print("depth\teps_median\tbackpressure_rate")
print(f"{base_depth}\t{base_eps:.0f}\t{base_bp:.6f}")
print(f"{candidate_depth}\t{candidate_eps:.0f}\t{candidate_bp:.6f}")
print(f"ratio\t{ratio:.4f}\tbackpressure_delta={bp_delta:.6f}")

failures = []
if ratio < float(minimum_ratio):
    failures.append(
        f"throughput ratio {ratio:.4f} is below {float(minimum_ratio):.4f}"
    )
if bp_delta > float(max_bp_delta):
    failures.append(
        f"backpressure delta {bp_delta:.6f} exceeds {float(max_bp_delta):.6f}"
    )
if failures:
    raise SystemExit("; ".join(failures))
PY
