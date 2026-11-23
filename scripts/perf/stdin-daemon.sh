#!/usr/bin/env bash
# Stdin batch-mode daemon throughput over two synthetic lanes.
#
# Generates a deterministic event file and two single-rule lanes under
# target/perf-stdin/: all-match (the rule matches every event, so every event
# produces one output line) and no-match (the rule matches nothing). Each lane
# runs `engine daemon` with stdin input until end of input, timed with
# /usr/bin/time, and prints one TSV row per run plus the median per lane.
#
# Usage:
#   scripts/perf/stdin-daemon.sh [LANES...]
# LANES defaults to "all-match no-match".
#
# Environment:
#   EVENTS        events per lane (default 1000000)
#   RUNS          measured runs per lane (default 3); the median is reported
#   SINK          stdout (piped to wc -l) or file (target/perf-stdin/out.ndjson)
#                 (default stdout)
#   RSIGMA        binary under test (default target/release/rsigma)
#   SUMMARY_FILE  optional path for the per-lane medians in the TSV layout
#                 check-regression.py reads (lane, variant, events, matches, eps)
#   DAEMON_FLAGS  extra flags passed to `engine daemon`
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
work="${repo_root}/target/perf-stdin"
lanes=("${@:-all-match no-match}")
if [ "${#lanes[@]}" -eq 1 ]; then
    read -r -a lanes <<<"${lanes[0]}"
fi

bin="${RSIGMA:-${repo_root}/target/release/rsigma}"
events="${EVENTS:-1000000}"
runs="${RUNS:-3}"
sink="${SINK:-stdout}"
addr="127.0.0.1:19190"
[ -x "${bin}" ] || { echo "build first: cargo build --release --all-features -p rsigma" >&2; exit 1; }
[ -x /usr/bin/time ] || { echo "/usr/bin/time is required" >&2; exit 1; }
case "${sink}" in
    stdout | file) ;;
    *) echo "SINK must be stdout or file, got ${sink}" >&2; exit 1 ;;
esac
if [ "$(uname -s)" = "Darwin" ]; then
    time_flag=-l
else
    time_flag=-v
fi

mkdir -p "${work}"
events_file="${work}/events-${events}.ndjson"
if [ ! -s "${events_file}" ]; then
    python3 - "${events}" "${events_file}" <<'PY'
import json
import random
import sys

count, path = int(sys.argv[1]), sys.argv[2]
rng = random.Random(0)
images = ["cmd.exe", "powershell.exe", "rundll32.exe", "svchost.exe", "explorer.exe"]
with open(path, "w", encoding="utf-8") as out:
    for seq in range(count):
        image = rng.choice(images)
        event = {
            "EventType": "perf",
            "EventID": 4688,
            "Image": f"C:\\Windows\\System32\\{image}",
            "CommandLine": f"{image} /c task-{rng.randrange(1 << 20)}",
            "User": f"user{rng.randrange(500)}",
            "SourceIp": ".".join(str(rng.randrange(256)) for _ in range(4)),
            "Seq": seq,
        }
        out.write(json.dumps(event, separators=(",", ":")))
        out.write("\n")
PY
fi

write_rule() {
    local path="$1" id="$2" value="$3"
    cat >"${path}" <<EOF
title: Perf ${value}
id: ${id}
status: test
logsource:
    product: perf
detection:
    selection:
        EventType: ${value}
    condition: selection
level: low
EOF
}
write_rule "${work}/all-match.yml" 6b0f6c1e-4f43-4c55-9d34-0d1f6c6f2a01 perf
write_rule "${work}/no-match.yml" 6b0f6c1e-4f43-4c55-9d34-0d1f6c6f2a02 never-present

time_file="${work}/time.txt"
log_file="${work}/daemon.log"
out_file="${work}/out.ndjson"

# Run one lane once and print "output_lines real user sys max_rss_bytes".
run_once() {
    local rule="$1" lines
    # shellcheck disable=SC2086
    if [ "${sink}" = "stdout" ]; then
        lines="$(/usr/bin/time "${time_flag}" -o "${time_file}" \
            "${bin}" engine daemon -r "${rule}" --api-addr "${addr}" ${DAEMON_FLAGS:-} \
            <"${events_file}" 2>"${log_file}" | wc -l | tr -d ' ')" || return 1
    else
        rm -f "${out_file}"
        /usr/bin/time "${time_flag}" -o "${time_file}" \
            "${bin}" engine daemon -r "${rule}" --api-addr "${addr}" \
            --output "file://${out_file}" ${DAEMON_FLAGS:-} \
            <"${events_file}" >/dev/null 2>"${log_file}" || return 1
        lines="$(wc -l <"${out_file}" | tr -d ' ')"
    fi
    python3 - "${time_file}" "${lines}" <<'PY' || return 1
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
lines = sys.argv[2]
mac = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", text)
if mac:
    real, user, sys_s = (float(v) for v in mac.groups())
    rss = int(re.search(r"(\d+)\s+maximum resident set size", text).group(1))
else:
    wall = re.search(r"Elapsed \(wall clock\) time.*: (.+)", text).group(1).strip()
    real = 0.0
    for part in wall.split(":"):
        real = real * 60 + float(part)
    user = float(re.search(r"User time \(seconds\): ([\d.]+)", text).group(1))
    sys_s = float(re.search(r"System time \(seconds\): ([\d.]+)", text).group(1))
    rss = int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", text).group(1)) * 1024
status = re.search(r"Exit status: (\d+)", text)
if status and status.group(1) != "0":
    raise SystemExit(f"daemon exited with status {status.group(1)}")
print(lines, real, user, sys_s, rss)
PY
}

if [ -n "${SUMMARY_FILE:-}" ]; then
    printf 'lane\tvariant\tevents\tmatches\teps\n' >"${SUMMARY_FILE}"
fi
printf 'lane\trun\tevents\toutput_lines\treal_s\tuser_s\tsys_s\tmax_rss_mb\tevents_per_s\n'
for lane in "${lanes[@]}"; do
    rule="${work}/${lane}.yml"
    [ -f "${rule}" ] || { echo "unknown lane ${lane}" >&2; exit 1; }
    samples=()
    for run in $(seq 1 "${runs}"); do
        sample="$(run_once "${rule}")" || {
            echo "${lane} run ${run} failed, see ${log_file}" >&2
            exit 1
        }
        read -r lines real user sys_s rss <<<"${sample}"
        samples+=("${lines}:${real}:${user}:${sys_s}:${rss}")
        python3 - "${lane}" "${run}" "${events}" "${lines}" "${real}" "${user}" "${sys_s}" "${rss}" <<'PY'
import sys
lane, run, events, lines, real, user, sys_s, rss = sys.argv[1:]
print(f"{lane}\t{run}\t{events}\t{lines}\t{float(real):.2f}\t{float(user):.2f}\t{float(sys_s):.2f}\t{int(rss) / 1048576:.1f}\t{int(events) / float(real):.0f}")
PY
    done
    python3 - "${lane}" "${events}" "${sink}" "${SUMMARY_FILE:-}" "${samples[@]}" <<'PY'
import statistics
import sys

lane, events, sink, summary = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
samples = [sample.split(":") for sample in sys.argv[5:]]
lines = {sample[0] for sample in samples}
if len(lines) != 1:
    raise SystemExit(f"output line count changed across runs: {sorted(lines)}")
real, user, sys_s, rss = (
    statistics.median(float(sample[i]) for sample in samples) for i in range(1, 5)
)
line_count = lines.pop()
print(
    f"{lane}\tmedian\t{events}\t{line_count}\t{real:.2f}\t{user:.2f}\t{sys_s:.2f}\t"
    f"{rss / 1048576:.1f}\t{events / real:.0f}"
)
if summary:
    with open(summary, "a", encoding="utf-8") as out:
        out.write(f"{lane}\t{sink}\t{events}\t{line_count}\t{events / real:.0f}\n")
PY
done
