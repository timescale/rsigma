#!/usr/bin/env bash
# Run baseline-daemon.sh across the vendor-shape lanes and the flag variants
# that matter after witness indexing: bare default, logsource routing alone,
# and routing plus the cross-rule AC pass.
#
# Usage: scripts/perf/daemon-matrix.sh [FIXTURES_DIR]
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="${1:-$(cd "${script_dir}/../.." && pwd)/target/perf-fixtures}"

for lane in raw_windows structured_windows cisco_syslog sysmon_file_event; do
    for variant in default logsource logsource_ac; do
        case "${variant}" in
            default) flags=() ;;
            logsource) flags=(--logsource-routing) ;;
            logsource_ac) flags=(--logsource-routing --cross-rule-ac) ;;
        esac
        printf 'variant=%s ' "${variant}"
        "${script_dir}/baseline-daemon.sh" "${fixtures}" "${lane}" "${flags[@]+"${flags[@]}"}"
    done
done
