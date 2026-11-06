#!/bin/sh
# Decide whether a change needs the CI build and test jobs.
#
# Usage: ci-changes.sh <event-name> [<base> <head>]
#
# Prints `code=true` when any changed file between <base> and <head> is more
# than documentation, and `code=false` when every one is. Only pull_request
# events are classified; every other event, and any diff that fails, prints
# `code=true`, so a mistake here runs CI rather than skipping it.
set -eu

event="${1:?usage: ci-changes.sh <event-name> [<base> <head>]}"

if [ "$event" != "pull_request" ]; then
  echo "code=true"
  exit 0
fi

base="${2:?pull_request needs <base> and <head>}"
head="${3:?pull_request needs <base> and <head>}"

if ! files="$(git diff --name-only "$base" "$head")"; then
  echo "code=true"
  exit 0
fi

# Markdown under a tests/ directory is a test input (golden output files), so
# it counts as code.
code=false
while IFS= read -r file; do
  [ -n "$file" ] || continue
  case "$file" in
    */tests/*) code=true ;;
    docs/* | assets/* | *.md | LICENSE | .gitignore) ;;
    *) code=true ;;
  esac
  if [ "$code" = true ]; then
    echo "needs CI: $file" >&2
    break
  fi
done <<EOF
$files
EOF

echo "code=$code"
