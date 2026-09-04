#!/usr/bin/env bash
# Publish a single workspace crate to crates.io, skipping the upload when the
# target version already exists on the registry.
#
# This keeps the publish workflow idempotent: if an earlier run published some
# crates and then failed partway through (a network blip, a fixable manifest
# issue, a dependency-ordering bug), the workflow can be re-run and each crate
# that already landed is left untouched instead of aborting the whole job on a
# "crate version already exists" error.
set -euo pipefail

crate="${1:?usage: publish-crate.sh <crate-name>}"

version="$(cargo pkgid -p "$crate" | sed 's/.*[#@]//')"

# Sparse-index layout for names of four or more characters:
# {first two}/{next two}/{name}. Every workspace crate (rsigma-*, rstix) is at
# least five characters, so the one- to three-character layouts never apply.
index_url="https://index.crates.io/${crate:0:2}/${crate:2:2}/${crate}"

if curl -sf "$index_url" | grep -q "\"vers\":\"${version}\""; then
  echo "::notice::${crate} ${version} is already on crates.io; skipping publish"
  exit 0
fi

echo "Publishing ${crate} ${version}"
cargo publish --locked -p "$crate"
