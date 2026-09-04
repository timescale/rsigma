#!/usr/bin/env bash

# Packages target-specific release binaries into a named archive
# for distribution via a GitHub release.
#
# Expects to be run from the root of the repository.

set -eo pipefail

if [[ -z "${TARGET}" ]]; then
  >&2 echo "Error: TARGET environment variable not set"
  exit 1
fi

TARGET_DIR="./target"
RELEASE_DIR="${TARGET_DIR}/${TARGET}/release"

if [[ ! -d "${RELEASE_DIR}" ]]; then
  >&2 echo "Error: missing target release directory?"
  exit 1
fi

ARCHIVE_DIR="${TARGET_DIR}/archive/rsigma-${TARGET}"
mkdir -p "${ARCHIVE_DIR}"

if [[ "${TARGET}" == *"windows"* ]]; then
  cp "${RELEASE_DIR}/rsigma.exe" "${ARCHIVE_DIR}/rsigma.exe"
  cp "${RELEASE_DIR}/rsigma-lsp.exe" "${ARCHIVE_DIR}/rsigma-lsp.exe"

  ARCHIVE_FILE="${TARGET_DIR}/archive/rsigma-${TARGET}.zip"
  7z a "${ARCHIVE_FILE}" "${ARCHIVE_DIR}"/*
else
  cp "${RELEASE_DIR}/rsigma" "${ARCHIVE_DIR}/rsigma"
  cp "${RELEASE_DIR}/rsigma-lsp" "${ARCHIVE_DIR}/rsigma-lsp"

  ARCHIVE_FILE="${TARGET_DIR}/archive/rsigma-${TARGET}.tar.gz"
  tar -C "${ARCHIVE_DIR}" -czf "${ARCHIVE_FILE}" .
fi

if [[ -z "${GITHUB_OUTPUT}" ]]; then
  echo "${ARCHIVE_FILE}"
else
  echo "filename=${ARCHIVE_FILE}" >> "${GITHUB_OUTPUT}"
fi
