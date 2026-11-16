#!/usr/bin/env python3
"""Validate OCSF golden files against the schema server.

Not run in CI (no network fetches). After regenerating goldens:

    python3 scripts/ocsf-validate.py
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


def golden_files(paths: list[str]) -> list[Path]:
    if paths:
        return [Path(p) for p in paths]
    root = Path("crates/rsigma-runtime/tests/golden/ocsf")
    return sorted(root.rglob("*.json"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="https://schema.ocsf.io")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    files = golden_files(args.paths)
    if not files:
        print("no golden files", file=sys.stderr)
        return 2
    failed = False
    for path in files:
        try:
            finding = json.loads(path.read_text())
        except OSError as exc:
            print(f"{path}: error: : {exc}", file=sys.stderr)
            return 2
        version = (
            finding.get("metadata", {}).get("version") if isinstance(finding, dict) else None
        )
        if not isinstance(version, str):
            print(f"{path}: error: metadata.version: missing", file=sys.stderr)
            failed = True
            continue
        url = f"{args.server.rstrip('/')}/{version}/api/v2/validate"
        body = json.dumps(finding).encode()
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                report = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"{path}: network: {exc}", file=sys.stderr)
            return 2
        for kind in ("errors", "warnings"):
            for item in report.get(kind) or []:
                attr = item.get("attribute_path") or item.get("path") or ""
                message = item.get("message") or item
                label = "error" if kind == "errors" else "warning"
                print(f"{path}: {label}: {attr}: {message}")
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
