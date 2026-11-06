#!/usr/bin/env python3
"""Check the docs catalogues against the source tree.

Each check compares a list the docs maintain by hand (fuzz harnesses, lint
counts, metrics, HTTP routes, features, protected config keys, environment
variables, native backends, navigation) with the code it describes, and
rejects em and en dashes outside windash examples. Needs only the Python
standard library and no built binary.

    python3 scripts/docs-audit/check_sources.py

Exits 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "docs" / "content"
VARS = ROOT / "docs" / "_data" / "vars.yml"

# Lines that describe the windash dash set must keep the literal characters.
DASHES = ("\u2014", "\u2013")
NUMBER_WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine",
    10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
    17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty", 30: "thirty", 40: "forty", 50: "fifty",
}
# Read by tests, benches, release tooling, or other programs, not by users of rsigma.
ENV_IGNORED = re.compile(r"^(RSIGMA_UPDATE|RSIGMA_TEST_|RSIGMA_DIFF|RSTIX_|CARGO_|CI$|PATH$|HOME$)")
NAV_UTILITY_PAGES = {"privacy.md"}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def words(n: int) -> str:
    if n in NUMBER_WORDS:
        return NUMBER_WORDS[n]
    tens, ones = divmod(n, 10)
    return f"{NUMBER_WORDS[tens * 10]}-{NUMBER_WORDS[ones]}"


def vars_int(key: str) -> int | None:
    match = re.search(rf"^\s*{key}:\s+(\d+)", read(VARS), re.M)
    return int(match.group(1)) if match else None


def markdown_files() -> list[Path]:
    files = sorted(CONTENT.rglob("*.md"))
    files += sorted(ROOT.glob("crates/*/README.md"))
    files += sorted((ROOT / "skills").rglob("*.md"))
    files += [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "BENCHMARKS.md", "CHANGELOG.md")]
    return [path for path in files if path.is_file()]


def check_navigation() -> list[str]:
    nav = read(ROOT / "docs" / "docmd.config.js")
    listed = set()
    for item in re.findall(r'path:\s*"(/[^"]*)"', nav):
        slug = item.strip("/")
        if not slug:
            listed.add("index.md")
            continue
        for candidate in (CONTENT / slug / "index.md", CONTENT / f"{slug}.md"):
            if candidate.is_file():
                listed.add(str(candidate.relative_to(CONTENT)))
    errors = []
    for path in sorted(CONTENT.rglob("*.md")):
        name = str(path.relative_to(CONTENT))
        if name not in listed and name not in NAV_UTILITY_PAGES:
            errors.append(f"docs/content/{name} is not in the docs/docmd.config.js navigation")
    return errors


def check_fuzz() -> list[str]:
    harnesses = sorted(path.stem for path in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    scheduled = re.findall(r"target: (fuzz_[a-z0-9_]+)", read(ROOT / ".github" / "workflows" / "fuzz.yml"))
    page = read(CONTENT / "developers" / "fuzzing.md")
    tabled = set(re.findall(r"^\| `(fuzz_[a-z0-9_]+)`", page, re.M))
    errors = [f"fuzzing.md has no table row for {name}" for name in harnesses if name not in tabled]
    errors += [f"fuzzing.md lists {name}, which is not in fuzz/fuzz_targets/" for name in sorted(tabled - set(harnesses))]
    errors += [f"fuzz.yml schedules {name}, which is not in fuzz/fuzz_targets/" for name in scheduled if name not in harnesses]
    ships = re.search(r"ships (\d+)", page)
    if not ships or int(ships.group(1)) != len(harnesses):
        errors.append(f"fuzzing.md should say it ships {len(harnesses)} harnesses")
    runs = re.search(r"runs (\d+) of them", page)
    if not runs or int(runs.group(1)) != len(scheduled):
        errors.append(f"fuzzing.md should say the workflow runs {len(scheduled)} of them")
    security = read(CONTENT / "reference" / "security.md")
    if f"{words(len(scheduled)).capitalize()} harnesses run on a scheduled CI workflow" not in security:
        errors.append(f"security.md should say {words(len(scheduled)).capitalize()} harnesses run on a scheduled CI workflow")
    return errors


def check_dashes() -> list[str]:
    errors = []
    for path in markdown_files():
        for number, line in enumerate(read(path).splitlines(), 1):
            if any(dash in line for dash in DASHES) and "windash" not in line.lower():
                errors.append(f"{path.relative_to(ROOT)}:{number} uses an em or en dash")
    return errors


def check_env_vars() -> list[str]:
    page = read(CONTENT / "reference" / "environment-variables.md")
    documented = set(re.findall(r"`([A-Z][A-Z0-9_]+)`", page))
    found: dict[str, str] = {}
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if {"tests", "benches", "target"} & set(path.parts):
            continue
        text = read(path)
        names = re.findall(r'(?:var|var_os)\(\s*"([A-Z][A-Z0-9_]+)"', text)
        names += re.findall(r'env\s*=\s*"([A-Z][A-Z0-9_]+)"', text)
        for name in names:
            found.setdefault(name, str(path.relative_to(ROOT)))
    return [
        f"{name} (read in {where}) is missing from reference/environment-variables.md"
        for name, where in sorted(found.items())
        if name not in documented and not ENV_IGNORED.match(name)
    ]


def check_lints() -> list[str]:
    text = read(ROOT / "crates" / "rsigma-parser" / "src" / "lint" / "catalogue.rs")
    block = text.split("lint_catalogue!", 1)[1]
    entries = re.findall(r"^\s+([A-Za-z0-9]+)\s+=>\s+\(Severity::\w+,\s+(SAFE|NONE),", block, re.M)
    safe = sum(1 for _, fix in entries if fix == "SAFE")
    errors = []
    if vars_int("total") != len(entries):
        errors.append(f"vars.yml rsigma.lint.total should be {len(entries)} (lint_catalogue! entries)")
    if vars_int("autofix") != safe:
        errors.append(f"vars.yml rsigma.lint.autofix should be {safe} (SAFE entries)")
    if (vars_int("rules") or 0) + (vars_int("reserved") or 0) != len(entries):
        errors.append("vars.yml rsigma.lint.rules plus reserved should equal total")
    return errors


def check_metrics() -> list[str]:
    text = read(ROOT / "crates" / "rsigma-cli" / "src" / "daemon" / "metrics.rs")
    names = list(dict.fromkeys(re.findall(r'(?:Opts|HistogramOpts)::new\(\s*"([^"]+)"', text)))
    page = read(CONTENT / "reference" / "metrics.md")
    errors = [f"{name} is missing from reference/metrics.md" for name in names if f"`{name}`" not in page]
    if vars_int("names") != len(names):
        errors.append(f"vars.yml rsigma.metrics.names should be {len(names)} (constructors in daemon/metrics.rs)")
    return errors


def check_http_routes() -> list[str]:
    text = read(ROOT / "crates" / "rsigma-cli" / "src" / "daemon" / "server.rs")
    routes = list(dict.fromkeys(re.findall(r'\.route\(\s*"(/[^"]+)"', text)))
    pages = "".join(read(CONTENT / "reference" / name) for name in ("http-api.md", "http-api-state.md", "http-api-observability.md"))
    return [f"daemon route {route} is missing from the HTTP API reference" for route in routes if route not in pages]


def check_features() -> list[str]:
    page = read(CONTENT / "reference" / "feature-flags.md")
    cargo = read(ROOT / "crates" / "rsigma-cli" / "Cargo.toml")
    block = cargo.split("[features]", 1)[1].split("\n[", 1)[0]
    names = [name for name in re.findall(r"^([A-Za-z0-9_-]+)\s*=", block, re.M) if name != "default"]
    return [f"CLI feature {name} is missing from reference/feature-flags.md" for name in names if f"`{name}`" not in page]


def check_protected_config_keys() -> list[str]:
    text = read(ROOT / "crates" / "rsigma-cli" / "src" / "config" / "mod.rs")
    table = text.split("PROTECTED_KEYS: &[ProtectedKey] = &[", 1)
    if len(table) != 2:
        return ["PROTECTED_KEYS not found in crates/rsigma-cli/src/config/mod.rs"]
    keys = re.findall(r'key:\s*"([^"]+)"', table[1].split("\n];", 1)[0])
    if not keys:
        return ["no keys parsed from PROTECTED_KEYS in crates/rsigma-cli/src/config/mod.rs"]
    errors = []
    for name, heading in (("configuration.md", "## Project config trust"), ("security.md", "## Project config files")):
        page = read(CONTENT / "reference" / name)
        if f"\n{heading}\n" not in page:
            errors.append(f"reference/{name} has no '{heading}' section")
            continue
        section = page.split(f"\n{heading}\n", 1)[1].split("\n## ", 1)[0]
        errors += [f"protected config key {key} is missing from the '{heading}' section of reference/{name}" for key in keys if f"`{key}`" not in section]
    return errors


def check_native_backends() -> list[str]:
    def targets(path: Path) -> list[str]:
        match = re.search(r"NATIVE_TARGETS:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]", read(path))
        return re.findall(r'"([a-z0-9_-]+)"', match.group(1)) if match else []

    cli = targets(ROOT / "crates" / "rsigma-cli" / "src" / "commands" / "convert.rs")
    mcp = targets(ROOT / "crates" / "rsigma-mcp" / "src" / "tools" / "shared.rs")
    errors = []
    if not cli:
        return ["NATIVE_TARGETS not found in crates/rsigma-cli/src/commands/convert.rs"]
    if cli != mcp:
        errors.append(f"NATIVE_TARGETS differ between the CLI {cli} and the MCP server {mcp}")
    pages = {
        "docs/content/cli/backend/targets.md": read(CONTENT / "cli" / "backend" / "targets.md"),
        "docs/content/cli/backend/formats.md": read(CONTENT / "cli" / "backend" / "formats.md"),
        "crates/rsigma-cli/README.md": read(ROOT / "crates" / "rsigma-cli" / "README.md"),
        "skills/rsigma/SKILL.md": read(ROOT / "skills" / "rsigma" / "SKILL.md"),
    }
    for page, text in pages.items():
        errors += [f"{page} does not name the native backend {name}" for name in cli if f"`{name}`" not in text and f"  {name} " not in text]
    return errors


CHECKS = [
    check_navigation,
    check_fuzz,
    check_dashes,
    check_env_vars,
    check_lints,
    check_metrics,
    check_http_routes,
    check_features,
    check_protected_config_keys,
    check_native_backends,
]


def main() -> int:
    failed = 0
    for check in CHECKS:
        errors = check()
        name = check.__name__.removeprefix("check_")
        print(f"{'FAIL' if errors else 'ok  '} {name}")
        for error in errors:
            print(f"     {error}")
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
