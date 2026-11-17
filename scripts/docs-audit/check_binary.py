#!/usr/bin/env python3
"""Check the docs against a built `rsigma` binary.

Compares the CLI reference pages with `--help`, the published config schema
and its keys with `config schema`, the MCP docs with `tools/list` and
`resources/list`, the backend samples with `backend targets` and
`backend formats`, and runs the self-contained YAML examples (rules,
pipelines, and config files) through the binary. Build with every feature so
all flags, keys, and tools exist:

    cargo build --locked -p rsigma --all-features
    python3 scripts/docs-audit/check_binary.py --bin target/debug/rsigma

Needs only the Python standard library. Exits 0 when every check passes, 1
otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "docs" / "content"
GLOBAL_FLAGS = {"log-format", "output-format", "color", "quiet", "no-stats", "features", "help", "version"}
FLAG = r"--([A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])"
MCP_DOCS = [
    CONTENT / "guide" / "mcp-server.md",
    CONTENT / "cli" / "mcp" / "serve.md",
    ROOT / "crates" / "rsigma-mcp" / "README.md",
]
CONFIG_COMMANDS = {
    "daemon": (["engine", "daemon"], CONTENT / "cli" / "engine" / "daemon.md"),
    "eval": (["engine", "eval"], CONTENT / "cli" / "engine" / "eval.md"),
    "backtest": (["rule", "backtest"], CONTENT / "cli" / "rule" / "backtest.md"),
    "convert": (["backend", "convert"], CONTENT / "cli" / "backend" / "convert.md"),
}
CONFIG_SECTIONS = {"version", "global", "daemon", "eval", "backtest", "coverage", "scorecard", "visibility", "hygiene", "doc", "mcp", "rulesets", "convert"}
TRIVIAL_RULE = """title: t
id: 00000000-0000-0000-0000-000000000000
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image: x}
  condition: sel
"""

BIN = ""


def run(args: list[str], cwd: Path | None = None, stdin: str = "") -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "COLUMNS": "200", "LC_ALL": "C", "RSIGMA_SIGMA_CLI": "/nonexistent/sigma"})
    return subprocess.run([BIN, *args], capture_output=True, text=True, env=env, cwd=cwd, input=stdin, timeout=60, check=False)


def strip_fences(text: str) -> str:
    return re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)


def help_flags(command: list[str]) -> set[str] | None:
    proc = run([*command, "--help"])
    if proc.returncode != 0:
        return None
    flags = set()
    for line in proc.stdout.splitlines():
        if re.match(r"^\s{2,9}-", line):
            header = re.split(r"\s{2,}", line.strip(), maxsplit=1)[0]
            flags.update(re.findall(FLAG, header))
    return flags - GLOBAL_FLAGS


def check_cli_flags() -> list[str]:
    errors = []
    for path in sorted((CONTENT / "cli").rglob("*.md")):
        text = read(path)
        heading = re.search(r"^# `rsigma ([^`]+)`", text, re.M)
        if path.name == "index.md" or not heading:
            continue
        rel = path.relative_to(ROOT)
        command = heading.group(1).split()
        actual = help_flags(command)
        if actual is None:
            errors.append(f"{rel}: `rsigma {' '.join(command)} --help` failed")
            continue
        body = strip_fences(text)
        mentioned = set(re.findall(FLAG, body))
        for line in body.splitlines():
            if not line.startswith("|") or "deprecated" in line.lower():
                continue
            for flag in re.findall(FLAG, line.split("|")[1]):
                if flag not in actual and flag not in GLOBAL_FLAGS:
                    errors.append(f"{rel} documents --{flag}, which `rsigma {' '.join(command)}` does not accept")
        errors += [f"{rel} does not mention --{flag}" for flag in sorted(actual - mentioned)]
    return errors


def schema_leaves(schema: dict) -> list[str]:
    defs = schema.get("$defs") or schema.get("definitions") or {}

    def resolve(node):
        while isinstance(node, dict) and "$ref" in node:
            node = defs[node["$ref"].rsplit("/", 1)[-1]]
        return node

    paths: list[str] = []

    def walk(node, prefix: str, depth: int) -> None:
        node = resolve(node)
        if depth > 6 or not isinstance(node, dict):
            return
        for key in ("anyOf", "oneOf", "allOf"):
            for sub in node.get(key, []):
                walk(sub, prefix, depth)
        for name, sub in node.get("properties", {}).items():
            path = f"{prefix}.{name}" if prefix else name
            paths.append(path)
            walk(sub, path, depth + 1)
        if "items" in node:
            walk(node["items"], prefix, depth + 1)
        if isinstance(node.get("additionalProperties"), dict):
            walk(node["additionalProperties"], prefix, depth + 1)

    walk(schema, "", 0)
    return sorted(set(paths))


def check_config() -> list[str]:
    proc = run(["config", "schema"])
    if proc.returncode != 0:
        return [f"`rsigma config schema` failed: {proc.stderr.strip()}"]
    schema = json.loads(proc.stdout)
    errors = []
    if json.loads(read(ROOT / "docs" / "rsigma.schema.json")) != schema:
        errors.append(
            "docs/rsigma.schema.json is stale; regenerate it with "
            "`cargo run -p rsigma --all-features -- config schema > docs/rsigma.schema.json`"
        )
    docs = "\n".join(read(path) for path in CONTENT.rglob("*.md"))
    helps = {section: run([*command, "--help"]).stdout for section, (command, _) in CONFIG_COMMANDS.items()}
    for key in schema_leaves(schema):
        leaf = key.rsplit(".", 1)[-1]
        if key in docs or f"`{leaf}`" in docs or re.search(rf"^\s*#?\s*{re.escape(leaf)}:", docs, re.M):
            continue
        section = key.split(".", 1)[0]
        if section in CONFIG_COMMANDS:
            page = read(CONFIG_COMMANDS[section][1])
            stem = re.escape(leaf.replace("_", "-").removesuffix("s"))
            flags = set(re.findall(rf"--[a-z0-9-]*{stem}[a-z0-9-]*", helps[section]))
            if any(flag in page for flag in flags):
                continue
        errors.append(f"config key {key} is not documented, and no matching documented flag was found")
    return errors


def mcp_lists() -> tuple[list[str], list[str]]:
    proc = subprocess.Popen(
        [BIN, "mcp", "serve", "--daemon-url", "http://127.0.0.1:9", "--allow-operate-writes"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def call(message_id: int, method: str) -> dict:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": message_id, "method": method, "params": {}}) + "\n")
        proc.stdin.flush()
        while True:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError(f"mcp serve exited before answering {method}")
            message = json.loads(line)
            if message.get("id") == message_id:
                return message["result"]

    try:
        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "docs-audit", "version": "0"}},
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        proc.stdout.readline()
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        tools = [tool["name"] for tool in call(1, "tools/list")["tools"]]
        resources = [resource["uri"] for resource in call(2, "resources/list")["resources"]]
    finally:
        proc.kill()
        proc.wait()
    return tools, resources


def check_mcp() -> list[str]:
    tools, resources = mcp_lists()
    errors = []
    for path in MCP_DOCS:
        text = read(path)
        rel = path.relative_to(ROOT)
        errors += [f"{rel} does not mention the MCP tool {tool}" for tool in tools if not re.search(rf"\b{tool}\b", text)]
        errors += [f"{rel} does not mention the MCP resource {uri}" for uri in resources if uri not in text]
        errors += [f"{rel} mentions {uri}, which the server does not list" for uri in sorted(set(re.findall(r"rsigma://[a-z0-9/_-]+", text)) - set(resources))]
    return errors


def normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def check_backend_samples() -> list[str]:
    errors = []
    targets = run(["backend", "targets"]).stdout.split("\n\n", 1)[0]
    page = {normalize(line) for line in read(CONTENT / "cli" / "backend" / "targets.md").splitlines()}
    errors += [f"cli/backend/targets.md sample is missing `{normalize(line)}`" for line in targets.splitlines() if line.strip() and normalize(line) not in page]
    formats_page = read(CONTENT / "cli" / "backend" / "formats.md")
    page = {normalize(line) for line in formats_page.splitlines()}
    for target in re.findall(r"^rsigma backend formats ([a-z0-9]+)$", formats_page, re.M):
        output = run(["backend", "formats", target]).stdout
        errors += [
            f"cli/backend/formats.md {target} sample is missing `{normalize(line)}`"
            for line in output.splitlines()
            if line.strip() and normalize(line) not in page
        ]
    return errors


def yaml_blocks():
    files = sorted(CONTENT.rglob("*.md")) + sorted(ROOT.glob("crates/*/README.md")) + [ROOT / "README.md"]
    for path in files:
        text = read(path)
        for match in re.finditer(r"^```ya?ml[^\n]*\n(.*?)^```", text, re.S | re.M):
            yield path, text[: match.start()].count("\n") + 1, match.group(1)


def classify(body: str) -> str | None:
    if re.search(r"\.\.\.|\u2026|<[A-Za-z_][^>\n]*>", body):
        return None
    documents = [doc for doc in re.split(r"^---\s*$", body, flags=re.M) if doc.strip()]
    tops = [set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*):", doc, re.M)) for doc in documents]
    if not tops or not all(tops):
        return None
    if any({"detection", "correlation"} & keys or {"filter", "logsource"} <= keys for keys in tops):
        return "rule" if all("title" in keys or "action" in keys for keys in tops) else None
    if "transformations" in tops[0]:
        return "pipeline"
    if tops[0] & (CONFIG_SECTIONS - {"version"}) and tops[0] <= CONFIG_SECTIONS:
        return "config"
    return None


def check_examples() -> list[str]:
    errors = []
    for path, line, body in yaml_blocks():
        kind = classify(body)
        if kind is None:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            example = tmpdir / "example.yml"
            example.write_text(body, encoding="utf-8")
            if kind == "rule":
                proc = run(["rule", "validate", "-v", str(example)], cwd=tmpdir)
                tail = proc.stdout.split("Compile errors:\n")[-1]
                if proc.returncode != 0 and re.fullmatch(r"(?:\s*- [^\n]*: unknown rule reference: [^\n]*\n?)+", tail):
                    continue
            elif kind == "pipeline":
                rule = tmpdir / "rule.yml"
                rule.write_text(TRIVIAL_RULE, encoding="utf-8")
                proc = run(["rule", "fields", "-r", str(rule), "-p", str(example)], cwd=tmpdir)
            else:
                proc = run(["config", "validate", "--config", str(example)], cwd=tmpdir)
                if proc.returncode == 0 and re.search(r'"unknown_keys":\s*\[\s*"', proc.stdout):
                    errors.append(f"{path.relative_to(ROOT)}:{line} config example has unknown keys")
                    continue
            if proc.returncode != 0:
                detail = (proc.stdout + proc.stderr).strip().splitlines()[-1:] or [""]
                errors.append(f"{path.relative_to(ROOT)}:{line} {kind} example fails: {detail[0]}")
    return errors


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


CHECKS = [check_cli_flags, check_config, check_mcp, check_backend_samples, check_examples]


def main() -> int:
    global BIN
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--bin", required=True, help="path to an rsigma binary built with --all-features")
    BIN = str(Path(parser.parse_args().bin).resolve())
    failed = 0
    for check in CHECKS:
        errors = check()
        print(f"{'FAIL' if errors else 'ok  '} {check.__name__.removeprefix('check_')}")
        for error in errors:
            print(f"     {error}")
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
