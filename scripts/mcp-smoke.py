#!/usr/bin/env python3
"""Smoke-test a built ``rsigma mcp serve`` binary end to end.

Drives the MCP server over stdio (default) or Streamable HTTP (``--http``),
runs the full surface (all 12 tools and 4 resources), and prints a pass/fail
summary. This is a quick post-build sanity check against a real binary; CI
correctness is covered by the crate's Rust tests (``crates/rsigma-mcp/tests``
and the per-tool unit tests).

The ``mcp`` Cargo feature is opt-in, so build with it first::

    cargo build --release -p rsigma --features mcp

Then::

    python3 scripts/mcp-smoke.py                    # stdio transport
    python3 scripts/mcp-smoke.py --http             # Streamable HTTP + bearer auth
    python3 scripts/mcp-smoke.py --bin path/to/rsigma --port 39517

Exits 0 on full success, 1 otherwise. Uses only the Python standard library.
"""
import argparse
import json
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

VALID_RULE = r"""
title: Whoami Execution
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
level: low
"""

# Uppercase `Status` triggers the fixable non_lowercase_key lint rule.
LINT_RULE = r"""
title: Whoami Execution
id: 22222222-2222-2222-2222-222222222222
Status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
level: low
"""

EVENT = {"Image": r"C:\Windows\System32\whoami.exe"}

INIT_PARAMS = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "rsigma-mcp-smoke", "version": "0"},
}

# (tool name, arguments) covering every tool.
TOOL_CALLS = [
    ("parse_rule", {"yaml": VALID_RULE}),
    ("parse_condition", {"condition": "selection and not filter"}),
    ("lint_rules", {"yaml": LINT_RULE}),
    ("validate_rules", {"yaml": VALID_RULE}),
    ("evaluate_events", {"yaml": VALID_RULE, "events": [EVENT]}),
    ("convert_rules", {"yaml": VALID_RULE, "target": "postgres"}),
    ("list_backends", {}),
    ("list_fields", {"yaml": VALID_RULE}),
    ("resolve_pipeline", {"pipeline": "sysmon"}),
    ("list_builtin_pipelines", {}),
    ("fix_rules", {"yaml": LINT_RULE}),
    ("author_ads", {"yaml": VALID_RULE}),
]

RESOURCES = [
    "rsigma://lint/catalogue",
    "rsigma://ads/schema",
    "rsigma://reference/modifiers",
    "rsigma://reference/mitre-tactics",
]

TIMEOUT_S = 15


class Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _on_alarm)


class StdioClient:
    """MCP client over newline-delimited JSON-RPC on the server's stdio."""

    transport = "stdio"

    def __init__(self, bin_path):
        self._id = 0
        self._stderr = open("/tmp/rsigma-mcp-smoke.stdio.stderr.log", "w")
        self.proc = subprocess.Popen(
            [bin_path, "mcp", "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
            bufsize=1,
        )

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        signal.alarm(TIMEOUT_S)
        try:
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError(f"server closed stdout awaiting {method}")
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("id") == self._id:
                    return obj
        except Timeout:
            raise RuntimeError(f"timed out awaiting {method}")
        finally:
            signal.alarm(0)

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.terminate()
        self._stderr.close()


class HttpClient:
    """MCP client over Streamable HTTP with bearer-token auth."""

    transport = "http"

    def __init__(self, bin_path, host, port):
        self.url = f"http://{host}:{port}/mcp"
        self.token = secrets.token_urlsafe(16)
        self.session = None
        self._id = 0
        self._stderr = open("/tmp/rsigma-mcp-smoke.http.stderr.log", "w")
        self.proc = subprocess.Popen(
            [bin_path, "mcp", "serve", "--http", f"{host}:{port}",
             "--auth-token", self.token],
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
            text=True,
        )
        for _ in range(50):
            with socket.socket() as s:
                s.settimeout(0.2)
                if s.connect_ex((host, port)) == 0:
                    break
            time.sleep(0.1)
        else:
            raise RuntimeError("server never bound the HTTP port")

    @staticmethod
    def _parse(ctype, raw):
        if "event-stream" in ctype:
            for line in raw.splitlines():
                if line.startswith("data:"):
                    try:
                        return json.loads(line[5:].strip())
                    except Exception:
                        pass
            return None
        return json.loads(raw) if raw.strip() else None

    def _post(self, msg, token):
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("accept", "application/json, text/event-stream")
        if token:
            req.add_header("authorization", f"Bearer {token}")
        if self.session:
            req.add_header("mcp-session-id", self.session)
        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT_S)
        except urllib.error.HTTPError as e:
            return e.code, None
        sid = resp.headers.get("mcp-session-id")
        if sid:
            self.session = sid
        return resp.status, self._parse(resp.headers.get("content-type", ""), resp.read().decode())

    def unauthorized_is_rejected(self):
        """POST initialize without a token; True if the server returns 401."""
        msg = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": INIT_PARAMS}
        code, _ = self._post(msg, token=None)
        return code == 401

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        code, body = self._post(msg, token=self.token)
        if code != 200 or body is None:
            raise RuntimeError(f"{method}: HTTP {code}")
        return body

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._post(msg, token=self.token)

    def close(self):
        self.proc.terminate()
        self._stderr.close()


def _tool_text(result):
    for c in result.get("content", []):
        if c.get("type") == "text":
            return c["text"]
    return ""


def run_suite(client):
    passed = True

    init = client.request("initialize", INIT_PARAMS)
    si = init["result"]["serverInfo"]
    print(f"  initialize: {si.get('name')} {si.get('version')}")
    client.notify("notifications/initialized")

    tools = [t["name"] for t in client.request("tools/list")["result"]["tools"]]
    print(f"  tools/list: {len(tools)} tools")
    passed &= len(tools) == len(TOOL_CALLS)

    tool_ok = 0
    for name, args in TOOL_CALLS:
        resp = client.request("tools/call", {"name": name, "arguments": args})
        if "error" in resp:
            print(f"    [ERROR] {name}: {resp['error']}")
            continue
        res = resp["result"]
        if res.get("isError"):
            print(f"    [isError] {name}: {_tool_text(res)[:120]}")
            continue
        tool_ok += 1
        print(f"    [ok] {name}")
    print(f"  tools: {tool_ok}/{len(TOOL_CALLS)} ok")
    passed &= tool_ok == len(TOOL_CALLS)

    res_uris = [r["uri"] for r in client.request("resources/list")["result"]["resources"]]
    print(f"  resources/list: {len(res_uris)} resources")
    passed &= len(res_uris) == len(RESOURCES)

    res_ok = 0
    for uri in RESOURCES:
        resp = client.request("resources/read", {"uri": uri})
        if "error" in resp or not resp["result"].get("contents"):
            print(f"    [ERROR] {uri}")
            continue
        res_ok += 1
        print(f"    [ok] {uri}")
    print(f"  resources: {res_ok}/{len(RESOURCES)} ok")
    passed &= res_ok == len(RESOURCES)

    return passed


def main():
    ap = argparse.ArgumentParser(description="Smoke-test rsigma mcp serve.")
    ap.add_argument("--http", action="store_true", help="use the Streamable HTTP transport")
    ap.add_argument("--bin", default="./target/release/rsigma", help="path to the rsigma binary")
    ap.add_argument("--port", type=int, default=39517, help="HTTP port (--http only)")
    args = ap.parse_args()

    passed = True
    if args.http:
        print(f"== HTTP transport ({args.bin}) ==")
        client = HttpClient(args.bin, "127.0.0.1", args.port)
        try:
            rejected = client.unauthorized_is_rejected()
            print(f"  auth: request without token -> {'401 (rejected)' if rejected else 'NOT rejected'}")
            passed &= rejected
            passed &= run_suite(client)
        finally:
            client.close()
    else:
        print(f"== stdio transport ({args.bin}) ==")
        client = StdioClient(args.bin)
        try:
            passed &= run_suite(client)
        finally:
            client.close()

    print()
    print("RESULT:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
