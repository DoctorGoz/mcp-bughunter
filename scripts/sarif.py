#!/usr/bin/env python3
"""sarif.py - tiny SARIF 2.1.0 writer shared by mcp-bh tools.

Library use: `import sarif; sarif.write(path, rules, results)`.
CLI (used by the bash tools): `sarif.py shadow HITS.jsonl OUT.sarif`.
Findings carry logical locations (server URL / tool name), since MCP has no source files.
"""
import json
import os
import sys

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
RULES = {
    "MCP03-poisoning": "Tool definition contains hidden or manipulative instructions",
    "MCP03-shadowing": "Tool description references a tool from another server",
    "MCP03-duplicate-tool": "Same tool name exposed by more than one server",
    "MCP03-rugpull": "Tool definition changed since the baseline",
    "MCP09-shadow-server": "MCP endpoint found by path probing or declared in a client config (verify it is sanctioned)",
    "MCP02-authz": "Tool call returns another principal's object",
    "MCP05-ssrf": "Tool fetched an attacker-supplied URL (callback observed)",
    "MCP05-injection": "Tool executed attacker-supplied input (callback observed)",
}
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def result(rule, level, text, logical=None, props=None):
    r = {"ruleId": rule, "level": level, "message": {"text": text}}
    if logical:
        r["locations"] = [{"logicalLocations": [{"name": n, "kind": k} for k, n in logical]}]
    if props:
        r["properties"] = props
    return r


def document(results, tool="mcp-bughunter", version="0.2.0"):
    used = sorted({r["ruleId"] for r in results}) or []
    rules = [{"id": i, "shortDescription": {"text": RULES.get(i, i)}} for i in used]
    return {"$schema": SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": tool, "version": version, "rules": rules}},
                      "results": results}]}


def write(path, results):
    if not path:
        return
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(document(results), fh, indent=2)


def from_shadow_hits(jsonl):
    out = []
    for ln in open(jsonl):
        ln = ln.strip()
        if not ln:
            continue
        h = json.loads(ln)
        lvl = "warning" if h.get("verdict") == "mcp-open" else "note"
        out.append(result("MCP09-shadow-server", lvl,
                          f"{h['url']} answered like MCP ({h.get('verdict')}, HTTP {h.get('http')})",
                          [("url", h["url"])], {"verdict": h.get("verdict")}))
    return out


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "shadow":
        write(sys.argv[3], from_shadow_hits(sys.argv[2]))
    else:
        sys.exit("usage: sarif.py shadow HITS.jsonl OUT.sarif")
