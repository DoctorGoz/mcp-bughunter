#!/usr/bin/env python3
"""mcp-discover.py - list MCP servers declared in common client config files (read-only).

Reads (never writes, never connects to anything): Claude Desktop, Claude Code, Cursor, VS Code,
Windsurf configs for macOS and Linux, relative to $HOME and the current directory. Prints server
name, client, transport, and command or URL. Env and header VALUES are never shown; token-like
strings in args and URLs are replaced with ***.

  mcp-bh discover [--home DIR] [--cwd DIR] [--json] [--sarif FILE]
"""
import argparse
import json
import os
import re
import sys

# (client, path relative to home or cwd, base)
LOCATIONS = [
    ("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json", "home"),
    ("claude-desktop", ".config/Claude/claude_desktop_config.json", "home"),
    ("claude-code", ".claude.json", "home"),
    ("claude-code", ".mcp.json", "cwd"),
    ("cursor", ".cursor/mcp.json", "home"),
    ("cursor", ".cursor/mcp.json", "cwd"),
    ("vscode", "Library/Application Support/Code/User/mcp.json", "home"),
    ("vscode", ".config/Code/User/mcp.json", "home"),
    ("vscode", "Library/Application Support/Code/User/settings.json", "home"),
    ("vscode", ".config/Code/User/settings.json", "home"),
    ("vscode", ".vscode/mcp.json", "cwd"),
    ("windsurf", ".codeium/windsurf/mcp_config.json", "home"),
]
SECRET_KEY = re.compile(r"(token|key|secret|auth|passw|sig|credential|bearer)", re.I)
TOKENISH = re.compile(r"(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{8,}|"
                      r"AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+\S+|"
                      r"[A-Za-z0-9+/_-]{32,}={0,2})")


def redact_text(s):
    return TOKENISH.sub("***", s)


def redact_url(u):
    u = re.sub(r"//[^/@\s]+@", "//***@", u)  # userinfo
    u = re.sub(r"([?&][^=&#]*)=([^&#]*)",
               lambda m: m.group(1) + "=" + ("***" if SECRET_KEY.search(m.group(1)) else m.group(2)), u)
    return redact_text(u)


def redact_args(args):
    out, hide_next = [], False
    for a in args:
        a = str(a)
        if hide_next:
            out.append("***"); hide_next = False; continue
        m = re.match(r"^(--?[A-Za-z0-9_-]+)=(.*)$", a)
        if m and SECRET_KEY.search(m.group(1)):
            out.append(m.group(1) + "=***")
        elif a.startswith("-") and SECRET_KEY.search(a) and "=" not in a:
            out.append(a); hide_next = True
        else:
            out.append(redact_url(a) if "://" in a else redact_text(a))
    return out


def servers_in(doc):
    """Yield (scope, name, spec) from every mcpServers/servers mapping in a config document."""
    def maps(d, scope):
        if not isinstance(d, dict):
            return
        for key in ("mcpServers", "servers"):
            if isinstance(d.get(key), dict):
                for n, spec in d[key].items():
                    if isinstance(spec, dict):
                        yield scope, n, spec
        if isinstance(d.get("mcp"), dict):  # VS Code settings.json
            yield from maps(d["mcp"], scope)
    yield from maps(doc, "user")
    if isinstance(doc, dict) and isinstance(doc.get("projects"), dict):  # Claude Code per-project
        for proj, pd in doc["projects"].items():
            yield from maps(pd, "project")


def describe(client, path, scope, name, spec):
    if spec.get("command"):
        transport = "stdio"
        target = " ".join([redact_text(str(spec["command"]))] + redact_args(spec.get("args") or []))
    elif spec.get("url") or spec.get("serverUrl"):
        url = spec.get("url") or spec.get("serverUrl")
        t = str(spec.get("type") or spec.get("transport") or "").lower()
        transport = "sse" if t == "sse" or (not t and url.rstrip("/").endswith("/sse")) else "http"
        target = redact_url(str(url))
    else:
        transport, target = "unknown", ""
    return {"name": name, "client": client, "scope": scope, "config": path,
            "transport": transport, "target": target,
            "env_vars": sorted((spec.get("env") or {}).keys()) if isinstance(spec.get("env"), dict) else [],
            "header_names": sorted((spec.get("headers") or {}).keys()) if isinstance(spec.get("headers"), dict) else []}


def discover(home, cwd):
    found, seen = [], set()
    for client, rel, base in LOCATIONS:
        path = os.path.join(home if base == "home" else cwd, rel)
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            doc = json.load(open(path, errors="ignore"))
        except (ValueError, OSError):
            found.append({"name": "", "client": client, "config": path, "transport": "unparseable", "target": ""})
            continue
        for scope, name, spec in servers_in(doc):
            found.append(describe(client, path, scope, name, spec))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", default=os.path.expanduser("~"))
    ap.add_argument("--cwd", default=os.getcwd())
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sarif", default="", help="also write SARIF 2.1.0 (one note per server)")
    a = ap.parse_args()
    found = discover(a.home, a.cwd)
    if a.sarif:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import sarif
        sarif.write(a.sarif, [sarif.result("MCP09-shadow-server", "note",
                              f"declared server {f['name']} ({f['transport']}) {f['target']}",
                              [("server", f["name"])]) for f in found if f["name"]])
    if a.json:
        print(json.dumps(found, indent=2))
        return
    if not found:
        print("no MCP client configs with servers found")
    for f in found:
        print(f"{f['client']:15} {f['name'] or '-':24} {f['transport']:9} {f['target']}   [{f['config']}]")


if __name__ == "__main__":
    main()
