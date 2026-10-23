"""mcp-bh-only tests: per-scan SARIF output, client-config discovery, and standalone hygiene."""
import json
import os

from test_mcp_kit import enum, run, server, ROOT  # noqa: F401  (server is a fixture)


def test_no_orchestrator_dependency():
    for d, _, fs in os.walk(ROOT):
        if ".git" in d:
            continue
        for f in fs:
            if f.endswith((".sh", ".py")) and f not in ("test_kit.py", "test_extras.py", "test_mcp_kit.py"):
                assert "egress-env" not in open(os.path.join(d, f)).read()




# ── SARIF ──
def check_sarif(path, expect_rules=None, min_results=0):
    doc = json.loads(open(path).read())
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run_ = doc["runs"][0]
    assert run_["tool"]["driver"]["name"] and isinstance(run_["tool"]["driver"]["rules"], list)
    rule_ids = {r["id"] for r in run_["tool"]["driver"]["rules"]}
    assert len(run_["results"]) >= min_results
    for r in run_["results"]:
        assert r["ruleId"] in rule_ids and r["level"] in ("error", "warning", "note", "none")
        assert r["message"]["text"]
        for loc in r.get("locations", []):
            assert all(l["name"] for l in loc["logicalLocations"])
    if expect_rules:
        assert expect_rules <= {r["ruleId"] for r in run_["results"]}
    return doc


def test_sarif_poison_shadow_and_diff(server, tmp_path):
    _, clean = enum(server, "clean", tmp_path)
    _, bad = enum(server, "poisoned", tmp_path)
    _, shadow = enum(server, "shadow", tmp_path)
    _, rug = enum(server, "rugpull", tmp_path)
    run("poison-scan", "scan", clean, bad, shadow, "--out", str(tmp_path / "o1"), "--sarif", str(tmp_path / "ps.sarif"))
    check_sarif(tmp_path / "ps.sarif", {"MCP03-poisoning", "MCP03-shadowing", "MCP03-duplicate-tool"}, 3)
    run("poison-scan", "diff", "--baseline", clean, "--current", rug, "--out", str(tmp_path / "o2"), "--sarif", str(tmp_path / "d.sarif"))
    check_sarif(tmp_path / "d.sarif", {"MCP03-rugpull"}, 1)
    run("poison-scan", "scan", clean, "--out", str(tmp_path / "o3"), "--sarif", str(tmp_path / "none.sarif"))
    assert check_sarif(tmp_path / "none.sarif")["runs"][0]["results"] == []


def test_sarif_shadow_scan_and_confirm(server, tmp_path):
    url, _ = server()
    paths = tmp_path / "p.txt"
    paths.write_text("/mcp\n")
    run("shadow-scan", url.rsplit("/mcp", 1)[0], "--paths", str(paths), "--out", str(tmp_path / "s"), "--sarif", str(tmp_path / "s.sarif"))
    check_sarif(tmp_path / "s.sarif", {"MCP09-shadow-server"}, 1)
    common = ["confirm", "authz", "--base-url", url, "--tool", "get_record", "--id-param", "recordId",
              "--own-id", "1001", "--victim-id", "1002", "--nonexistent-id", "999999"]
    run(*common, "--victim-marker", "Lucinda", "--sarif", str(tmp_path / "c.sarif"))
    doc = check_sarif(tmp_path / "c.sarif", {"MCP02-authz"}, 1)
    assert doc["runs"][0]["results"][0]["level"] == "error"
    run(*common, "--victim-marker", "zzz-absent", "--sarif", str(tmp_path / "n.sarif"))
    assert all(r["level"] != "error" for r in check_sarif(tmp_path / "n.sarif")["runs"][0]["results"])


# ── discover ──
def test_discover_lists_and_redacts(tmp_path):
    home = tmp_path / "home"
    def w(rel, doc):
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc))
    SECRET = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    w(".config/Claude/claude_desktop_config.json", {"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "server-files", "--api-key", SECRET, "/data"], "env": {"API_TOKEN": SECRET}}}})
    w("Library/Application Support/Claude/claude_desktop_config.json", {"mcpServers": {"mac": {"command": "uvx", "args": ["x"]}}})
    w(".claude.json", {"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.test/mcp?token=" + SECRET + "&v=1",
                                               "headers": {"Authorization": "Bearer " + SECRET}}},
                       "projects": {"/proj": {"mcpServers": {"proj-srv": {"type": "sse", "url": "https://u:pw@mcp.example.test/sse"}}}}})
    w(".cursor/mcp.json", {"mcpServers": {"cur": {"url": "https://mcp.example.test/sse"}}})
    w(".config/Code/User/mcp.json", {"servers": {"vs": {"command": "node", "args": ["srv.js", "--token=" + SECRET]}}})
    w(".codeium/windsurf/mcp_config.json", {"mcpServers": {"ws": {"serverUrl": "https://mcp.example.test/mcp"}}})
    (home / "empty").mkdir()
    r = run("discover", "--home", str(home), "--cwd", str(home / "empty"), "--json")
    assert r.returncode == 0, r.stderr
    assert SECRET not in r.stdout and "pw@" not in r.stdout
    got = {(x["client"], x["name"]): x for x in json.loads(r.stdout)}
    assert got[("claude-desktop", "files")]["transport"] == "stdio"
    assert got[("claude-desktop", "files")]["env_vars"] == ["API_TOKEN"]
    assert "***" in got[("claude-desktop", "files")]["target"] and "/data" in got[("claude-desktop", "files")]["target"]
    assert got[("claude-desktop", "mac")]["transport"] == "stdio"
    assert got[("claude-code", "remote")]["transport"] == "http" and "token=***" in got[("claude-code", "remote")]["target"]
    assert got[("claude-code", "proj-srv")]["transport"] == "sse" and got[("claude-code", "proj-srv")]["scope"] == "project"
    assert got[("cursor", "cur")]["transport"] == "sse"
    assert "--token=***" in got[("vscode", "vs")]["target"]
    assert got[("windsurf", "ws")]["transport"] == "http"
    r = run("discover", "--home", str(tmp_path / "nothing"), "--cwd", str(tmp_path / "nothing"))
    assert "no MCP client configs" in r.stdout
