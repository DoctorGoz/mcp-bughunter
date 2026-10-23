# MCP Bughunter

A small tool for **confirming and reporting** bugs in Model Context Protocol (MCP) servers. It
is not a full scanner: it enumerates a server, flags suspicious tool definitions, runs a small
fuzz to find leads, and then helps you prove a lead with a control and export the result
(JSON, Markdown, SARIF 2.1.0). When you need broader coverage, see
[When you need more](#when-you-need-more).

The command is `mcp-bh`. It speaks the streamable-HTTP transport (and the legacy HTTP+SSE
transport for enumeration) using `curl` and the Python standard library. No MCP SDK is required.
It does not read or scan server source code.

> **Responsible use.** Only test servers you own or have explicit written authorization to
> test. Several commands send injection payloads and make tool calls. Respect the program's
> rules on automated tooling and rate limits. Use `mcp-bh safe` for hands-off runs.

## What it checks

| Threat | What the kit does |
|--------|-------------------|
| **Tool poisoning** | `poison-scan` scores each tool's name, description and schema text against weighted families (instruction override, concealment, exfil directives, secret solicitation, hidden tags, invisible Unicode) and decodes hidden code points. |
| **Tool shadowing** | `poison-scan scan A B ...` flags a description that names another server's tool, and tool names duplicated across servers. |
| **Rug pull / description drift** | `poison-scan diff --baseline old --current new` reports added, removed and mutated tool definitions. |
| **Over-broad tools** | `enum` lists privileged-looking tools and server-injected parameters (params the schema says the client must not set); `probe` fuzzes string params for command injection, SSRF and traversal; `confirm authz` runs a 4-way differential over a tool call. |
| **Light fuzz** | `fuzz` sends a small fixed payload set per string parameter (traversal, command injection, SSRF to your own callback listener, template injection, oversized and type-confusion values) and reports candidates only. |
| **Shadow servers** | `shadow-scan` probes common MCP paths with a real `initialize` and greps JS bundles for MCP client URLs. |

Note the two senses of "shadow": `poison-scan` finds *tool* shadowing; `shadow-scan` finds
undeclared *servers*.

## Commands

```
mcp-bh enum <url> [--auth "H: v"] [--out DIR] [--proxy URL] [--transport auto|streamable|sse]
mcp-bh poison-scan scan <mcp-assets.json> [more.json ...] [--out DIR]
mcp-bh poison-scan diff --baseline OLD.json --current NEW.json [--out DIR]
mcp-bh call <url> --tool NAME --args '{...}' | --resource URI | --prompt NAME
mcp-bh probe <url> --assets mcp-assets.json [--mode cmdinj|ssrf|traversal|all] [--oob-base URL] [--max-calls N]
mcp-bh fuzz <url> --i-understand-this-calls-tools [--tool NAME] [--oob-base URL] [--include-destructive]
mcp-bh confirm authz|ssrf|injection|oob-poll ...   # --sarif FILE for SARIF
mcp-bh discover [--home DIR] [--json]               # list servers in local client configs
mcp-bh shadow-scan <origin> [--js-dir DIR] [--paths FILE]
mcp-bh oob-listener [--host H] [--port P]
mcp-bh safe enum|probe|call|resource ...     # read-only wrapper for automated runs
```

`--sarif FILE` is available on `poison-scan` (scan and diff), `shadow-scan`, `confirm` and `discover`.
`discover` reads Claude Desktop, Claude Code, Cursor, VS Code and Windsurf configs (macOS and
Linux paths) read-only, and redacts env/header values and token-like strings.

Outputs are plain files under `./mcp-bh-out/<tool>-<timestamp>/` (override with `--out`):
JSON for machines, Markdown for people. `MCP_BH_PROXY` sets an HTTP proxy for curl-based tools.

Requirements: Python 3.9+, bash, curl.

## Quick start (offline, against the bundled fixture)

The fixture is a tiny local MCP server with a benign tool, a poisoned tool, a shadowing tool,
and deliberately vulnerable tools. It binds to 127.0.0.1 only.

```bash
python3 tests/fixture_server.py --variant poisoned --port 8765 &
bin/mcp-bh enum http://127.0.0.1:8765/mcp --out /tmp/poisoned
bin/mcp-bh poison-scan scan /tmp/poisoned/mcp-assets.json --out /tmp/scan
cat /tmp/scan/poison-report.md          # add_numbers flagged critical

# rug pull: enumerate a clean baseline, then the mutated server
kill %1; python3 tests/fixture_server.py --variant clean --port 8765 &
bin/mcp-bh enum http://127.0.0.1:8765/mcp --out /tmp/base
kill %1; python3 tests/fixture_server.py --variant rugpull --port 8765 &
bin/mcp-bh enum http://127.0.0.1:8765/mcp --out /tmp/new
bin/mcp-bh poison-scan diff --baseline /tmp/base/mcp-assets.json --current /tmp/new/mcp-assets.json
kill %1
```

Fuzz the vulnerable variant (it calls tools on the fixture; never point it at a server you do not
own or have permission to test):

```bash
python3 tests/fixture_server.py --variant vuln --port 8765 &
bin/mcp-bh fuzz http://127.0.0.1:8765/mcp --i-understand-this-calls-tools
```

Run the tests: `python3 -m pytest -q tests` (all offline).

## Reading results honestly

- A flagged description is a **review prioritizer**, not a vulnerability. On a first-party
  server a poisoned description is usually by design. It matters when an attacker can introduce or
  alter a description that someone else's agent consumes, or when a definition changes after
  the user approved it.
- A probe `SIGNAL` means the response carried an execution indicator (for example `/etc/passwd`
  content). Confirm with `mcp-bh confirm`, including a negative control, before reporting.
- A blind SSRF or injection (callback only) is a lower rung than one that returns content or
  credentials. `confirm` records the `--channel` you assert; do not inflate it.
- Report coverage with its denominator ("12 of 40 tools probed"), never "secure".

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the mapping to OWASP lists.

## When you need more

MCP Bughunter stays small on purpose. For wider or deeper coverage, these projects (not affiliated
with this one; check each project's own documentation for current features) cover other ground:

- [manthanghasadiya/mcpsec](https://github.com/manthanghasadiya/mcpsec): a Python (3.11+, MIT) security scanner and protocol
  fuzzer for MCP servers. It connects to live servers over stdio or HTTP for runtime scanning and
  fuzzing, and can also audit source (local paths or GitHub repositories) with sink patterns and
  Semgrep rules.
- [pfrederiksen/mcpsec](https://github.com/pfrederiksen/mcpsec): a Go (Apache-2.0) auditor aligned to the OWASP MCP Top 10 beta.
  It checks MCP configurations, keeps multi-client inventories with shadow-server policy checks,
  detects baseline drift, enumerates remote tools read-only, and emits OCSF JSON or Splunk HEC
  events for SIEM pipelines.
- [Semgrep](https://semgrep.dev): static analysis for source code. Use it (or a source auditor above) when you have the
  server's code; MCP Bughunter does not read source.

## License

MIT, see [LICENSE](LICENSE).
