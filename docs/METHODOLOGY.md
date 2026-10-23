# Methodology

Each kit command maps to a check in the OWASP MCP Top 10 (the 2025 community draft; ids may be
renumbered in later revisions) and, where it applies, the OWASP Top 10 for LLM Applications
(2025). "Partial" means the kit supports the check but a human must finish it.

| Check | Command | OWASP MCP | OWASP LLM | Coverage |
|-------|---------|-----------|-----------|----------|
| Secrets in tool/resource output | `enum`, `call --resource` | MCP01 Token mismanagement and secret exposure | LLM02 Sensitive information disclosure | Partial: surfaces resources to read; no secret scanner |
| Server-injected / privileged params | `enum` (atz hints) | MCP02 Privilege escalation via scope creep | LLM06 Excessive agency | Hint only; confirm manually |
| Tool poisoning | `enum`, `poison-scan scan` | MCP03 Tool poisoning | LLM01 Prompt injection (indirect) | Static heuristics; regex families, no semantic model |
| Rug pull / description drift | `poison-scan diff` | MCP03 | LLM01, LLM03 Supply chain | Needs a baseline captured earlier |
| Tool shadowing | `poison-scan scan A B` | MCP03, MCP06 Intent flow subversion | LLM01 | Name-reference heuristic across servers you supply |
| Command injection / SSRF / traversal in tool params | `probe`, `confirm ssrf\|injection` | MCP05 Command injection and execution | LLM05 Improper output handling, LLM06 | Payload fuzz + reflected signatures + optional OOB |
| Cross-object / cross-tenant tool abuse | `confirm authz` | MCP02, MCP07 Insufficient authn/z, MCP10 Context injection and over-sharing | LLM02, LLM06 | 4-way differential; needs two identities |
| Unauthenticated access | `enum` without `--auth` | MCP07 | n/a | Reported as a hint |
| Light param fuzz (leads only) | `fuzz` | MCP05 | LLM05, LLM06 | Fixed ~16 cases per string param, capped at 40 per tool; candidates, never findings |
| Declared servers inventory | `discover` | MCP09 | n/a | Reads local client configs only; does not contact servers |
| Shadow MCP servers | `shadow-scan` | MCP09 Shadow MCP servers | n/a | Path list + JS grep only |
| Audit / telemetry gaps | none | MCP08 Lack of audit and telemetry | n/a | Not testable black-box; out of scope |
| Dependency tampering | none | MCP04 Supply chain | LLM03 | Out of scope (needs source/SBOM) |

## Procedure

1. **Enumerate** read-only (`enum`). Keep the `mcp-assets.json`; it is your baseline.
2. **Static review**: `poison-scan scan` on every server the same agent can reach (pass them all
   together for the shadowing check). Read the raw bytes of anything flagged.
3. **Drift**: re-enumerate on a schedule and `poison-scan diff` against the baseline.
4. **Find leads**: `fuzz` (small, rate-limited, requires `--i-understand-this-calls-tools`) or `probe` (larger wordlists), skipping state-changing and outbound-message tools unless
   you explicitly opt in. Use `safe` for any unattended run.
5. **Confirm** each candidate with a control: a victim marker plus nonexistent-id comparison for
   authz; an OOB nonce for blind execution. Unconfirmed candidates stay candidates.
6. **Export**: `--sarif FILE` on `poison-scan`, `shadow-scan`, `confirm` and `discover` writes SARIF 2.1.0 with logical locations (server, tool) because MCP has no source files. `confirm` emits a result only for confirmed or likely verdicts.
7. **Grade by effect**, not acceptance: a tool that accepted a payload and returned an error is
   not proof of impact.

## Scope

MCP Bughunter does not audit source code, configuration hygiene or SIEM pipelines. See the README's
"When you need more" for tools that do.

## Limits

Heuristics are regexes tuned for English text and produce both false positives (a legitimate tool
that says "you must provide an API key" scores low but non-zero) and false negatives (paraphrased
or non-English instructions). The scorer reads only what `tools/list` returns, not what the
server does at call time.
