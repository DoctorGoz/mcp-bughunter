#!/usr/bin/env bash
# mcp-readonly-broker.sh — read-only wrapper for hands-off / automated MCP testing.
#
# Use it when something other than you (a script, CI job, or LLM agent) drives the kit and the
# safety of the run must not depend on that driver behaving. It execs only enum/probe/call and:
#   * strips `--include-write` from every passthrough, so the fuzzer's destructive path is
#     unreachable;
#   * refuses `call` and single-tool `probe` on any tool whose name matches a state-changing or
#     outbound-message marker (delete, create, send, feedback, contact, ...). Fail-safe = refuse;
#   * hands the same marker list to the fuzzer as a floor that applies even when the server
#     under test marks a tool readOnlyHint (the server controls that annotation, so it is not trusted);
#   * caps fuzz volume at $MCP_BH_MAX_CALLS (default 60).
# Auth comes from $MCP_BH_AUTH ("Header: value"), so a token need not appear on argv.
#
# Usage:
#   mcp-readonly-broker.sh enum     <url> [opts]
#   mcp-readonly-broker.sh probe    <url> [opts]
#   mcp-readonly-broker.sh call     <url> --tool NAME --args JSON
#   mcp-readonly-broker.sh resource <url> --resource URI [opts]
#   mcp-readonly-broker.sh --selftest
#
# Exit: the underlying script's code; 2 usage; 3 refused (state-changing tool).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# State-changing markers for the `call` guard. Superset of mcp-probe.sh's DESTRUCTIVE set: an
# adaptive single call to a create/send/update tool is itself a mutation, so the read-mostly floor
# is broader than the fuzzer's canary-at-exec-tool skip. Curated to avoid matching common read
# verbs as substrings (no bare set/put/post/patch — they hide in settings/output/compose/dispatch).
# Outbound verbs too (feedback, contact, submit, report...): a call there puts a message in front of
# people at the target, which is a write even when nothing in the product changes.
DESTRUCTIVE_RE='(delete|destroy|remove|drop|purge|revoke|wipe|terminate|deactivate|cancel|uninstall|create|update|write|insert|send|transfer|pay|grant|deploy|install|disable|enable|rotate|modify|overwrite|reset|feedback|contact|message|mail|notify|submit|report|comment|ticket|support|invite|share|publish|reply|book|order|purchase|subscribe|register|upload)'

is_destructive() { echo "${1:-}" | grep -qiE "$DESTRUCTIVE_RE"; }

selftest() {
    local ok=1
    for t in deleteUser destroy_all sendMoney create-token updateProfile revokeKey resetPassword feedback-to-devs submitForm contact_support bookFlight; do
        is_destructive "$t" || { echo "SELFTEST FAIL: '$t' should be destructive"; ok=0; }
    done
    for t in getUser list_tools read_resource searchDocs fetchUrl describe_tool show_config lookup query_db http_get; do
        is_destructive "$t" && { echo "SELFTEST FAIL: '$t' should be allowed"; ok=0; }
    done
    # --include-write must be stripped
    local -a out; mapfile -t out < <(strip_write --tool fetch --include-write --max-calls 5)
    printf '%s\n' "${out[@]}" | grep -q -- '--include-write' && { echo "SELFTEST FAIL: --include-write not stripped"; ok=0; }
    [[ $ok == 1 ]] && { echo "mcp-readonly-broker selftest OK"; return 0; } || return 1
}

# Echo the args with every --include-write removed (one per line, for safe re-capture).
strip_write() {
    local a
    for a in "$@"; do [[ "$a" == "--include-write" ]] && continue; printf '%s\n' "$a"; done
}

main() {
    local sub="${1:-}"
    [[ "$sub" == "--selftest" ]] && { selftest; return $?; }
    shift || true
    local url="${1:-}"; shift || true
    if [[ -z "$sub" || -z "$url" ]]; then
        sed -n "2,22p" "${BASH_SOURCE[0]}" >&2; return 2
    fi


    # Sanitize passthrough: drop --include-write anywhere in the tail.
    local -a args=(); local a
    for a in "$@"; do [[ "$a" == "--include-write" ]] && continue; args+=("$a"); done


    # Auth from the environment, never argv/prompt (unless suppressed).
    local -a auth=()
    if [[ -n "${MCP_BH_AUTH:-}" && "${1:-}" != "--no-auth-env" ]]; then
        auth=(--auth "$MCP_BH_AUTH")
    fi

    case "$sub" in
        enum)     exec bash "$HERE/mcp-enum.sh"  "$url" "${auth[@]}" "${args[@]}" ;;
        probe)
            # The fuzzer skips write-shaped tools by its own, narrower list, and trusts a server's
            # readOnlyHint; hand it this floor, which it applies regardless, and refuse an explicit one.
            local tool="" i
            for ((i=0; i<${#args[@]}; i++)); do
                [[ "${args[$i]}" == "--tool" ]] && { tool="${args[$((i+1))]:-}"; break; }
            done
            if [[ -n "$tool" ]] && is_destructive "$tool"; then
                echo "refused: tool '$tool' matches a state-changing marker — the read-mostly broker will not fuzz it" >&2
                return 3
            fi
            # A hands-off fuzz is bounded: the fuzzer's own default (400 calls) is a manual-run figure.
            local cap="${MCP_BH_MAX_CALLS:-60}" want="" j
            local -a capped=()
            for ((j=0; j<${#args[@]}; j++)); do
                if [[ "${args[$j]}" == "--max-calls" ]]; then want="${args[$((j+1))]:-}"; j=$((j+1)); continue; fi
                capped+=("${args[$j]}")
            done
            [[ "$want" =~ ^[0-9]+$ && "$want" -lt "$cap" ]] && cap="$want"
            GN_SKIP_RE="$DESTRUCTIVE_RE" exec bash "$HERE/mcp-probe.sh" "$url" "${auth[@]}" "${capped[@]}" --max-calls "$cap" ;;
        resource) exec bash "$HERE/mcp-call.sh"  "$url" "${auth[@]}" "${args[@]}" ;;  # --resource read is read-only
        call)
            # Extract --tool NAME and refuse if it looks state-changing.
            local tool="" i
            for ((i=0; i<${#args[@]}; i++)); do
                [[ "${args[$i]}" == "--tool" ]] && { tool="${args[$((i+1))]:-}"; break; }
            done
            if [[ -n "$tool" ]] && is_destructive "$tool"; then
                echo "refused: tool '$tool' matches a state-changing marker — the read-mostly broker will not call it (this is a floor, not a judgement of intent)" >&2
                return 3
            fi
            exec bash "$HERE/mcp-call.sh" "$url" "${auth[@]}" "${args[@]}" ;;
        *) echo "unknown subcommand: $sub (want enum|probe|call|resource)" >&2; return 2 ;;
    esac
}

main "$@"
