"""How the tests spell the kit's commands in this tree: one `mcp-bh` entrypoint."""
import importlib.util
import os
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = [sys.executable, os.path.join(ROOT, "bin", "mcp-bh")]
_SCRUB = ("http_proxy", "https_proxy", "all_proxy", "mcp_bh_proxy", "mcp_bh_auth")
ENV = {k: v for k, v in os.environ.items() if k.lower() not in _SCRUB}
ENV["NO_PROXY"] = "127.0.0.1,localhost"


def run(sub, *args, cwd=None, env=None, timeout=120):
    return subprocess.run(KIT + [sub] + list(args), capture_output=True, text=True, cwd=cwd,
                          env={**ENV, **(env or {})}, timeout=timeout)


def confirm_out(tmp_path, name):
    """Extra confirm flags, and the file the verdict lands in."""
    out = tmp_path / (name + ".json")
    return ["--out", str(out)], out


def oob_env(log):
    return {"MCP_BH_OOB_LOG": str(log)}


def max_calls_env(n):
    return {"MCP_BH_MAX_CALLS": str(n)}


def fuzz_flags(tmp_path):
    return []


def start_oob(log):
    """The kit's OOB listener, bound to loopback on a free port, recording to `log`."""
    spec = importlib.util.spec_from_file_location("oobl", os.path.join(ROOT, "scripts", "oob-listener.py"))
    lst = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lst)
    lst.LOG = str(log)
    srv = lst.make_server("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
