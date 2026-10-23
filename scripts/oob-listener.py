#!/usr/bin/env python3
"""oob-listener.py - minimal out-of-band HTTP callback recorder.

Records GET/POST /h/<nonce> as one JSON line in $MCP_BH_OOB_LOG (default
./mcp-bh-out/oob-hits.jsonl). Everything else returns 404. Used to prove a blind SSRF or
command-injection fired through an MCP tool: the tool is handed http://<host>:<port>/h/<nonce>
and a recorded hit for that nonce is the evidence.

  mcp-bh oob-listener [--host 127.0.0.1] [--port 18080]
Only run it where you control the network path; bind a public address only for authorized tests.
"""
import argparse
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.path.expanduser(os.environ.get("MCP_BH_OOB_LOG", "mcp-bh-out/oob-hits.jsonl"))
_lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    def _rec(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) == 2 and parts[0] == "h" and parts[1]:
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "nonce": parts[1],
                   "method": self.command, "port": self.server.server_port,
                   "src_ip": self.client_address[0],
                   "user_agent": self.headers.get("User-Agent", "")}
            with _lock:
                os.makedirs(os.path.dirname(os.path.abspath(LOG)), exist_ok=True)
                with open(LOG, "a") as fh:
                    fh.write(json.dumps(rec) + "\n")
            self.send_response(200)
            body = b"ok"
        else:
            self.send_response(404)
            body = b""
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _rec

    def log_message(self, *a):
        pass


def make_server(host="127.0.0.1", port=18080):
    return ThreadingHTTPServer((host, port), H)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    a = ap.parse_args()
    print(f"listening on {a.host}:{a.port}, log {LOG}")
    make_server(a.host, a.port).serve_forever()
