#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fault-injecting upstream for R-004 lazy fetch (plays the GitHub asset host).

Listens on 127.0.0.1 only. Serves files from one directory:

  /files/NAME      the file
  /truncate/NAME   full Content-Length, half the bytes, then close
  /stall/NAME      full Content-Length, 64 KiB, then silence
  /wrong/NAME      same length, first byte changed
  /badlen/NAME     Content-Length one byte larger than the file
  /slow/NAME       the file at about 1 MiB/s
  /r/ok/NAME       relative redirect to /files/NAME
  /r/loopback      redirect to http://127.0.0.1:22/x
  /r/private       redirect to http://10.0.0.1/x
  /r/metadata      redirect to http://169.254.169.254/latest/meta-data/
  /r/v6            redirect to http://[::1]:18090/files/x
  /r/https         redirect to https://example.com/x
  /r/loop          redirect to itself
  /stats           JSON request counts per path
"""

import http.server
import json
import pathlib
import sys
import threading
import time

ROOT = pathlib.Path(sys.argv[1]).resolve()
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18090
COUNTS = {}
LOCK = threading.Lock()
REDIRECTS = {
    "loopback": "http://127.0.0.1:22/x",
    "private": "http://10.0.0.1/x",
    "metadata": "http://169.254.169.254/latest/meta-data/",
    "v6": "http://[::1]:18090/files/x",
    "https": "https://example.com/x",
    "loop": "/r/loop",
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("upstream " + (fmt % args) + "\n")

    def send_plain(self, code, body=b"", headers=()):
        self.send_response(code)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def file(self, name):
        if "/" in name or name.startswith("."):
            return None
        path = ROOT / name
        return path.read_bytes() if path.is_file() else None

    def do_GET(self):
        with LOCK:
            COUNTS[self.path] = COUNTS.get(self.path, 0) + 1
        parts = self.path.strip("/").split("/")
        if parts == ["stats"]:
            with LOCK:
                body = json.dumps(COUNTS, sort_keys=True).encode()
            return self.send_plain(200, body)
        if len(parts) == 2 and parts[0] == "r" and parts[1] in REDIRECTS:
            return self.send_plain(302, headers=[("Location", REDIRECTS[parts[1]])])
        if len(parts) == 3 and parts[:2] == ["r", "ok"]:
            return self.send_plain(302, headers=[("Location", "/files/" + parts[2])])
        if len(parts) != 2:
            return self.send_plain(404)
        mode, name = parts
        data = self.file(name)
        if data is None:
            return self.send_plain(404)
        if mode == "files":
            return self.send_plain(200, data)
        self.send_response(200)
        length = len(data) + 1 if mode == "badlen" else len(data)
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.end_headers()
        if mode == "truncate":
            self.wfile.write(data[: len(data) // 2])
        elif mode == "stall":
            self.wfile.write(data[:65536])
            self.wfile.flush()
            time.sleep(120)
        elif mode == "wrong":
            self.wfile.write(bytes([data[0] ^ 0xFF]) + data[1:])
        elif mode == "badlen":
            self.wfile.write(data)
        elif mode == "slow":
            for offset in range(0, len(data), 65536):
                self.wfile.write(data[offset : offset + 65536])
                time.sleep(0.0625)
        self.close_connection = True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    Server(("127.0.0.1", PORT), Handler).serve_forever()
