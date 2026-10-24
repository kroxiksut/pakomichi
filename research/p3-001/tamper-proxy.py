#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Loopback proxy in front of the repository reader for the P3-001 runs.

  tamper-proxy.py LISTEN_PORT UPSTREAM_PORT CONTROL GATE LOG

For each request the proxy re-reads CONTROL (JSON, missing = pass through):

  {"hold": "SUBSTRING",                       # wait while GATE is absent
   "rules": [{"match": "SUBSTRING", "from": "TEXT", "to": "TEXT"},
             {"match": "SUBSTRING", "file": "PATH"}]}

The first rule whose `match` is in the request target changes the response
body: `from`/`to` replaces the first occurrence (same length, so only the
bytes change), `file` replaces the whole body. The proxy rewrites Host to
the reader's endpoint, forces `Connection: close`, fixes Content-Length,
and logs one line per request. It stands for a hostile network or mirror
between APT and the local repository; the reader itself is unchanged.
"""

import json
import os
import socket
import socketserver
import sys
import threading
import time

LISTEN, UPSTREAM, CONTROL, GATE, LOG = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
LOCK = threading.Lock()


def log(line):
    with LOCK, open(LOG, "a") as handle:
        handle.write(line + "\n")


def control():
    try:
        with open(CONTROL) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def change(target, body, rules):
    for rule in rules:
        if rule["match"] not in target:
            continue
        if "file" in rule:
            with open(rule["file"], "rb") as handle:
                return handle.read(), "file"
        old, new = rule["from"].encode(), rule["to"].encode()
        if len(old) != len(new) or old not in body:
            return body, "no-match"
        return body.replace(old, new, 1), "replaced"
    return body, "-"


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        target = lines[0].split(" ")[1] if len(lines[0].split(" ")) == 3 else "-"
        kept = [line for line in lines[1:] if not line.lower().startswith(("host:", "connection:"))]
        forwarded = "\r\n".join([lines[0], f"Host: 127.0.0.1:{UPSTREAM}", *kept, "Connection: close"]) + "\r\n\r\n"
        settings = control()
        hold = settings.get("hold")
        if hold and hold in target and not os.path.exists(GATE):
            log(f"event=hold target={target}")
            deadline = time.time() + 300
            while not os.path.exists(GATE) and time.time() < deadline:
                time.sleep(0.05)
            log(f"event=release target={target}")
        response = b""
        with socket.create_connection(("127.0.0.1", UPSTREAM)) as upstream:
            upstream.sendall(forwarded.encode("latin-1"))
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                response += chunk
        header, _, body = response.partition(b"\r\n\r\n")
        status = header.split(b" ", 2)[1].decode("latin-1") if b" " in header else "-"
        action = "-"
        if status == "200" and lines[0].startswith("GET "):
            body, action = change(target, body, settings.get("rules", []))
            fixed = [h for h in header.split(b"\r\n") if not h.lower().startswith(b"content-length:")]
            header = b"\r\n".join(fixed + [b"Content-Length: " + str(len(body)).encode()])
        self.request.sendall(header + b"\r\n\r\n" + body)
        log(f"req target={target} status={status} action={action}")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", LISTEN), Handler) as server:
        server.serve_forever()
