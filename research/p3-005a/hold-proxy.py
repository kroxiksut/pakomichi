#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Loopback proxy that holds chosen requests until a gate file exists.

  hold-proxy.py LISTEN_PORT UPSTREAM_PORT HOLD GATE LOG

The P3-005a scenarios point a client at this proxy to switch generations
between the signed top-level metadata and the files it references (R-004
G2-G4) without a test hook in the production reader. Each connection carries
one request: the proxy rewrites Host to the reader's endpoint, forces
`Connection: close`, waits while the target contains HOLD and GATE is
absent (at most 300 s), forwards, relays the response, and logs one line.
Request bodies are not forwarded (the reader refuses them anyway).
"""

import os
import socket
import socketserver
import sys
import threading
import time

LISTEN, UPSTREAM, HOLD, GATE, LOG = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
LOCK = threading.Lock()


def log(line):
    with LOCK, open(LOG, "a") as handle:
        handle.write(line + "\n")


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
        if HOLD in target and not os.path.exists(GATE):
            log(f"event=hold target={target}")
            deadline = time.time() + 300
            while not os.path.exists(GATE) and time.time() < deadline:
                time.sleep(0.05)
            log(f"event=release target={target}")
        status = "-"
        with socket.create_connection(("127.0.0.1", UPSTREAM)) as upstream:
            upstream.sendall(forwarded.encode("latin-1"))
            first = True
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                if first:
                    status = chunk.split(b" ", 2)[1].decode("latin-1") if b" " in chunk else "-"
                    first = False
                self.request.sendall(chunk)
        log(f"req target={target} status={status}")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", LISTEN), Handler) as server:
        server.serve_forever()
