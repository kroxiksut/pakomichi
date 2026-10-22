# SPDX-License-Identifier: MIT OR Apache-2.0
"""Serve the R-001 repositories on loopback and log every request.

Each log line records the Host header, path, status, and size, so a run can
show which URI (and therefore which repository instance) a package manager
actually fetched. Usage: python3 -I repo-server.py SERVED_DIR LOG_FILE [PORT]
"""

import functools
import http.server
import sys
import threading
import time


class Handler(http.server.SimpleHTTPRequestHandler):
    log = None
    # Parallel downloads log from several threads; appends on a Windows-backed
    # mount are not atomic, so serialize the writes.
    lock = threading.Lock()

    def log_request(self, code="-", size="-"):
        host = self.headers.get("Host", "-")
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {host} {self.command} {self.path} {code} {size}\n"
        with self.lock:
            self.log.write(line)
            self.log.flush()

    def log_message(self, *args):
        pass


def main():
    served, log_file = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 18081
    Handler.log = open(log_file, "a", encoding="utf-8")
    handler = functools.partial(Handler, directory=served)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"serving {served} on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
