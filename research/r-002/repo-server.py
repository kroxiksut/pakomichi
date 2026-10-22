#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Serve only the synthetic R-002 repository tree on loopback."""

from __future__ import annotations

import argparse
import http.server
from pathlib import Path


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format_string: str, *args: object) -> None:
        with LOG.open("a", encoding="utf-8") as stream:
            stream.write(f"{self.address_string()} {format_string % args}\n")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root", type=Path)
parser.add_argument("log", type=Path)
parser.add_argument("--port", type=int, default=18082)
args = parser.parse_args()
ROOT = args.root.resolve(strict=True)
LOG = args.log
LOG.parent.mkdir(parents=True, exist_ok=True)
server = http.server.ThreadingHTTPServer(
    ("127.0.0.1", args.port),
    lambda *handler_args, **kwargs: Handler(*handler_args, directory=str(ROOT), **kwargs),
)
server.serve_forever()
