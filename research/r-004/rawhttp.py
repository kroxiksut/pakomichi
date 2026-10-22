#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Send one raw HTTP request (Python string escapes allowed) and print
'<status> <body-bytes> <leak>' where leak is 1 if the body looks like
/etc/passwd or /etc/shadow content."""

import socket
import sys

request = sys.argv[1].encode().decode("unicode_escape").encode("latin-1")
port = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
with socket.create_connection(("127.0.0.1", port), timeout=15) as conn:
    conn.sendall(request)
    data = b""
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError):
        pass
head, _, body = data.partition(b"\r\n\r\n")
status = head.split(b" ")[1].decode() if head.startswith(b"HTTP/") else "none"
leak = int(b"root:" in body)
print(status, len(body), leak)
