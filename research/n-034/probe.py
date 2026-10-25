#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""N-034 probe: try to bind (and listen on) an address, print the outcome.

    probe.py bind HOST PORT [reuseport]  -> "bound" or the errno name
    probe.py connect HOST PORT           -> "connected" or the errno name

Runs as the unprivileged test user; prints one word, exits 0 either way.
"""

import errno
import socket
import sys


def main() -> None:
    action, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if action == "bind":
            if len(sys.argv) > 4 and sys.argv[4] == "reuseport":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind((host, port))
            sock.listen(1)
            print("bound")
        elif action == "connect":
            sock.settimeout(5)
            sock.connect((host, port))
            print("connected")
        else:
            print("usage")
    except OSError as error:
        print(errno.errorcode.get(error.errno, str(error.errno)))
    finally:
        sock.close()


main()
