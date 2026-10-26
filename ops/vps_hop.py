#!/usr/bin/env python3
"""Reach the Sakura VPS (sakura-vps) by hopping through kans-water-server.

Why: this VM's HTTPS proxy CONNECT to 100.124.133.46 started failing with
an empty response on 2026-10-26 (the direct ssh_via_tailscale.py path),
while the same proxy reaches kans-water-server (100.81.23.126) fine and
kans-water-server has a direct tailnet route to the VPS.

Chain: VM --(proxy tunnel)--> kans-water-server sshd (user kan, VM key)
       --(direct-tcpip channel)--> VPS sshd (user ubuntu, VM key)

Usage:
  vps_hop.py run '<command>'
  vps_hop.py put <local_path> <remote_path>
  vps_hop.py get <remote_path> <local_path>
"""
import os
import sys

sys.path.insert(0, os.path.expanduser("~/workspace/server-setup"))
sys.path.insert(0, os.path.expanduser("~/workspace/server-setup/pylibs"))

import paramiko  # noqa: E402
from ssh_via_tailscale import tunnel_socket  # noqa: E402

WSERVER = "100.81.23.126"
VPS = "100.124.133.46"
KEY = os.path.expanduser("~/.ssh/id_ed25519")


def connect():
    # kans-water-server sshd refuses channel forwarding, so a small TCP
    # forwarder runs there as user kan: 100.81.23.126:10022 -> VPS:22.
    # We speak SSH to the VPS end-to-end through it, with this VM's key.
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    sock = tunnel_socket(WSERVER, 10022)
    t2 = paramiko.Transport(sock)
    t2.start_client(timeout=20)
    t2.auth_publickey("ubuntu", key)
    return None, t2


def run_cmd(t, cmd):
    ch = t.open_session()
    ch.exec_command(cmd)
    out, err = b"", b""
    while True:
        if ch.recv_ready():
            out += ch.recv(65536)
        if ch.recv_stderr_ready():
            err += ch.recv_stderr(65536)
        if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
            break
    return ch.recv_exit_status(), out.decode(errors="replace"), err.decode(errors="replace")


def main():
    mode = sys.argv[1]
    t1, t2 = connect()
    try:
        if mode == "run":
            code, out, err = run_cmd(t2, sys.argv[2])
            print(f"RUN code={code}\n{out}{err}")
        elif mode == "put":
            sftp = paramiko.SFTPClient.from_transport(t2)
            sftp.put(sys.argv[2], sys.argv[3])
            sftp.close()
            print("PUT_OK")
        elif mode == "get":
            sftp = paramiko.SFTPClient.from_transport(t2)
            sftp.get(sys.argv[2], sys.argv[3])
            sftp.close()
            print("GET_OK")
        else:
            print("unknown mode", file=sys.stderr)
            return 2
    finally:
        t2.close()
        if t1 is not None:
            t1.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
