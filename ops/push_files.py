#!/usr/bin/env python3
"""Push prepared honeypot files from this workspace to the Sakura VPS
over the Tailscale proxy tunnel, using Muse's SSH key (same transport
as ssh_via_tailscale.py). File contents stream disk -> VPS directly.
Usage: python3 push_files.py
"""
import os, sys

sys.path.insert(0, os.path.expanduser('~/workspace/server-setup'))
sys.path.insert(0, os.path.expanduser('~/workspace/server-setup/pylibs'))
import ssh_via_tailscale as svt  # noqa: E402
import paramiko  # noqa: E402

HOST = '100.124.133.46'
USER = 'ubuntu'
BASE = os.path.expanduser('~/workspace/honeypot')

PAIRS = [
    ('docker-compose.yml', '/opt/cowrie/docker-compose.yml'),
    ('etc/cowrie.cfg', '/opt/cowrie/etc/cowrie.cfg'),
    ('etc/extra-userdb.txt', '/opt/cowrie/etc/extra-userdb.txt'),
    ('block-outbound.sh', '/opt/cowrie/block-outbound.sh'),
    ('summarize.py', '/opt/cowrie/summarize.py'),
    ('daemon.json', '/tmp/daemon.json'),
    ('cowrie-fw.service', '/tmp/cowrie-fw.service'),
    ('logrotate-cowrie', '/tmp/logrotate-cowrie'),
]

def main():
    sock = svt.tunnel_socket(HOST)
    t = paramiko.Transport(sock)
    t.start_client(timeout=20)
    key = paramiko.Ed25519Key.from_private_key_file(os.path.expanduser('~/.ssh/id_ed25519'))
    t.auth_publickey(USER, key)
    for local_rel, remote in PAIRS:
        local = os.path.join(BASE, local_rel)
        data = open(local, 'rb').read()
        tmp = remote + '.tmp'
        ch = t.open_session()
        ch.exec_command(f'cat > {tmp} && mv {tmp} {remote}')
        ch.sendall(data)
        ch.shutdown_write()
        code = ch.recv_exit_status()
        print(f'{local_rel} -> {remote}: {len(data)} bytes, exit={code}')
        if code != 0:
            raise SystemExit(f'push failed for {local_rel}')
    t.close()
    print('ALL_PUSHED')

if __name__ == '__main__':
    main()
