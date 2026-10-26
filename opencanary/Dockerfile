FROM python:3.12-slim

RUN pip install --no-cache-dir opencanary \
 && mkdir -p /etc/opencanaryd /var/log/opencanary \
 && cd /etc/opencanaryd && opencanaryd --copyconfig \
 && openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/opencanaryd/privkey.pem \
      -out /etc/opencanaryd/cert.pem \
      -days 3650 -subj "/CN=fileserver.local" 2>/dev/null

COPY patch_config.py /tmp/patch_config.py
RUN python3 /tmp/patch_config.py /etc/opencanaryd/opencanary.conf

# twistd writes its pid file in the working directory; /tmp is a
# writable tmpfs in the compose service.
WORKDIR /tmp
# --dev runs twistd in the foreground (the --start mode daemonizes,
# which ends the container). Ports are bound before the drop to
# nobody/nogroup.
CMD ["opencanaryd", "--dev", "--uid=nobody", "--gid=nogroup"]
