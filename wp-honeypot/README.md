# WordPress honeypot
A small, inert WordPress decoy using only Python 3.12's standard library.
It captures probes and attempted credentials without executing submitted content.
HTTP listens on 8080 and optional TLS on 8443, published as ports 80 and 443.
Prepare writable storage before starting the unprivileged container:
`mkdir -p data certs && sudo chown 65534:65534 data && sudo chmod 700 data`
Place a readable TLS certificate and private key in `certs/cert.pem` and `certs/key.pem`.
Without either certificate file, HTTPS is skipped and HTTP continues.
Build and start with `docker compose up -d --build`.
Stop other decoys using host ports 80/443 before starting this service.
Each request appends one immediately flushed JSON object to `data/wp.jsonl`.
Events include local timezone timestamps, direct peer IPs, paths, and captured bodies.
Credentials are sensitive: restrict log access and apply an appropriate retention policy.
Run `python3 summarize_wp.py data/wp.jsonl` for yesterday's Asia/Tokyo summary.
Choose a date with `WP_DATE=2026-10-25 python3 summarize_wp.py data/wp.jsonl`.
Multiple paths are accepted; use `-` to read JSONL from standard input.
Run `bash smoke_test.sh` to exercise the local HTTP listener on port 18080.
