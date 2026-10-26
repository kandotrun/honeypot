#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
pid=''
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
WP_PORT=18080 WP_LOG="$tmp/wp.jsonl" WP_CERT="$tmp/missing.pem" WP_KEY="$tmp/missing.key" python3 app.py >"$tmp/server.out" 2>"$tmp/server.err" &
pid=$!
ready=false
for attempt in $(seq 1 50); do
  if curl -fsS http://127.0.0.1:18080/ -o /dev/null 2>/dev/null; then ready=true; break; fi
  sleep 0.1
done
if [ "$ready" != true ]; then echo 'FAIL server startup'; cat "$tmp/server.err"; exit 1; fi
base=http://127.0.0.1:18080
curl -fsS "$base/" -o /dev/null
curl -fsS "$base/wp-login.php" -o /dev/null
curl -fsS -d 'log=admin&pwd=secret123' "$base/wp-login.php" -o /dev/null
curl -fsS -H 'Content-Type: text/xml' --data '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>admin</string></value><value><string>hunter2</string></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>' "$base/xmlrpc.php" -o /dev/null
curl -fsS "$base/wp-json/wp/v2/users" -o /dev/null
curl -fsS "$base/wp-content/plugins/akismet/readme.txt" -o /dev/null
curl -sS "$base/.env" -o /dev/null
failed=0
check() {
  if grep -E "$2" "$tmp/wp.jsonl" >/dev/null; then echo "PASS $1"; else echo "FAIL $1"; failed=1; fi
}
check 'wp_login captures secret123' '"event": "wp_login".*"password": "secret123"'
check 'xmlrpc event logged' '"event": "xmlrpc"'
check 'xmlrpc captures hunter2' '"xmlrpc_pass": "hunter2"'
check 'exploit_probe for /.env logged' '"path": "/\.env".*"event": "exploit_probe"'
exit "$failed"
