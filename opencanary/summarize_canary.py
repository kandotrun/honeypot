#!/usr/bin/env python3
"""Summarize one JST day of OpenCanary events as JSON.

Usage: summarize_canary.py <logfile> [YYYY-MM-DD]
Reads the OpenCanary JSON-lines log (stdin when the path is "-"),
converts each event's utc_time to JST, and keeps the target date
(default: yesterday JST). Startup noise (logtype 1001) is excluded.
"""
import collections
import datetime
import json
import sys

JST = datetime.timezone(datetime.timedelta(hours=9))


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/opencanary/opencanary.log"
    if len(sys.argv) > 2:
        target = sys.argv[2]
    else:
        target = (datetime.datetime.now(JST) - datetime.timedelta(days=1)).strftime("%Y-%m-%d")

    src = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    events = 0
    by_port = collections.Counter()
    ips = collections.Counter()
    creds = collections.Counter()
    redis_cmds = collections.Counter()
    http_paths = collections.Counter()
    for line in src:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("logtype") == 1001:
            continue
        try:
            utc = datetime.datetime.strptime(e["utc_time"], "%Y-%m-%d %H:%M:%S.%f")
        except (KeyError, ValueError):
            continue
        if utc.replace(tzinfo=datetime.timezone.utc).astimezone(JST).strftime("%Y-%m-%d") != target:
            continue
        events += 1
        by_port[str(e.get("dst_port"))] += 1
        if e.get("src_host"):
            ips[e["src_host"]] += 1
        data = e.get("logdata") or {}
        if data.get("USERNAME"):
            creds[f"{data.get('USERNAME')}/{data.get('PASSWORD', '')}"] += 1
        if data.get("CMD"):
            redis_cmds[str(data["CMD"])] += 1
        if data.get("PATH"):
            http_paths[str(data["PATH"])] += 1

    print(json.dumps({
        "date": target,
        "events": events,
        "unique_ips": len(ips),
        "by_port": by_port.most_common(),
        "top_ips": ips.most_common(5),
        "top_credentials": creds.most_common(5),
        "top_redis_cmds": redis_cmds.most_common(5),
        "top_http_paths": http_paths.most_common(5),
    }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
