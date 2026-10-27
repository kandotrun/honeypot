#!/usr/bin/env python3
"""Summarize one day of Cowrie JSON logs.

Usage: summarize.py <cowrie.json> [YYYY-MM-DD JST date, default: yesterday JST]
Reads cowrie.json (JSON lines), filters events whose timestamp falls on
the target date in Asia/Tokyo, prints a compact Japanese-ready summary
as JSON on stdout for the reporting cron to format.
"""
import sys, json, collections
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))

def main():
    path = sys.argv[1]
    if len(sys.argv) > 2:
        target = sys.argv[2]
    else:
        target = (datetime.now(JST) - timedelta(days=1)).strftime("%Y-%m-%d")

    ips = collections.Counter()
    pairs = collections.Counter()
    commands = collections.Counter()
    downloads = []
    sessions = set()
    connects = 0
    logins_ok = 0
    logins_ng = 0

    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            ts = e.get("timestamp", "")
            # cowrie timestamps are UTC ISO; convert to JST date
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                day = dt.astimezone(JST).strftime("%Y-%m-%d")
            except Exception:
                continue
            if day != target:
                continue
            ev = e.get("eventid", "")
            ip = e.get("src_ip", "")
            if ip:
                ips[ip] += 1
            if e.get("session"):
                sessions.add(e["session"])
            if ev == "cowrie.session.connect":
                connects += 1
            elif ev in ("cowrie.login.success", "cowrie.login.failed"):
                u = e.get("username", "?")
                p = e.get("password", "?")
                pairs[(u, p)] += 1
                if ev == "cowrie.login.success":
                    logins_ok += 1
                else:
                    logins_ng += 1
            elif ev == "cowrie.command.input":
                cmd = (e.get("input") or "").strip()
                if cmd:
                    commands[cmd.split()[0]] += 1
            elif ev == "cowrie.session.file_download":
                downloads.append({
                    "url": e.get("url", ""),
                    "ip": ip,
                })

    out = {
        "date": target,
        "connects": connects,
        "unique_ips": len(ips),
        "top_ips": ips.most_common(10),
        "sessions": len(sessions),
        "login_success": logins_ok,
        "login_failed": logins_ng,
        "top_credentials": [[f"{u}/{p}", c] for (u, p), c in pairs.most_common(10)],
        "top_commands": commands.most_common(15),
        "downloads": downloads[:20],
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
