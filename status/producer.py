#!/usr/bin/env python3
"""Realtime honeypot status producer (Sakura VPS).

Tails the Cowrie and OpenCanary JSON logs and writes a compact
status.json (+ a self-contained preview page) every run. Designed
for a 10-second systemd timer: only the last few MB of each log are
read. All timestamps are emitted in JST ISO format.
"""
import collections
import datetime
import json
import os
import sys
import urllib.request

JST = datetime.timezone(datetime.timedelta(hours=9))
OUT_DIR = "/opt/honeypot-status"
COWRIE_LOG = "/opt/cowrie/data/var/log/cowrie/cowrie.json"
CANARY_LOG = "/opt/opencanary/data/logs/opencanary.log"
TAIL_BYTES = 6 * 1024 * 1024
GEO_CACHE_PATH = os.path.join(OUT_DIR, "geo_cache.json")
# The honeypot VPS sits in Sakura's Ishikari (Hokkaido) zone 1.
TARGET = {"name": "石狩", "lat": 43.17, "lon": 141.31}
GEO_MAX_LOOKUPS_PER_RUN = 40


def load_geo_cache():
    try:
        with open(GEO_CACHE_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_geo_cache(cache):
    tmp = GEO_CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, ensure_ascii=False)
    os.replace(tmp, GEO_CACHE_PATH)


def geo_lookup(ips):
    """Resolve IPs to {country, country_name, city, lat, lon} via the
    ip-api batch endpoint (free, no key). Returns {ip: geo} for the
    ones that resolved. Bounded per call; failures stay unknown."""
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        body = json.dumps([
            {"query": ip, "fields": "status,country,countryCode,city,lat,lon,query"}
            for ip in chunk
        ]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=body,
            headers={"Content-Type": "application/json", "User-Agent": "honeypot-status/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                rows = json.loads(r.read())
        except Exception:
            continue
        for row in rows:
            if row.get("status") == "success":
                out[row["query"]] = {
                    "country": row.get("countryCode", ""),
                    "country_name": row.get("country", ""),
                    "city": row.get("city", ""),
                    "lat": row.get("lat"),
                    "lon": row.get("lon"),
                }
    return out


def now_jst():
    return datetime.datetime.now(JST)


def tail_lines(path, max_bytes=TAIL_BYTES):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()
            data = f.read().decode("utf-8", errors="replace")
        return data.splitlines()
    except OSError:
        return []


def parse_ts_cowrie(e):
    try:
        dt = datetime.datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        return dt.replace(tzinfo=datetime.timezone.utc).astimezone(JST)
    except (KeyError, ValueError):
        return None


def parse_ts_canary(e):
    try:
        dt = datetime.datetime.strptime(e["utc_time"], "%Y-%m-%d %H:%M:%S.%f")
        return dt.replace(tzinfo=datetime.timezone.utc).astimezone(JST)
    except (KeyError, ValueError):
        return None


def main():
    now = now_jst()
    today = now.strftime("%Y-%m-%d")
    hour_ago = now - datetime.timedelta(hours=1)
    min_buckets = [0] * 60
    feed = []

    # ---- Cowrie -------------------------------------------------
    c_sessions_today = 0
    c_sessions_1h = 0
    c_logins_today = 0
    c_ips = collections.Counter()
    c_creds = collections.Counter()
    c_cmds = collections.Counter()
    c_downloads = []
    open_sessions = {}
    closed_sessions = set()
    session_ip = {}
    ip_last = {}
    for line in tail_lines(COWRIE_LOG):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = parse_ts_cowrie(e)
        if ts is None:
            continue
        ev = e.get("eventid", "")
        sid = e.get("session")
        if ev == "cowrie.session.connect":
            if sid:
                session_ip[sid] = e.get("src_ip", "")
            if e.get("src_ip"):
                ip_last[e["src_ip"]] = max(ts, ip_last.get(e["src_ip"], ts))
            if ts.strftime("%Y-%m-%d") == today:
                c_sessions_today += 1
                c_ips[e.get("src_ip", "")] += 1
            if ts >= hour_ago:
                c_sessions_1h += 1
                idx = int((now - ts).total_seconds() // 60)
                if 0 <= idx < 60:
                    min_buckets[59 - idx] += 1
            if sid:
                open_sessions[sid] = ts
        elif ev == "cowrie.session.closed":
            if sid:
                closed_sessions.add(sid)
        elif ev == "cowrie.login.success":
            if ts.strftime("%Y-%m-%d") == today:
                c_logins_today += 1
                c_creds[f"{e.get('username', '')}/{e.get('password', '')}"] += 1
            feed.append((ts, "cowrie", e.get("src_ip", ""), "SSH/TELNET ログイン成功",
                         f"{e.get('username', '')}/{e.get('password', '')}"))
        elif ev == "cowrie.command.input":
            if ts.strftime("%Y-%m-%d") == today:
                cmd = (e.get("input") or "").strip()
                if cmd:
                    c_cmds[cmd.split()[0]] += 1
            feed.append((ts, "cowrie", e.get("src_ip", ""), "コマンド実行",
                         (e.get("input") or "")[:60]))
        elif ev == "cowrie.session.file_download":
            if ts.strftime("%Y-%m-%d") == today:
                c_downloads.append({"ts": ts.isoformat(), "src": e.get("src_ip", ""),
                                      "url": (e.get("url") or "")[:120]})
            feed.append((ts, "cowrie", e.get("src_ip", ""), "⚠ ダウンロード",
                         (e.get("url") or "")[:60]))
        elif ev == "cowrie.session.file_upload":
            feed.append((ts, "cowrie", e.get("src_ip", ""), "⚠ アップロード",
                         (e.get("filename") or "")[:60]))
    active = [
        {"src": session_ip.get(sid, ""), "since": ts.isoformat()}
        for sid, ts in open_sessions.items()
        if sid not in closed_sessions and (now - ts).total_seconds() < 300
    ]

    # ---- OpenCanary ---------------------------------------------
    k_events_today = 0
    k_events_1h = 0
    k_ports = collections.Counter()
    k_ips = collections.Counter()
    k_creds = collections.Counter()
    port_names = {"21": "FTP", "80": "HTTP", "443": "HTTPS", "8080": "PROXY",
                  "3306": "MySQL", "1433": "MSSQL", "6379": "Redis",
                  "5900": "VNC", "5060": "SIP"}
    for line in tail_lines(CANARY_LOG):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("logtype") == 1001:
            continue
        ts = parse_ts_canary(e)
        if ts is None:
            continue
        port = str(e.get("dst_port"))
        if ts.strftime("%Y-%m-%d") == today:
            k_events_today += 1
            k_ports[port] += 1
            if e.get("src_host"):
                k_ips[e["src_host"]] += 1
                ip_last[e["src_host"]] = max(ts, ip_last.get(e["src_host"], ts))
            data = e.get("logdata") or {}
            if data.get("USERNAME"):
                k_creds[f"{data.get('USERNAME')}/{data.get('PASSWORD', '')}"] += 1
        if ts >= hour_ago:
            k_events_1h += 1
        data = e.get("logdata") or {}
        detail = ""
        if data.get("USERNAME"):
            detail = f"{data.get('USERNAME')}/{data.get('PASSWORD', '')}"
        elif data.get("CMD"):
            detail = f"CMD {data.get('CMD')}"
        elif data.get("PATH"):
            detail = str(data.get("PATH"))[:60]
        feed.append((ts, "canary", e.get("src_host", ""),
                     f"{port_names.get(port, port)} ポート{port}", detail))

    # ---- Geolocation (cached; bounded lookups per run) ----------
    cache = load_geo_cache()
    merged = c_ips + k_ips
    now_epoch = now.timestamp()
    stale = [ip for ip, _ in merged.most_common(60)
             if ip and (ip not in cache or now_epoch - cache[ip].get("ts", 0) > 30 * 86400)]
    if stale:
        fresh = geo_lookup(stale[:GEO_MAX_LOOKUPS_PER_RUN])
        for ip, geo in fresh.items():
            cache[ip] = {**geo, "ts": now_epoch}
        if fresh:
            save_geo_cache(cache)

    def geo_of(ip):
        g = cache.get(ip)
        if not g:
            return None
        return {"country": g.get("country", ""), "country_name": g.get("country_name", ""),
                "city": g.get("city", ""), "lat": g.get("lat"), "lon": g.get("lon")}

    attackers = []
    for ip, count in merged.most_common(40):
        entry = {"ip": ip, "count": count,
                 "last": ip_last[ip].isoformat() if ip in ip_last else None}
        g = geo_of(ip)
        if g:
            entry.update(g)
        attackers.append(entry)

    feed.sort(key=lambda x: x[0], reverse=True)
    feed_out = [
        {"ts": ts.isoformat(), "sensor": s, "src": src, "kind": kind, "detail": detail,
         "geo": geo_of(src)}
        for ts, s, src, kind, detail in feed[:30]
    ]

    status = {
        "generated_at": now.isoformat(),
        "target": TARGET,
        "attackers": attackers,
        "cowrie": {
            "sessions_today": c_sessions_today,
            "sessions_1h": c_sessions_1h,
            "logins_today": c_logins_today,
            "active_sessions": active,
            "top_ips": c_ips.most_common(5),
            "top_credentials": c_creds.most_common(5),
            "top_commands": c_cmds.most_common(5),
            "downloads_today": c_downloads[-5:],
        },
        "canary": {
            "events_today": k_events_today,
            "events_1h": k_events_1h,
            "by_port": [[f"{port_names.get(p, p)}({p})", n] for p, n in k_ports.most_common()],
            "top_ips": k_ips.most_common(5),
            "top_credentials": k_creds.most_common(5),
        },
        "events_per_minute": min_buckets,
        "feed": feed_out,
    }
    tmp = os.path.join(OUT_DIR, "status.json.tmp")
    with open(tmp, "w") as f:
        json.dump(status, f, ensure_ascii=False, indent=1)
    os.replace(tmp, os.path.join(OUT_DIR, "status.json"))
    print("status.json written", now.isoformat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
