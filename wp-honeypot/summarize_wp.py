#!/usr/bin/env python3
"""Summarize a Tokyo calendar day's decoy events."""
import collections
import datetime as dt
import json
import os
import sys
from zoneinfo import ZoneInfo


def main():
    tokyo = ZoneInfo('Asia/Tokyo')
    date = os.environ.get('WP_DATE', (dt.datetime.now(tokyo).date() - dt.timedelta(days=1)).isoformat())
    dt.date.fromisoformat(date)
    events, ips, paths, credentials = (collections.Counter() for _ in range(4))
    exploits = []
    total = 0
    for filename in sys.argv[1:] or ['-']:
        stream = sys.stdin if filename == '-' else open(filename, encoding='utf-8')
        try:
            for line in stream:
                try:
                    item = json.loads(line)
                    stamp = dt.datetime.fromisoformat(item['ts'])
                    if stamp.tzinfo is None or stamp.astimezone(tokyo).date().isoformat() != date:
                        continue
                    event, ip, path = item['event'], item['src_ip'], item['path'].split('?', 1)[0]
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                total += 1
                events[event] += 1
                ips[ip] += 1
                paths[path] += 1
                if event == 'wp_login':
                    credentials[(item.get('username', ''), item.get('password', ''))] += 1
                elif event == 'xmlrpc':
                    pairs = item.get('xmlrpc_credentials')
                    if pairs is None and 'xmlrpc_user' in item:
                        pairs = [[item['xmlrpc_user'], item.get('xmlrpc_pass', '')]]
                    for pair in pairs or []:
                        if isinstance(pair, list) and len(pair) == 2 and all(isinstance(v, str) for v in pair):
                            credentials[tuple(pair)] += 1
                if event == 'exploit_probe' and len(exploits) < 10:
                    exploits.append({k: item[k] for k in ('ts', 'src_ip', 'path')})
        finally:
            if stream is not sys.stdin:
                stream.close()
    print(json.dumps({'date': date, 'total': total, 'unique_ips': len(ips),
                      'by_event': dict(events), 'top_ips': ips.most_common(5),
                      'top_paths': paths.most_common(8),
                      'credentials': [[u, p, n] for (u, p), n in credentials.most_common(5)],
                      'exploits': exploits}, ensure_ascii=True))


if __name__ == '__main__':
    main()
