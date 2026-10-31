#!/usr/bin/env python3
"""For-Iran test: is an already Xray-OK config also reachable from Iran?

Method (Check-host.net, no API key, free):
  1. GET https://check-host.net/nodes/hosts, keep nodes whose location
     country is "ir" (live list, not hardcoded: ir6 was offline in a
     2026-10-31 check, ir1 Tehran / ir3 Shiraz / ir5 Tehran were live).
  2. For each unique host:port among the OK configs, start a TCP check:
     GET https://check-host.net/check-tcp?host=<host>:<port>&node=<ir node>...
     This returns a request_id; poll GET /check-result/<id> until every
     node reports (or ~20s timeout).
  3. A host counts as Iran-reachable if at least half of the responding
     Iran nodes returned a TCP time (not null). One ISP alone is not
     enough to call it "for Iran", and one failing ISP alone is not
     enough to drop it either.

Honest limit, stated in README too: this is TCP reachability from
Iran nodes + a full Xray test on the GitHub runner. It is NOT a full
VLESS handshake from inside Iran -- no public API can do that without
a client actually sitting in Iran. A config in vless-for-iran.txt has
passed both gates; a config only in vless-all.txt has passed only the
runner gate. DPI / SNI filtering on a specific Iranian ISP can still
break a config that passes both gates on the test day.

Rate limit: Check-host returns limit_exceeded on the free API if
called too fast. This script tests unique host:port pairs only (not
every config), sleeps between hosts, and retries once after 30s on
limit_exceeded. That is why the Iran stage runs only on the small
OK set, never on the full raw list.

Usage: python3 iran_test.py <ok_plain_file> <out_plain_file> <out_report_json>
"""
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://check-host.net"
HEADERS = {"Accept": "application/json", "User-Agent": "ConfigsHUB-VLESS/1.0"}

def get_json(url: str):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def iran_nodes():
    data = get_json(f"{API}/nodes/hosts")
    nodes = []
    for name, info in data.get("nodes", {}).items():
        loc = info.get("location", [])
        if loc and loc[0] == "ir":
            nodes.append(name)
    return sorted(nodes)

def parse_hostport(cfg: str):
    u = urllib.parse.urlparse(cfg)
    try:
        port = u.port or 443
    except ValueError:
        return None
    if not u.hostname:
        return None
    return f"{u.hostname}:{port}"

def check_host_tcp(hostport: str, nodes, retries=1):
    q = "&".join(f"node={n}" for n in nodes)
    url = f"{API}/check-tcp?host={urllib.parse.quote(hostport)}&{q}"
    for attempt in range(retries + 1):
        data = get_json(url)
        if data.get("error") == "limit_exceeded" and attempt < retries:
            time.sleep(30)
            continue
        rid = data.get("request_id")
        if not rid:
            return {"host": hostport, "ok": False, "error": str(data)[:200]}
        for _ in range(20):
            time.sleep(1)
            res = get_json(f"{API}/check-result/{rid}")
            if res and all(n in res for n in nodes):
                times = {}
                good = 0
                for n in nodes:
                    v = res.get(n)
                    # result is a list of {address, time} or null
                    t = None
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        t = v[0].get("time")
                    times[n] = t
                    if t is not None:
                        good += 1
                return {"host": hostport, "ok": good * 2 >= len(nodes) and good > 0,
                        "good": good, "of": len(nodes), "times": times}
        return {"host": hostport, "ok": False, "error": "result timeout"}
    return {"host": hostport, "ok": False, "error": "limit_exceeded"}

def main():
    ok_file, out_file, report_file = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    configs = [l.strip() for l in ok_file.read_text().splitlines() if l.strip().startswith("vless://")]
    try:
        nodes = iran_nodes()
    except Exception as e:
        print(f"Iran nodes fetch failed ({e}) -- For-Iran file will be empty this run.")
        nodes = []
    print(f"Iran nodes: {nodes}")
    if not nodes:
        print("No Iran nodes online right now -- For-Iran file will be empty.")
        out_file.write_text("", encoding="utf-8")
        Path(report_file).write_text(json.dumps({"iran_nodes": [], "results": []}, indent=2), encoding="utf-8")
        return
    host_to_result = {}
    for cfg in configs:
        hp = parse_hostport(cfg)
        if not hp or hp in host_to_result:
            continue
        try:
            host_to_result[hp] = check_host_tcp(hp, nodes)
        except Exception as e:
            host_to_result[hp] = {"host": hp, "ok": False, "error": str(e)[:200]}
        print(f"{hp}: {host_to_result[hp]}")
        time.sleep(2)
    for_iran = [c for c in configs if host_to_result.get(parse_hostport(c), {}).get("ok")]
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(("\n".join(for_iran) + "\n") if for_iran else "", encoding="utf-8")
    Path(report_file).write_text(json.dumps({"iran_nodes": nodes, "results": host_to_result}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"FOR-IRAN: {len(for_iran)} / {len(configs)}")

if __name__ == "__main__":
    main()
