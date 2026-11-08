#!/usr/bin/env python3
"""Two-stage VLESS liveness test, following the method used by v2all /
MK_XRAYchecker / XrayChecker -- not invented here.

Stage 1 -- TCP ping (cheap filter):
    socket.create_connection(host, port), timeout 4s, 100 workers.
    Drops dead ports and non-routable IPs. TCP-open alone is NOT proof
    of a working proxy, so survivors go to Stage 2.

Stage 2 -- Real Xray handshake (proof):
    For each survivor, generate a minimal Xray config (inbound SOCKS on
    a free local port, outbound = that one VLESS server), start Xray,
    and curl https://www.gstatic.com/generate_204 through the SOCKS
    proxy, timeout 8s. Only HTTP 200/204/301/302 through the proxy
    counts as OK. Latency is the curl time, and OK configs are sorted
    by it, fastest first.

Unsupported, not dead: encryption != none (e.g. mlkem) and transports
outside tcp/ws/grpc/xhttp are collected separately into
vless-unsupported.txt. They are never silently dropped as dead.

Accumulation (2026-11-09): the previous run's healthy configs are
loaded from the plain subscription files already in the checkout and
merged with the fresh scrape before testing, so a working config does
not drop out just because it left the collector's scrape window.
Everything merged is RE-TESTED with both stages; dead configs drop.

Cap and ranking: at most 50 healthy configs per subscription file
(per-country files and the all file, each its own cap of 50). Files
are ordered by the latency measured in Stage 2 (the curl time through
the proxy, ms), lowest first; if more than 50 are healthy, only the
best 50 are kept and the rest are dropped.

Usage (as run on a GitHub Actions runner):
    python3 tester.py <raw_dir> <out_dir> <xray_binary>
    env: TCP_TIMEOUT=4 TCP_WORKERS=100 REAL_TIMEOUT=8 REAL_WORKERS=20

Output in <out_dir>:
    vless-all.txt / vless-<cc>.txt   -- Base64 subscriptions, OK only
    vless-all-plain.txt / vless-<cc>-plain.txt -- same, plain text
    vless-unsupported.txt -- plain, unsupported (not tested)
    report.json -- counts per country: total / tcp_alive / ok /
      unsupported / dropped_by_cap, plus top-level cap and all_ok
      (all counts reflect the capped totals)
"""
import base64
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

PROBE = "https://www.gstatic.com/generate_204"
MAX_PER_FILE = 50  # max healthy configs per subscription file (all + per-country)

def config_key(cfg: str) -> str:
    """Identity of a config for dedup: everything before the remark."""
    return cfg.split("#")[0]

def load_previous(outdir: Path):
    """Previous run's healthy configs, grouped by country code.

    Reads the plain subscription files already in the checkout
    (vless-<cc>-plain.txt). Tolerates them being missing (first run).
    vless-all-plain.txt and vless-for-iran-plain.txt are skipped: they
    are derived files, re-built every run from the country files.
    """
    previous = {}
    for path in sorted(outdir.glob("vless-*-plain.txt")):
        stem = path.name.replace("vless-", "").replace("-plain.txt", "")  # "de" / "all" / "for-iran"
        if stem in ("all", "for-iran"):
            continue
        cc = stem.upper()
        configs = [l.strip() for l in path.read_text().splitlines()
                   if l.strip().startswith("vless://")]
        if configs:
            previous[cc] = configs
    return previous

def merge_configs(fresh, previous):
    """Fresh configs first, then previous healthy ones not already seen.

    Dedup by config key (part before '#'), so a config re-scraped with
    a different remark, or a previous config already renamed by
    final_names.py, still counts as the same config.
    """
    seen = set()
    merged = []
    for cfg in list(fresh) + list(previous):
        key = config_key(cfg)
        if key in seen:
            continue
        seen.add(key)
        merged.append(cfg)
    return merged

def parse_vless(uri: str):
    u = urllib.parse.urlparse(uri)
    if u.scheme != "vless":
        return None
    q = urllib.parse.parse_qs(u.query)
    get = lambda k, d="": q.get(k, [d])[0]
    try:
        port = u.port or 443
    except ValueError:
        return None
    return {
        "uuid": urllib.parse.unquote(u.username or ""),
        "address": u.hostname or "",
        "port": port,
        "encryption": get("encryption", "none"),
        "security": get("security", "none"),
        "type": get("type", "tcp"),
        "host": get("host", ""),
        "path": get("path", "/"),
        "sni": get("sni", ""),
        "fp": get("fp", ""),
        "alpn": get("alpn", ""),
        "pbk": get("pbk", ""),
        "sid": get("sid", ""),
        "flow": get("flow", ""),
        "service": get("serviceName", get("service", "")),
    }

def is_routable(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname: let DNS / connect decide
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)

def tcp_ping(args):
    cfg, timeout = args
    p = parse_vless(cfg)
    if not p or not p["uuid"] or not p["address"] or not is_routable(p["address"]):
        return cfg, False
    try:
        with socket.create_connection((p["address"], p["port"]), timeout=timeout):
            return cfg, True
    except Exception:
        return cfg, False

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

def xray_config(p, socks_port):
    stream = {"network": p["type"]}
    if p["security"] == "tls":
        tls = {"serverName": p["sni"] or p["address"]}
        if p["alpn"]:
            tls["alpn"] = p["alpn"].split(",")
        if p["fp"]:
            tls["fingerprint"] = p["fp"]
        stream["tlsSettings"] = tls
        stream["security"] = "tls"
    elif p["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": p["sni"] or p["address"],
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "fingerprint": p["fp"] or "chrome",
        }
        stream["security"] = "reality"
    if p["type"] == "ws":
        stream["wsSettings"] = {"path": p["path"], "headers": {"Host": p["host"]} if p["host"] else {}}
    elif p["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p["service"]}
    elif p["type"] == "xhttp":
        stream["xhttpSettings"] = {"path": p["path"], "host": p["host"]} if p["host"] else {"path": p["path"]}
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]:
        user["flow"] = p["flow"]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]}, "streamSettings": stream}],
    }

def real_test(args):
    cfg, xray, timeout = args
    p = parse_vless(cfg)
    if not p:
        return cfg, "BAD_URI", None
    if p["encryption"] != "none" or p["type"] not in ("tcp", "ws", "grpc", "xhttp"):
        return cfg, "UNSUPPORTED", None
    port = free_port()
    conf = Path(f"/tmp/xray-test-{port}.json")
    conf.write_text(json.dumps(xray_config(p, port)))
    proc = subprocess.Popen([xray, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.8)
        t0 = time.time()
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout),
             "--proxy", f"socks5h://127.0.0.1:{port}", PROBE],
            capture_output=True, text=True, timeout=timeout + 5)
        ms = int((time.time() - t0) * 1000)
        if r.stdout.strip() in ("200", "204", "301", "302"):
            return cfg, "OK", ms
        return cfg, f"HTTP_{r.stdout.strip() or 'FAIL'}", ms
    except Exception:
        return cfg, "TIMEOUT", None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        conf.unlink(missing_ok=True)

def write_pair(outdir: Path, stem: str, configs):
    outdir.mkdir(parents=True, exist_ok=True)
    plain = ("\n".join(configs) + "\n") if configs else ""
    (outdir / f"{stem}-plain.txt").write_text(plain, encoding="utf-8")
    (outdir / f"{stem}.txt").write_text(base64.b64encode(plain.encode()).decode(), encoding="utf-8")
    return len(configs)

def main():
    rawdir, outdir, xray = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    # Accumulation: load the previous run's healthy configs BEFORE the
    # purge below deletes the old outputs.
    previous = load_previous(outdir)
    # Fresh run: drop stale outputs from a previous source/channel so old
    # country files are not left published after a source switch.
    outdir.mkdir(parents=True, exist_ok=True)
    for stale in outdir.glob("vless-*.txt"):
        stale.unlink()
    (outdir / "report.json").unlink(missing_ok=True)
    tcp_timeout = float(os.environ.get("TCP_TIMEOUT", "4"))
    tcp_workers = int(os.environ.get("TCP_WORKERS", "100"))
    real_timeout = int(os.environ.get("REAL_TIMEOUT", "8"))
    real_workers = int(os.environ.get("REAL_WORKERS", "20"))
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "probe": PROBE,
              "tcp_timeout": tcp_timeout, "real_timeout": real_timeout,
              "cap": MAX_PER_FILE, "countries": {}}
    all_ok = []  # (ms, cfg)
    unsupported = []
    # Fresh countries from raw/, keyed by country code.
    fresh = {}
    for path in sorted(rawdir.glob("vless-*.txt")):
        if path.name == "vless-all.txt":
            continue
        cc = path.stem.replace("vless-", "").upper()
        fresh[cc] = [l.strip() for l in path.read_text().splitlines() if l.strip().startswith("vless://")]
    # Union: countries that only exist in the previous run's output are
    # still re-tested, so their healthy configs survive.
    for cc in sorted(set(fresh) | set(previous)):
        configs = merge_configs(fresh.get(cc, []), previous.get(cc, []))
        # Stage 1
        with ThreadPoolExecutor(max_workers=tcp_workers) as ex:
            alive = [c for c, ok in ex.map(tcp_ping, [(c, tcp_timeout) for c in configs]) if ok]
        # Stage 2
        ok_items = []
        unsup = 0
        with ThreadPoolExecutor(max_workers=real_workers) as ex:
            for cfg, status, ms in ex.map(real_test, [(c, xray, real_timeout) for c in alive]):
                if status == "OK":
                    ok_items.append((ms, cfg))
                elif status == "UNSUPPORTED":
                    unsup += 1
                    unsupported.append(cfg)
        # Rank by measured Stage 2 latency (ms, lowest first) and keep
        # only the best MAX_PER_FILE per file.
        ok_items.sort()
        dropped = max(0, len(ok_items) - MAX_PER_FILE)
        ok_items = ok_items[:MAX_PER_FILE]
        ok_cfgs = [c for _, c in ok_items]
        all_ok.extend(ok_items)
        write_pair(outdir, f"vless-{cc.lower()}", ok_cfgs)
        report["countries"][cc] = {"total": len(configs), "tcp_alive": len(alive),
                                   "ok": len(ok_cfgs), "unsupported": unsup,
                                   "dropped_by_cap": dropped}
        print(f"{cc}: total={len(configs)} (fresh={len(fresh.get(cc, []))} prev={len(previous.get(cc, []))}) "
              f"tcp={len(alive)} ok={len(ok_cfgs)} unsupported={unsup} dropped_by_cap={dropped}")
    all_ok.sort()
    all_dropped = max(0, len(all_ok) - MAX_PER_FILE)
    all_ok = all_ok[:MAX_PER_FILE]
    write_pair(outdir, "vless-all", [c for _, c in all_ok])
    unsupported = list(dict.fromkeys(unsupported))
    (outdir / "vless-unsupported.txt").write_text(("\n".join(unsupported) + "\n") if unsupported else "", encoding="utf-8")
    report["all_ok"] = len(all_ok)
    report["all_dropped_by_cap"] = all_dropped
    report["unsupported_total"] = len(unsupported)
    (outdir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"ALL OK: {len(all_ok)} (dropped_by_cap={all_dropped})  UNSUPPORTED: {len(unsupported)}")

if __name__ == "__main__":
    main()
