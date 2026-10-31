#!/usr/bin/env python3
"""Rename final OK configs to the user's chic naming, removing ConfigsHUB names.

Rules (user's own spec, 2026-10-31):
  - Normal / country / all subs:  Alirzza<flag>
    e.g. Alirzza🇩🇪, Alirzza🇨🇦
  - For-Iran sub only:            Alirzza⭐<flag> <iran_ping>ms
    e.g. Alirzza⭐🇺🇸 140ms
    The ping is the IRAN ping, not the runner ping: the average TCP
    time (seconds -> ms, rounded) from the responding Check-host Iran
    nodes in report-iran.json. For-Iran configs are sorted by that
    Iran ping, fastest first.
  - Flag comes from the country code already extracted from the
    channel's own flag (RA is the channel's own label, kept as 🇷🇦;
    UNKNOWN configs, which the channel marks with 🏁, keep 🏁).
  - Duplicate names are allowed exactly as the user said (2026-10-31):
    no -2, -3 suffixes. Ten identical "Alirzza🇩🇪" entries stay identical.

Usage: python3 final_names.py <sub_dir>
  Reads <sub_dir>/*-plain.txt and <sub_dir>/report-iran.json,
  rewrites the plain files in place and regenerates the matching
  Base64 <sub_dir>/vless-*.txt files (except *-plain and unsupported).
"""
import base64
import json
import sys
import urllib.parse
from pathlib import Path

def cc_to_flag(cc: str) -> str:
    if cc == "UNKNOWN":
        return "🏁"
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(ord(c.upper()) - ord("A") + 0x1F1E6) for c in cc)
    return "🏁"

def set_remark(cfg: str, name: str) -> str:
    base = cfg.split("#")[0]
    return f"{base}#{name}"

def hostport(cfg: str):
    u = urllib.parse.urlparse(cfg)
    try:
        port = u.port or 443
    except ValueError:
        return None
    return f"{u.hostname}:{port}" if u.hostname else None

def rewrite_file(path: Path, names):
    configs = [l.strip() for l in path.read_text().splitlines() if l.strip().startswith("vless://")]
    renamed = [set_remark(c, n) for c, n in zip(configs, names)]
    plain = ("\n".join(renamed) + "\n") if renamed else ""
    path.write_text(plain, encoding="utf-8")
    b64_path = path.with_name(path.name.replace("-plain.txt", ".txt"))
    b64_path.write_text(base64.b64encode(plain.encode()).decode(), encoding="utf-8")
    return renamed

def main():
    sub = Path(sys.argv[1])
    iran_report = {}
    rp = sub / "report-iran.json"
    if rp.exists():
        iran_report = json.loads(rp.read_text()).get("results", {})
    # Normal files: Alirzza<flag>, flag from filename country code.
    for plain in sorted(sub.glob("vless-*-plain.txt")):
        if plain.name.startswith("vless-for-iran"):
            continue
        stem = plain.name.replace("-plain.txt", "")  # vless-de / vless-all
        cc = stem.replace("vless-", "").upper()
        if cc == "ALL":
            # all file: flag per config, from its country file is not
            # stored here, so recover it from the original remark's flag
            # before renaming is impossible after a second run. Instead
            # use the per-country files' order: handled below by the
            # caller running this script once on fresh tester output,
            # where all-plain still carries original remarks. Parse the
            # original flag from each config before overwriting.
            configs = [l.strip() for l in plain.read_text().splitlines() if l.strip()]
            names = []
            # original flag: last flag-like token in original remark
            import re
            flag_re = re.compile(r"([\U0001F1E6-\U0001F1FF]{2}|🏁)")
            for c in configs:
                frag = c.split("#", 1)[1] if "#" in c else ""
                m = flag_re.findall(frag)
                flag = m[-1] if m else "🏁"
                names.append(f"Alirzza{flag}")
            rewrite_file(plain, names)
            print(f"{plain.name}: {len(names)} renamed (all, per-config flag)")
            continue
        flag = cc_to_flag(cc)
        configs = [l.strip() for l in plain.read_text().splitlines() if l.strip()]
        names = [f"Alirzza{flag}"] * len(configs)
        rewrite_file(plain, names)
        print(f"{plain.name}: {len(names)} renamed to Alirzza{flag}")
    # For-Iran file: Alirzza⭐<flag> <iran_ms>ms, sorted by Iran ping.
    fir = sub / "vless-for-iran-plain.txt"
    if fir.exists():
        configs = [l.strip() for l in fir.read_text().splitlines() if l.strip().startswith("vless://")]
        items = []
        for c in configs:
            hp = hostport(c)
            res = iran_report.get(hp, {})
            times = [t for t in (res.get("times") or {}).values() if t is not None]
            ms = round(sum(times) / len(times) * 1000) if times else 0
            # country flag: from the country file that contains this
            # config, else from original remark
            flag = "🏁"
            for p in sorted(sub.glob("vless-*-plain.txt")):
                if p.name.startswith(("vless-for-iran", "vless-all")):
                    continue
                if c.split("#")[0] in p.read_text():
                    flag = cc_to_flag(p.name.replace("vless-", "").replace("-plain.txt", "").upper())
                    break
            items.append((ms, c, flag))
        items.sort(key=lambda x: x[0])
        names = [f"Alirzza⭐{flag} {ms}ms" for ms, c, flag in items]
        # Write sorted configs explicitly (sorted by Iran ping):
        plain = ("\n".join(set_remark(c, n) for (_, c, _), n in zip(items, names)) + "\n") if items else ""
        fir.write_text(plain, encoding="utf-8")
        (sub / "vless-for-iran.txt").write_text(base64.b64encode(plain.encode()).decode(), encoding="utf-8")
        print(f"vless-for-iran-plain.txt: {len(items)} renamed, Iran pings: {[m for m, _, _ in items]}")

if __name__ == "__main__":
    main()
