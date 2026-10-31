#!/usr/bin/env python3
"""Clean collector for ONE channel only: ConfigsHUB, VLESS only.

No Telegram API, no phone number, no bot token.
Source is the public web page https://t.me/s/ConfigsHUB, paged with
?before=<oldest post id> (post ids come from data-post="ConfigsHUB/<id>").
Country comes from the channel's own flag in the config remark, e.g. 🇨🇦 -> CA.
Output is PLAIN text only; tester.py turns the tested-OK subset into
the Base64 subscriptions. Only stdlib + requests.
"""
import html
import re
import sys
import urllib.parse
from pathlib import Path

import requests

CHANNEL = "ConfigsHUB"
BASE = f"https://t.me/s/{CHANNEL}"
HEADERS = {"User-Agent": "Mozilla/5.0"}

FLAG_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")
VLESS_RE = re.compile(r"vless://[^\s<\"']+")
# User's blocklist (2026-10-31): any config whose URI contains one of
# these (address, SNI, host header, path, remark, ...) is NOT collected.
BLOCKED_SUBSTRINGS = ("pages.dev", "workers.dev")
POST_RE = re.compile(r'data-post="ConfigsHUB/(\d+)"')

def flag_to_cc(flag: str) -> str:
    return "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flag)

def strip_tags(s: str) -> str:
    s = re.sub(r"<br\s*/?>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s)

def fetch_page(url: str) -> str:
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.text

def parse_page(page_html: str):
    out = []
    blocks = re.split(r'tgme_widget_message_text', page_html)
    for block in blocks[1:]:
        text = strip_tags(block)
        for cfg in VLESS_RE.findall(text):
            cfg = html.unescape(cfg).strip()
            if any(b in cfg.lower() for b in BLOCKED_SUBSTRINGS):
                continue
            m = FLAG_RE.search(cfg) or FLAG_RE.search(text)
            cc = flag_to_cc(m.group(1)) if m else "UNKNOWN"
            out.append((cfg, cc))
    return out

def dedup(items):
    seen = set()
    out = []
    for cfg, cc in items:
        key = cfg.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        out.append((cfg, cc))
    return out

def write_plain(path: Path, configs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(configs) + "\n") if configs else "", encoding="utf-8")
    return len(configs)

def main():
    max_pages = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("raw")
    url = BASE
    all_items = []
    for page_no in range(1, max_pages + 1):
        page = fetch_page(url)
        items = parse_page(page)
        print(f"page {page_no} {url}: {len(items)} vless", file=sys.stderr)
        all_items.extend(items)
        ids = [int(x) for x in POST_RE.findall(page)]
        if not ids:
            break
        url = f"{BASE}?before={min(ids)}"
    all_items = dedup(all_items)
    by_country = {}
    for cfg, cc in all_items:
        by_country.setdefault(cc, []).append(cfg)
    print(f"ALL: {write_plain(outdir / 'vless-all.txt', [c for c, _ in all_items])}")
    for cc in sorted(by_country):
        print(f"{cc}: {write_plain(outdir / f'vless-{cc.lower()}.txt', by_country[cc])}")

if __name__ == "__main__":
    main()
