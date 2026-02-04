#!/usr/bin/env python3
"""
Build FortiGate-friendly CIDR feeds for one or more ASNs using RIPEstat.
Outputs per-ASN IPv4/IPv6/all files + combined global feeds across all ASNs.
"""

import os, json, urllib.request, ipaddress, pathlib, sys
from datetime import datetime, timedelta

# ---------- Configuration via environment variables ----------
ASNS       = os.getenv("ASNS", "AS19318").replace(" ", "").split(",")  # comma-separated, e.g. "AS19318,AS13335"
MIN_PEERS  = int(os.getenv("MIN_PEERS", "10"))                         # RIPEstat default is 10  [1](https://whois.ipip.net/AS19318)
SOURCEAPP  = os.getenv("RIPE_SOURCEAPP", "asn-threat-feeds")           # polite identification  [3](https://radar.cloudflare.com/routing/as19318)

# Optionally pin a time window (else RIPEstat uses ~last 2 weeks)  [1](https://whois.ipip.net/AS19318)
START_DAYS = int(os.getenv("START_DAYS", "0"))  # 0 = let API default
END_DAYS   = int(os.getenv("END_DAYS",   "0"))

OUTDIR = pathlib.Path("feeds")
OUTDIR.mkdir(exist_ok=True)

def build_url(asn: str) -> str:
    base = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&min_peers_seeing={MIN_PEERS}&sourceapp={SOURCEAPP}"
    if START_DAYS > 0:
        start = (datetime.utcnow() - timedelta(days=START_DAYS)).strftime("%Y-%m-%dT%H:%M")
        base += f"&starttime={start}"
    if END_DAYS > 0:
        end = (datetime.utcnow() - timedelta(days=END_DAYS)).strftime("%Y-%m-%dT%H:%M")
        base += f"&endtime={end}"
    return base

def fetch_prefixes(asn: str):
    url = build_url(asn)
    req = urllib.request.Request(url, headers={"User-Agent": "ASN-Feeds/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        data = json.load(r)
    pfx = set()
    for item in data.get("data", {}).get("prefixes", []):
        val = item.get("prefix")
        if not val: 
            continue
        try:
            ipaddress.ip_network(val, strict=False)
            pfx.add(val)
        except ValueError:
            pass
    return sorted(pfx)

def write_list(path: pathlib.Path, items):
    path.write_text("\n".join(items) + ("\n" if items else ""))

# ---------- Build per-ASN feeds and global combined sets ----------
all_v4, all_v6 = set(), set()

for asn in ASNS:
    prefixes = fetch_prefixes(asn)
    v4 = sorted([p for p in prefixes if ":" not in p])
    v6 = sorted([p for p in prefixes if ":" in p])
    write_list(OUTDIR / f"as{asn.lower()}_ipv4.txt", v4)
    write_list(OUTDIR / f"as{asn.lower()}_ipv6.txt", v6)
    write_list(OUTDIR / f"as{asn.lower()}_all.txt",  sorted(prefixes))

    all_v4.update(v4)
    all_v6.update(v6)

write_list(OUTDIR / "combined_ipv4.txt", sorted(all_v4))
write_list(OUTDIR / "combined_ipv6.txt", sorted(all_v6))
write_list(OUTDIR / "combined_all.txt",  sorted(all_v4.union(all_v6)))
