#!/usr/bin/env python3
import json, urllib.request, ipaddress, pathlib

ASN = "AS19318"
MIN_PEERS = 10
OUTDIR = pathlib.Path("feeds")
OUTDIR.mkdir(exist_ok=True)

URL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json"
    f"?resource={ASN}&min_peers_seeing={MIN_PEERS}"
)

with urllib.request.urlopen(URL, timeout=30) as r:
    data = json.load(r)

prefixes = set()
for item in data["data"]["prefixes"]:
    pfx = item["prefix"]
    try:
        ipaddress.ip_network(pfx, strict=False)
        prefixes.add(pfx)
    except ValueError:
        pass

ipv4 = sorted(p for p in prefixes if ":" not in p)
ipv6 = sorted(p for p in prefixes if ":" in p)

(OUTDIR / "as19318_all.txt").write_text("\n".join(sorted(prefixes)) + "\n")
(OUTDIR / "as19318_ipv4.txt").write_text("\n".join(ipv4) + "\n")
(OUTDIR / "as19318_ipv6.txt").write_text("\n".join(ipv6) + "\n")
