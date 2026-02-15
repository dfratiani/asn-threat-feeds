#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Builds FortiGate-compatible CIDR feeds per ASN and combined, using RIPEstat.
- Per-ASN: feeds/as<asn>_ipv4.txt, as<asn>_ipv6.txt, as<asn>_all.txt
- Combined: feeds/combined_ipv4.txt, combined_ipv6.txt, combined_all.txt
- Optional permanent exclusions: feeds/exclusions.txt (one CIDR per line, supports inline '#' or ';' comments)

Environment variables:
  ASNS            Comma-separated list, e.g., "AS19318,AS15169"  (required)
  MIN_PEERS       Integer; RIPEstat min_peers_seeing filter (default 10)
  START_DAYS      Optional int; start of time window in days ago (e.g., 14)
  END_DAYS        Optional int; end of time window in days ago (e.g., 0)
  OUTPUT_DIR      Defaults to "feeds"
  EXCLUSIONS_FILE Defaults to "feeds/exclusions.txt"
  LOG_LEVEL       INFO (default), DEBUG, WARNING, ...

Data source:
  RIPEstat 'announced-prefixes' endpoint:
    https://stat.ripe.net/data/announced-prefixes/data.json?resource=ASXXXX&min_peers_seeing=N[&starttime=...][&endtime=...]
"""

import os
import sys
import json
import time
import shutil
import logging
import tempfile
import datetime as dt
from typing import Iterable, List, Set, Tuple

import ipaddress
import requests

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# -----------------------------
# Utilities
# -----------------------------

def parse_asns(asns_str: str) -> List[str]:
    if not asns_str:
        raise ValueError("ASNS environment variable is required (e.g., 'AS19318,AS15169').")
    out = []
    for token in asns_str.split(","):
        token = token.strip().upper()
        if token.startswith("AS"):
            token = token[2:]
        if not token.isdigit():
            raise ValueError(f"Invalid ASN token: {token}")
        out.append(token)
    return out

def _strip_inline_comment(s: str) -> str:
    """Return s with any trailing '#' or ';' comment removed."""
    if not s:
        return s
    cut = len(s)
    for marker in ("#", ";"):
        idx = s.find(marker)
        if idx != -1:
            cut = min(cut, idx)
    return s[:cut].strip()

def read_exclusions(path: str) -> List[ipaddress._BaseNetwork]:
    nets = []
    if not path or not os.path.exists(path):
        return nets
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#") or raw.startswith(";"):
                continue
            s = _strip_inline_comment(raw)
            if not s:
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except Exception:
                logging.warning("Skipping invalid exclusion entry: %s", raw)
    return nets

def collapse_and_sort(networks: Iterable[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    """
    Collapse and sort networks; supports mixed IPv4/IPv6 by collapsing per-family first.
    """
    v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
    v4 = list(ipaddress.collapse_addresses(v4)) if v4 else []
    v6 = list(ipaddress.collapse_addresses(v6)) if v6 else []

    def key(n):
        return (0 if isinstance(n, ipaddress.IPv4Network) else 1, int(n.network_address), n.prefixlen)

    return sorted(v4 + v6, key=key)

def subtract_exclusions(includes: Iterable[ipaddress._BaseNetwork],
                        exclusions: Iterable[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    """
    Return includes minus any overlapping excluded networks.
    Implemented by recursively splitting overlapping networks to ensure true set subtraction.
    """
    excl_by_family = {
        4: [e for e in exclusions if isinstance(e, ipaddress.IPv4Network)],
        6: [e for e in exclusions if isinstance(e, ipaddress.IPv6Network)],
    }

    def split_subtract(base: ipaddress._BaseNetwork, excl_list: List[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
        for e in excl_list:
            # If excluded fully covers 'base', drop it.
            if e.supernet_of(base) or e == base:
                return []
        # Partial overlap? split and recurse
        for e in excl_list:
            if base.overlaps(e) and not (e.supernet_of(base) or e == base):
                try:
                    parts = list(base.subnets(prefixlen_diff=1))
                except ValueError:
                    # Can't split further; drop to be safe
                    return []
                out = []
                for p in parts:
                    out.extend(split_subtract(p, excl_list))
                return out
        # No overlap: keep base
        return [base]

    result = []
    for n in includes:
        fam = 4 if isinstance(n, ipaddress.IPv4Network) else 6
        result.extend(split_subtract(n, excl_by_family[fam]))
    return collapse_and_sort(result)

def write_if_changed(path: str, lines: List[str]) -> bool:
    """Atomically write file only if content changed. Returns True if updated."""
    new_content = "".join(f"{l.rstrip()}\n" for l in lines)
    old_content = None
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            old_content = f.read()
    if old_content == new_content:
        logging.debug("No change: %s", path)
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(new_content)
        tmp_path = tmp.name
    shutil.move(tmp_path, path)
    logging.info("Wrote %s (%d lines)", path, len(lines))
    return True

def to_utc_iso(d: dt.datetime) -> str:
    return d.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

def compute_window(start_days: str, end_days: str) -> Tuple[str, str]:
    """
    Returns (start_iso, end_iso) or (None, None) if no window.
    START_DAYS and END_DAYS are interpreted as offsets from 'now' in days.
    """
    start_iso = end_iso = None
    now = dt.datetime.now(dt.UTC)
    if start_days and end_days:
        try:
            sd = int(start_days)
            ed = int(end_days)
            start = now - dt.timedelta(days=sd)
            end = now - dt.timedelta(days=ed)
            if start > end:
                start, end = end, start
            start_iso = to_utc_iso(start)
            end_iso = to_utc_iso(end)
        except Exception:
            logging.warning("Invalid START_DAYS/END_DAYS; ignoring window.")
    elif start_days and not end_days:
        try:
            sd = int(start_days)
            start = now - dt.timedelta(days=sd)
            start_iso = to_utc_iso(start)
            end_iso = to_utc_iso(now)
        except Exception:
            logging.warning("Invalid START_DAYS; ignoring.")
    elif end_days and not start_days:
        try:
            ed = int(end_days)
            start = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
            end = now - dt.timedelta(days=ed)
            start_iso = to_utc_iso(start)
            end_iso = to_utc_iso(end)
        except Exception:
            logging.warning("Invalid END_DAYS; ignoring.")
    return start_iso, end_iso

# -----------------------------
# RIPEstat query
# -----------------------------

def fetch_announced_prefixes(asn: str, min_peers: int,
                             start_iso: str = None, end_iso: str = None) -> List[str]:
    """
    Returns list of prefix strings announced for the ASN.
    """
    params = {
        "resource": f"AS{asn}",
        "min_peers_seeing": str(min_peers),
    }
    if start_iso:
        params["starttime"] = start_iso
    if end_iso:
        params["endtime"] = end_iso

    logging.info("Query RIPEstat announced-prefixes for AS%s (min_peers=%s, window=%s..%s)",
                 asn, min_peers, start_iso or "-", end_iso or "-")
    r = requests.get(RIPESTAT_URL, params=params, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"RIPEstat HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    if "data" not in data or "prefixes" not in data["data"]:
        raise RuntimeError(f"Unexpected RIPEstat response: {json.dumps(data)[:400]}")
    out = []
    for p in data["data"]["prefixes"]:
        pref = p.get("prefix")
        if pref:
            out.append(pref)
    logging.info("AS%s -> %d prefixes", asn, len(out))
    return out

# -----------------------------
# Main
# -----------------------------

def main() -> int:
    asns_env = os.environ.get("ASNS", "")
    output_dir = os.environ.get("OUTPUT_DIR", "feeds")
    min_peers = int(os.environ.get("MIN_PEERS", "10"))
    start_days = os.environ.get("START_DAYS")
    end_days = os.environ.get("END_DAYS")
    exclusions_file = os.environ.get("EXCLUSIONS_FILE", os.path.join(output_dir, "exclusions.txt"))

    try:
        asns = parse_asns(asns_env)
    except Exception as e:
        logging.error("ASNS parse error: %s", e)
        return 2

    start_iso, end_iso = compute_window(start_days, end_days)
    exclusions = read_exclusions(exclusions_file)
    if exclusions:
        logging.info("Loaded %d exclusion(s) from %s", len(exclusions), exclusions_file)
    else:
        logging.info("No exclusions loaded (file missing or empty): %s", exclusions_file)

    any_changes = False
    all_v4: List[ipaddress._BaseNetwork] = []
    all_v6: List[ipaddress._BaseNetwork] = []

    for asn in asns:
        # Fetch
        try:
            raw_prefixes = fetch_announced_prefixes(asn, min_peers, start_iso, end_iso)
        except Exception as e:
            logging.error("Failed to fetch prefixes for AS%s: %s", asn, e)
            return 3

        # Normalize -> ipaddress objects
        nets: List[ipaddress._BaseNetwork] = []
        for p in raw_prefixes:
            try:
                nets.append(ipaddress.ip_network(p, strict=False))
            except Exception:
                logging.warning("Skipping invalid prefix from API: %s", p)

        # Collapse (mixed families supported) then subtract exclusions and collapse again
        nets = collapse_and_sort(nets)
        if exclusions:
            nets = subtract_exclusions(nets, exclusions)

        # Split by family
        v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
        v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]

        all_v4.extend(v4)
        all_v6.extend(v6)

        # Prepare strings
        v4_lines = [str(n) for n in v4]
        v6_lines = [str(n) for n in v6]
        all_lines = [str(n) for n in nets]  # already collapsed

        # Write per-ASN files
        any_changes |= write_if_changed(os.path.join(output_dir, f"as{asn}_ipv4.txt"), v4_lines)
        any_changes |= write_if_changed(os.path.join(output_dir, f"as{asn}_ipv6.txt"), v6_lines)
        any_changes |= write_if_changed(os.path.join(output_dir, f"as{asn}_all.txt"), all_lines)

    # Combined outputs
    combined_v4 = collapse_and_sort(all_v4)
    combined_v6 = collapse_and_sort(all_v6)
    combined_all = collapse_and_sort(list(combined_v4) + list(combined_v6))

    any_changes |= write_if_changed(os.path.join(output_dir, "combined_ipv4.txt"), [str(n) for n in combined_v4])
    any_changes |= write_if_changed(os.path.join(output_dir, "combined_ipv6.txt"), [str(n) for n in combined_v6])
    any_changes |= write_if_changed(os.path.join(output_dir, "combined_all.txt"),  [str(n) for n in combined_all])

    if not any_changes:
        logging.info("No feed changes detected.")
    else:
        logging.info("Feed files updated.")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.error("Interrupted.")
        sys.exit(130)
