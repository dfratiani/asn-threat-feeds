#!/usr/bin/env python3
"""
build_multi_asn_feeds.py

Generates FortiGate-compatible CIDR feeds for:
  - per-ASN IPv4, IPv6, and combined (v4+v6) files
  - global combined IPv4, IPv6, and combined (v4+v6) files

Data source:
  - RIPEstat "Announced Prefixes" API with min_peers_seeing support
    Docs: https://stat.ripe.net/docs/02.data-api/announced-prefixes.html  # cite
    We map:
      MIN_PEERS   -> min_peers_seeing
      START_DAYS  -> starttime (now - START_DAYS days)
      END_DAYS    -> endtime   (now - END_DAYS days)

Exclusions:
  - Optional file: feeds/exclusions.txt
  - One CIDR per line (IPv4 or IPv6); lines starting with "#" are comments.
  - Exclusions are subtracted from *all* outputs (per-ASN and combined).
  - After subtraction, outputs are minimized & de-duplicated.

"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

import requests

# ----------------------
# Types
# ----------------------
IPv4Net = ipaddress.IPv4Network
IPv6Net = ipaddress.IPv6Network
IPNet = Union[IPv4Net, IPv6Net]


# ----------------------
# Exclusions helpers (self-contained)
# ----------------------
def load_exclusions(path: str = "feeds/exclusions.txt") -> List[IPNet]:
    """
    Read exclusion networks from feeds/exclusions.txt.
    Supports blank lines and '#' comments.
    Missing file -> returns empty list (no-op).
    """
    p = Path(path)
    if not p.exists():
        return []
    nets: List[IPNet] = []
    with p.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                print(f"[exclusions] WARN: Skipping invalid CIDR at line {lineno}: {line}", file=sys.stderr)
    return nets


def _subtract_one(net: IPNet, excludes: Sequence[IPNet]) -> List[IPNet]:
    """
    Subtract multiple exclusion networks from a single network.
    Uses ipaddress.address_exclude() where applicable.
    """
    result: List[IPNet] = [net]
    for ex in excludes:
        # Skip family mismatch early
        if net.version != ex.version:
            continue
        new_result: List[IPNet] = []
        for r in result:
            if ex.subnet_of(r):
                # ex is inside r -> split r into pieces that exclude ex
                new_result.extend(r.address_exclude(ex))
            elif r.subnet_of(ex) or r == ex:
                # r is fully covered by ex (drop it)
                continue
            else:
                # disjoint
                new_result.append(r)
        result = new_result
        if not result:
            break
    return result


def apply_exclusions(nets: Iterable[IPNet], excludes: Iterable[IPNet]) -> List[IPNet]:
    """
    Apply exclusions to an iterable of networks (mixed IPv4/IPv6 allowed).
    Returns a minimal, sorted list of networks after subtraction.
    """
    excludes = list(excludes)
    excludes_v4 = [e for e in excludes if isinstance(e, ipaddress.IPv4Network)]
    excludes_v6 = [e for e in excludes if isinstance(e, ipaddress.IPv6Network)]

    out: List[IPNet] = []
    for n in nets:
        exs = excludes_v4 if isinstance(n, ipaddress.IPv4Network) else excludes_v6
        out.extend(_subtract_one(n, exs))

    collapsed = list(ipaddress.collapse_addresses(out))
    collapsed.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return collapsed


# ----------------------
# Normalization / IO
# ----------------------
def collapse_and_sort(nets: Iterable[IPNet]) -> List[IPNet]:
    """Collapse adjacent/sibling prefixes and return stable order."""
    collapsed = list(ipaddress.collapse_addresses(nets))
    collapsed.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return collapsed


def write_cidrs(path: Path, nets: Iterable[IPNet]) -> None:
    """Write one CIDR per line to path (creates parent dirs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for n in nets:
            f.write(str(n) + "\n")


# ----------------------
# RIPEstat client (Announced Prefixes)
# ----------------------
RIPESTAT_BASE = "https://stat.ripe.net/data/announced-prefixes/data.json"  # cite


@dataclass
class RipeWindow:
    start_iso: Optional[str] = None
    end_iso: Optional[str] = None


def _compute_time_window(start_days: Optional[int], end_days: Optional[int]) -> RipeWindow:
    """
    START_DAYS / END_DAYS are interpreted as offsets from 'now' (UTC).
      - If only START_DAYS: start = now - START_DAYS, end unset (now per RIPEstat default)
      - If only END_DAYS:   end   = now - END_DAYS
      - If both:            start = now - START_DAYS, end = now - END_DAYS
        If start > end, swap for safety (warn).
    """
    now = datetime.now(timezone.utc)
    start_iso = end_iso = None

    if start_days is not None:
        start = now - timedelta(days=int(start_days))
        start_iso = start.isoformat(timespec="seconds").replace("+00:00", "Z")
    if end_days is not None:
        end = now - timedelta(days=int(end_days))
        end_iso = end.isoformat(timespec="seconds").replace("+00:00", "Z")

    if start_iso and end_iso:
        # Ensure chronological order
        if start_iso > end_iso:
            # swap
            start_iso, end_iso = end_iso, start_iso
            print("[ripe] NOTE: START_DAYS produced a later time than END_DAYS; window swapped.", file=sys.stderr)

    return RipeWindow(start_iso, end_iso)


def fetch_asn_prefixes_from_ripestat(
    asn: str,
    min_peers: int,
    start_days: Optional[int] = None,
    end_days: Optional[int] = None,
    session: Optional[requests.Session] = None,
    retries: int = 3,
    backoff_sec: float = 1.5,
) -> Tuple[List[IPv4Net], List[IPv6Net]]:
    """
    Query RIPEstat Announced Prefixes for the given ASN and return IPv4/IPv6 lists.

    - min_peers maps to RIPEstat 'min_peers_seeing' (default 10 per RIPEstat docs).  # cite
    - Optional start/end derived from START_DAYS/END_DAYS.

    Returns (v4_list, v6_list).
    """
    params = {
        "resource": asn.lstrip().lstrip("AS").lstrip("as"),
        "min_peers_seeing": int(min_peers),
        "sourceapp": "asn-threat-feeds",  # polite identification (see RIPEstat usage docs)
    }

    window = _compute_time_window(start_days, end_days)
    if window.start_iso:
        params["starttime"] = window.start_iso
    if window.end_iso:
        params["endtime"] = window.end_iso

    s = session or requests.Session()
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = s.get(RIPESTAT_BASE, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            # Expected structure: {'data': {'prefixes': [{'prefix': 'x/y', 'timelines': [...]}, ...], ...}}
            d = data.get("data", {})
            pref_entries = d.get("prefixes", [])
            v4: List[IPv4Net] = []
            v6: List[IPv6Net] = []
            for entry in pref_entries:
                pfx = entry.get("prefix")
                if not pfx:
                    continue
                try:
                    net = ipaddress.ip_network(pfx, strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    v4.append(net)
                else:
                    v6.append(net)
            return v4, v6
        except (requests.RequestException, json.JSONDecodeError) as e:
            if attempt > retries:
                raise
            sleep_for = backoff_sec * attempt
            print(f"[ripe] WARN: attempt {attempt}/{retries} failed for {asn}: {e}; retrying in {sleep_for:.1f}s", file=sys.stderr)
            time.sleep(sleep_for)


# ----------------------
# Builder
# ----------------------
def normalize(nets: Iterable[IPNet]) -> List[IPNet]:
    """Your existing dedupe/minimize pipeline can replace this if desired."""
    return collapse_and_sort(nets)


def build_feeds(
    asns: List[str],
    min_peers: int = 10,
    start_days: Optional[int] = None,
    end_days: Optional[int] = None,
    out_dir: Path = Path("feeds"),
) -> None:
    """
    Build all per-ASN and combined feeds, applying optional exclusions.
    """

    # Load exclusions once
    exclusions_path = out_dir / "exclusions.txt"
    exclusions = load_exclusions(str(exclusions_path))
    if exclusions:
        print(f"[exclusions] Loaded {len(exclusions)} exclusion networks from {exclusions_path}")
    else:
        print("[exclusions] No exclusions found (proceeding without filtering)")

    combined_v4: List[IPv4Net] = []
    combined_v6: List[IPv6Net] = []

    with requests.Session() as sess:
        for asn in asns:
            asn_norm = asn.strip()
            if not asn_norm:
                continue
            # Ensure "AS12345" form in filenames
            if not asn_norm.upper().startswith("AS"):
                asn_norm = "AS" + asn_norm

            print(f"[builder] Processing {asn_norm} ...")

            v4_raw, v6_raw = fetch_asn_prefixes_from_ripestat(
                asn=asn_norm,
                min_peers=min_peers,
                start_days=start_days,
                end_days=end_days,
                session=sess,
            )

            v4_final = normalize(v4_raw)
            v6_final = normalize(v6_raw)

            if exclusions:
                v4_final = apply_exclusions(v4_final, exclusions)
                v6_final = apply_exclusions(v6_final, exclusions)

            # Write per-ASN files
            write_cidrs(out_dir / f"{asn_norm.lower()}_ipv4.txt", v4_final)
            write_cidrs(out_dir / f"{asn_norm.lower()}_ipv6.txt", v6_final)

            asn_all = collapse_and_sort([*v4_final, *v6_final])
            write_cidrs(out_dir / f"{asn_norm.lower()}_all.txt", asn_all)

            combined_v4.extend(v4_final)
            combined_v6.extend(v6_final)

    # Combined outputs
    combined_v4 = normalize(combined_v4)
    combined_v6 = normalize(combined_v6)

    if exclusions:
        combined_v4 = apply_exclusions(combined_v4, exclusions)
        combined_v6 = apply_exclusions(combined_v6, exclusions)

    write_cidrs(out_dir / "combined_ipv4.txt", combined_v4)
    write_cidrs(out_dir / "combined_ipv6.txt", combined_v6)

    combined_all = collapse_and_sort([*combined_v4, *combined_v6])
    write_cidrs(out_dir / "combined_all.txt", combined_all)

    print("[builder] Done.")


# ----------------------
# Entrypoint
# ----------------------
def _parse_env_list(var: str, default: str = "") -> List[str]:
    raw = os.environ.get(var, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def main():
    """
    Env vars:
      - ASNS           (required) e.g., "AS19318,AS13335"
      - MIN_PEERS      (optional, default 10)
      - START_DAYS     (optional, integer)
      - END_DAYS       (optional, integer)
    """
    asns = _parse_env_list("ASNS")
    if not asns:
        raise SystemExit("ASNS is required (comma-separated list of target ASNs)")

    try:
        min_peers = int(os.environ.get("MIN_PEERS", "10"))
    except ValueError:
        min_peers = 10

    start_days_env = os.environ.get("START_DAYS")
    end_days_env = os.environ.get("END_DAYS")

    start_days = int(start_days_env) if start_days_env not in (None, "") else None
    end_days = int(end_days_env) if end_days_env not in (None, "") else None

    build_feeds(
        asns=asns,
        min_peers=min_peers,
        start_days=start_days,
        end_days=end_days,
        out_dir=Path("feeds"),
    )


if __name__ == "__main__":
    main()
