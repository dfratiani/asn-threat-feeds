#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_multi_asn_feeds.py  — with Diagnostics Mode, per-run diag folder, and summary.json

Generates FortiGate-compatible CIDR feeds from live BGP announcements
for one or more ASNs using RIPEstat's "announced-prefixes" API.

DIAGNOSTICS MODE (env DIAG=1)
-----------------------------
When enabled, prints richer runtime details and writes diagnostic artifacts
to feeds/diag/<run_id>/:
  - build.log (always written on completion or error)
  - summary.json (environment + per-ASN counts + combined sizes)
  - as<asn>_raw.txt and as<asn>_after_exclusions.txt (samples)

Environment variables
---------------------
ASNS        Comma-separated list of ASNs, e.g. "AS19318,AS13335,AS15169"
MIN_PEERS   Minimum RIS peers seeing a prefix (default: 10)
START_DAYS  Optional int: start time = now() - START_DAYS days
END_DAYS    Optional int: end time   = now() - END_DAYS   days
            If neither is set, RIPEstat uses its default rolling window.

# Diagnostics (all optional)
DIAG                    "0" (default) or "1" to enable diagnostics
DIAG_MAX_PREFIXES       Max sample lines to write into diag files (default: 50)
DIAG_WRITE_FILES        "0"/"1" write detailed samples under feeds/diag/<run_id>/ (default: 1)
DIAG_SHOW_EXCLUSIONS    "0"/"1" echo first N lines of exclusions (default: 1)

Outputs
-------
feeds/
  as<asn>_ipv4.txt
  as<asn>_ipv6.txt
  as<asn>_all.txt
  combined_ipv4.txt
  combined_ipv6.txt
  combined_all.txt
  diag/<run_id>/
    build.log
    summary.json
    as<asn>_raw.txt
    as<asn>_after_exclusions.txt
"""

from __future__ import annotations

import io
import json
import logging
import os
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple

import ipaddress
import urllib.parse
import urllib.request


# ------------------------------- Configuration -------------------------------

FEEDS_DIR = Path("feeds")
EXCLUSIONS_FILE = FEEDS_DIR / "exclusions.txt"
DIAG_DIR = FEEDS_DIR / "diag"

# RIPEstat endpoint: announced-prefixes
RIPES_ANNOUNCED_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"

# Comment tokens accepted in feeds/exclusions.txt (inline comments after CIDR)
COMMENT_TOKENS = ("#", ";", "//")

# HTTP defaults
HTTP_TIMEOUT = 30  # seconds
HTTP_RETRY = 3
HTTP_RETRY_SLEEP = 2  # seconds base (exponential backoff)

# Per-run diagnostics subfolder (use GitHub Actions run id if present)
GITHUB_RUN_ID = os.environ.get("GITHUB_RUN_ID")  # provided by GitHub Actions
RUN_SUBDIR = DIAG_DIR / (GITHUB_RUN_ID or "local")


# ------------------------------- Diagnostics ---------------------------------

def _as_bool(val: Optional[str], default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


class Diag:
    """Diagnostics helper that buffers logs and writes to feeds/diag/<run_id>/."""
    enabled: bool
    max_prefixes: int
    write_files: bool
    show_exclusions: bool
    log_buffer: io.StringIO
    summary: dict

    def __init__(self) -> None:
        self.enabled = _as_bool(os.environ.get("DIAG"), False)
        self.max_prefixes = int(os.environ.get("DIAG_MAX_PREFIXES", "50"))
        self.write_files = _as_bool(os.environ.get("DIAG_WRITE_FILES"), True)
        self.show_exclusions = _as_bool(os.environ.get("DIAG_SHOW_EXCLUSIONS"), True)
        self.log_buffer = io.StringIO()
        self.summary = {
            "run": {
                "run_id": GITHUB_RUN_ID or "local",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "env": {},  # filled in from main()
            },
            "asns": [],     # list of per-ASN dicts
            "combined": {}, # filled after build
            "notes": "Counts reflect what was seen and written during this run.",
        }

    def print(self, *args) -> None:
        msg = " ".join(str(a) for a in args)
        logging.info(msg)
        if self.enabled:
            self.log_buffer.write(msg + "\n")

    def dump_to_file(self) -> None:
        if not self.enabled:
            return
        RUN_SUBDIR.mkdir(parents=True, exist_ok=True)
        (RUN_SUBDIR / "build.log").write_text(self.log_buffer.getvalue(), encoding="utf-8")

    def dump_summary(self) -> None:
        if not self.enabled:
            return
        RUN_SUBDIR.mkdir(parents=True, exist_ok=True)
        (RUN_SUBDIR / "summary.json").write_text(
            json.dumps(self.summary, indent=2, sort_keys=False), encoding="utf-8"
        )

    def write_sample(self, name: str, lines: Sequence[str]) -> None:
        if not (self.enabled and self.write_files):
            return
        RUN_SUBDIR.mkdir(parents=True, exist_ok=True)
        sample = lines[: self.max_prefixes]
        (RUN_SUBDIR / name).write_text("\n".join(sample) + ("\n" if sample else ""), encoding="utf-8")

    def record_env(self, asns_env: str, min_peers: int, start_iso: Optional[str], end_iso: Optional[str]) -> None:
        if not self.enabled:
            return
        self.summary["run"]["env"] = {
            "ASNS": asns_env,
            "MIN_PEERS": min_peers,
            "START_ISO": start_iso,
            "END_ISO": end_iso,
            "DIAG": os.environ.get("DIAG"),
            "DIAG_MAX_PREFIXES": self.max_prefixes,
            "DIAG_WRITE_FILES": self.write_files,
            "DIAG_SHOW_EXCLUSIONS": self.show_exclusions,
        }

    def record_asn(self, asn: str, raw: int, after_excl: int, final_v4: int, final_v6: int, error: Optional[str] = None) -> None:
        if not self.enabled:
            return
        self.summary["asns"].append({
            "asn": asn.upper() if asn.upper().startswith("AS") else f"AS{asn}",
            "raw_prefixes": raw,
            "after_exclusions": after_excl,
            "final_ipv4": final_v4,
            "final_ipv6": final_v6,
            **({"error": error} if error else {}),
        })

    def record_combined(self, final_v4: int, final_v6: int) -> None:
        if not self.enabled:
            return
        self.summary["combined"] = {
            "final_ipv4": final_v4,
            "final_ipv6": final_v6,
            "final_all": final_v4 + final_v6,
        }


diag = Diag()


# ------------------------------ Logging setup --------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ------------------------------ Utility helpers -------------------------------

def _iso8601_from_days(days_ago: Optional[int]) -> Optional[str]:
    """Return an ISO8601 UTC timestamp for 'now - days_ago' if provided."""
    if days_ago is None:
        return None
    if days_ago < 0:
        raise ValueError("START_DAYS/END_DAYS cannot be negative.")
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.replace(microsecond=0).isoformat()


def _http_get_json(url: str, params: dict) -> dict:
    """GET JSON with retries/backoff using urllib (no third-party deps)."""
    q = urllib.parse.urlencode(params)
    full_url = f"{url}?{q}"
    last_err: Optional[Exception] = None
    for attempt in range(1, HTTP_RETRY + 1):
        try:
            req = urllib.request.Request(full_url, headers={"User-Agent": "asn-threat-feeds/1.3"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                data = resp.read()
                return json.loads(data.decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            last_err = e
            sleep_for = HTTP_RETRY_SLEEP * (2 ** (attempt - 1))
            logging.warning("GET failed (%s) attempt %d/%d: %s; retrying in %ss",
                            url, attempt, HTTP_RETRY, e, sleep_for)
            time.sleep(sleep_for)
    assert last_err is not None
    raise last_err


def _strip_inline_comment(line: str) -> str:
    """
    Returns the line up to (but not including) the first inline comment token.
    Recognizes '#', ';', and '//' comments. Trims surrounding whitespace.
    """
    if not line:
        return ""
    idxs = []
    for tok in COMMENT_TOKENS:
        i = line.find(tok)
        if i != -1:
            idxs.append(i)
    if idxs:
        line = line[:min(idxs)]
    return line.strip()


def load_exclusions(path: Path) -> Set[ipaddress._BaseNetwork]:
    """
    Load exclusions from `path`, allowing inline comments on the same line.
    - Accepts IPv4/IPv6 CIDRs OR single IPs (treated as /32 or /128) with strict=False
    - Ignores blank/comment-only/malformed lines; logs a warning with the line number.
    """
    exclusions: Set[ipaddress._BaseNetwork] = set()
    if not path.exists():
        diag.print(f"No exclusions file found at {path}; continuing without exclusions.")
        return exclusions

    lines = path.read_text(encoding="utf-8").splitlines()
    if diag.enabled and diag.show_exclusions:
        diag.print(f"DIAG: Showing up to {diag.max_prefixes} lines of exclusions (raw file):")
        for i, line in enumerate(lines[: diag.max_prefixes], 1):
            diag.print(f"{i:4d}: {line}")

    for lineno, raw in enumerate(lines, 1):
        cleaned = _strip_inline_comment(raw.strip())
        if not cleaned:
            continue
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            exclusions.add(net)
        except ValueError:
            logging.warning("Skipping invalid exclusion on line %d: %r", lineno, raw.rstrip())

    diag.print(
        f"Loaded {len(exclusions)} exclusions "
        f"({sum(1 for n in exclusions if isinstance(n, ipaddress.IPv4Network))} IPv4, "
        f"{sum(1 for n in exclusions if isinstance(n, ipaddress.IPv6Network))} IPv6) from {path}"
    )
    return exclusions


# --------------------------- Prefix subtraction logic -------------------------

def split_network(net: ipaddress._BaseNetwork) -> tuple[ipaddress._BaseNetwork, ipaddress._BaseNetwork]:
    first, second = tuple(net.subnets(prefixlen_diff=1))
    return first, second


def subtract_one(net: ipaddress._BaseNetwork, exc: ipaddress._BaseNetwork) -> List[ipaddress._BaseNetwork]:
    """Subtract a single exclusion `exc` from `net` and return residuals."""
    if not net.overlaps(exc):
        return [net]
    if net.subnet_of(exc) or net == exc:
        return []
    if net.prefixlen == net.max_prefixlen:
        return [net]
    a, b = split_network(net)
    res: List[ipaddress._BaseNetwork] = []
    for child in (a, b):
        if child.overlaps(exc):
            res.extend(subtract_one(child, exc))
        else:
            res.append(child)
    return res


def subtract_many(net: ipaddress._BaseNetwork, excludes: Iterable[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    result = [net]
    for exc in excludes:
        new_result: List[ipaddress._BaseNetwork] = []
        for piece in result:
            new_result.extend(subtract_one(piece, exc))
        result = new_result
        if not result:
            break
    return result


def apply_exclusions(prefixes: Iterable[str], exclusions: Set[ipaddress._BaseNetwork]) -> List[str]:
    """
    Apply exclusions to an iterable of string prefixes (true set difference).
    """
    out_v4: List[ipaddress.IPv4Network] = []
    out_v6: List[ipaddress.IPv6Network] = []

    v4_ex = [e for e in exclusions if isinstance(e, ipaddress.IPv4Network)]
    v6_ex = [e for e in exclusions if isinstance(e, ipaddress.IPv6Network)]

    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            logging.warning("Skipping invalid feed prefix %r", p)
            continue

        if isinstance(net, ipaddress.IPv4Network):
            overlaps = [e for e in v4_ex if e.overlaps(net)]
            residuals = subtract_many(net, overlaps) if overlaps else [net]
            out_v4.extend(n for n in residuals if isinstance(n, ipaddress.IPv4Network))
        else:
            overlaps = [e for e in v6_ex if e.overlaps(net)]
            residuals = subtract_many(net, overlaps) if overlaps else [net]
            out_v6.extend(n for n in residuals if isinstance(n, ipaddress.IPv6Network))

    collapsed_v4 = ipaddress.collapse_addresses(out_v4)
    collapsed_v6 = ipaddress.collapse_addresses(out_v6)

    v4_list = [n.with_prefixlen for n in collapsed_v4]
    v6_list = [n.with_prefixlen for n in collapsed_v6]
    return v4_list + v6_list


# ----------------------------- RIPEstat integration ---------------------------

def fetch_announced_prefixes(asn: str, min_peers: int,
                             start_iso: Optional[str],
                             end_iso: Optional[str]) -> List[str]:
    """
    Query RIPEstat for announced prefixes of `asn`, respecting min_peers_seeing
    and optional time window. Returns list of CIDR strings.
    """
    asn_clean = asn.upper().removeprefix("AS")
    params = {
        "resource": asn_clean,
        "min_peers_seeing": int(min_peers),
    }
    if start_iso:
        params["starttime"] = start_iso
    if end_iso:
        params["endtime"] = end_iso

    data = _http_get_json(RIPES_ANNOUNCED_PREFIXES, params)
    prefixes = []
    try:
        items = data["data"]["prefixes"]
        for it in items:
            p = it.get("prefix")
            if p:
                prefixes.append(p.strip())
    except Exception as e:  # noqa: BLE001
        logging.error("Unexpected RIPEstat response for AS%s: %s", asn_clean, e)
        raise

    return prefixes


def separate_v4_v6(prefixes: Iterable[str]) -> Tuple[List[str], List[str]]:
    v4, v6 = [], []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            logging.warning("Skipping invalid prefix from API %r", p)
            continue
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net.with_prefixlen)
        else:
            v6.append(net.with_prefixlen)
    return v4, v6


def normalize_cidrs(cidrs: Iterable[str]) -> List[str]:
    """Deduplicate/collapse a mixed v4/v6 list and return sorted strings."""
    v4_nets = []
    v6_nets = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if isinstance(n, ipaddress.IPv4Network):
            v4_nets.append(n)
        else:
            v6_nets.append(n)

    v4_collapsed = ipaddress.collapse_addresses(sorted(v4_nets, key=lambda n: (int(n.network_address), n.prefixlen)))
    v6_collapsed = ipaddress.collapse_addresses(sorted(v6_nets, key=lambda n: (int(n.network_address), n.prefixlen)))

    out_v4 = [n.with_prefixlen for n in v4_collapsed]
    out_v6 = [n.with_prefixlen for n in v6_collapsed]
    return out_v4 + out_v6


# ------------------------------ File I/O helpers ------------------------------

def write_lines(path: Path, lines: Sequence[str]) -> None:
    """Write lines with trailing newline, only if content changed (idempotent)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    new_content = "".join(f"{l}\n" for l in lines)

    if path.exists():
        try:
            current = path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            current = None
        if current == new_content:
            logging.info("No change: %s (%d entries)", path, len(lines))
            return

    path.write_text(new_content, encoding="utf-8")
    logging.info("Wrote %s (%d entries)", path, len(lines))


# --------------------------------- Main flow ----------------------------------

def build_for_asn(asn: str,
                  min_peers: int,
                  start_iso: Optional[str],
                  end_iso: Optional[str],
                  exclusions: Set[ipaddress._BaseNetwork]) -> Tuple[List[str], List[str], List[str]]:
    """
    Build feed lists for a single ASN.
    Returns (ipv4_list, ipv6_list, all_list).
    """
    error_text: Optional[str] = None
    raw: List[str] = []
    filtered: List[str] = []
    try:
        raw = fetch_announced_prefixes(asn, min_peers, start_iso, end_iso)
        diag.print(f"AS{asn.upper().removeprefix('AS')}: raw count before exclusions: {len(raw)}")
        if diag.enabled:
            diag.write_sample(f"as{asn.lower().removeprefix('as')}_raw.txt", [p for p in raw])

        filtered = apply_exclusions(raw, exclusions) if exclusions else raw
        diag.print(f"AS{asn.upper().removeprefix('AS')}: count after exclusions: {len(filtered)}")
        if diag.enabled:
            diag.write_sample(
                f"as{asn.lower().removeprefix('as')}_after_exclusions.txt",
                [p for p in filtered],
            )

        final = normalize_cidrs(filtered)

        v4, v6 = separate_v4_v6(final)
        all_list = v4 + v6
        asn_lower = asn.lower().removeprefix("as")
        # Write per-ASN files
        write_lines(FEEDS_DIR / f"as{asn_lower}_ipv4.txt", v4)
        write_lines(FEEDS_DIR / f"as{asn_lower}_ipv6.txt", v6)
        write_lines(FEEDS_DIR / f"as{asn_lower}_all.txt", all_list)

        # Record counts to summary
        diag.record_asn(asn, raw=len(raw), after_excl=len(filtered), final_v4=len(v4), final_v6=len(v6))
        return v4, v6, all_list

    except Exception as e:  # noqa: BLE001
        error_text = repr(e)
        diag.record_asn(asn, raw=len(raw), after_excl=len(filtered), final_v4=0, final_v6=0, error=error_text)
        raise


def main() -> None:
    # Read environment
    asns_env = os.environ.get("ASNS", "").strip()
    if not asns_env:
        raise SystemExit("ASNS environment variable is required (e.g., 'AS19318,AS13335').")

    # Allow "AS123" or "123"
    asns = [a.strip().upper() for a in asns_env.split(",") if a.strip()]
    if not asns:
        raise SystemExit("No valid ASNs provided in ASNS.")

    try:
        min_peers = int(os.environ.get("MIN_PEERS", "10"))
    except ValueError as e:
        raise SystemExit(f"MIN_PEERS must be an integer: {e}") from e

    # Optional days offsets
    start_days = os.environ.get("START_DAYS")
    end_days = os.environ.get("END_DAYS")

    try:
        start_iso = _iso8601_from_days(int(start_days)) if start_days else None
        end_iso = _iso8601_from_days(int(end_days)) if end_days else None
    except ValueError as e:
        raise SystemExit(f"Invalid START_DAYS/END_DAYS: {e}") from e

    # Diagnostics header + env snapshot
    if diag.enabled:
        diag.print("=== DIAGNOSTICS MODE ENABLED ===")
        diag.print(f"ASNS={asns_env}")
        diag.print(f"MIN_PEERS={min_peers}")
        diag.print(f"START_ISO={start_iso}  END_ISO={end_iso}")
        diag.print(f"DIAG_MAX_PREFIXES={diag.max_prefixes} DIAG_WRITE_FILES={diag.write_files} DIAG_SHOW_EXCLUSIONS={diag.show_exclusions}")
        diag.print(f"GITHUB_RUN_ID={GITHUB_RUN_ID or 'local'}  RUN_SUBDIR={RUN_SUBDIR}")
        diag.record_env(asns_env, min_peers, start_iso, end_iso)

    exclusions = load_exclusions(EXCLUSIONS_FILE)

    # Per-ASN builds
    combined_v4: List[str] = []
    combined_v6: List[str] = []
    combined_all: List[str] = []

    for asn in asns:
        v4, v6, all_list = build_for_asn(asn, min_peers, start_iso, end_iso, exclusions)
        combined_v4.extend(v4)
        combined_v6.extend(v6)
        combined_all.extend(all_list)

    # Normalize combined lists
    combined_v4 = normalize_cidrs(combined_v4)
    combined_v6 = normalize_cidrs(combined_v6)
    combined_all = normalize_cidrs(combined_all)

    # Write combined files
    write_lines(FEEDS_DIR / "combined_ipv4.txt", combined_v4)
    write_lines(FEEDS_DIR / "combined_ipv6.txt", combined_v6)
    write_lines(FEEDS_DIR / "combined_all.txt", combined_all)

    if diag.enabled:
        # Show final sizes and write to summary
        for name in ("combined_ipv4.txt", "combined_ipv6.txt", "combined_all.txt"):
            p = FEEDS_DIR / name
            diag.print(f"{name}: {'missing' if not p.exists() else p.stat().st_size} bytes")
        diag.record_combined(final_v4=len(combined_v4), final_v6=len(combined_v6))


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        diag.print(f"ERROR: SystemExit {e}")
        # Flush both log and summary on exit
        diag.dump_summary()
        diag.dump_to_file()
        raise
    except Exception as e:  # noqa: BLE001
        diag.print("UNCAUGHT EXCEPTION:", repr(e))
        diag.print(traceback.format_exc())
        # Flush both log and summary on error
        diag.dump_summary()
        diag.dump_to_file()
        raise
    else:
        # Normal completion: write summary + build.log
        diag.dump_summary()
        diag.dump_to_file()
