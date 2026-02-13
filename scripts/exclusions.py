# scripts/exclusions.py
import ipaddress
import os
import warnings
from typing import Iterable, List, Set, Union

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

def load_exclusions(path: str = "feeds/exclusions.txt") -> Set[IPNet]:
    """
    Read exclusion networks from feeds/exclusions.txt.
    - Supports blank lines and '#' comments.
    - Returns a set of IPv4Network/IPv6Network objects.
    - Missing file returns empty set (no-op).
    """
    nets: Set[IPNet] = set()
    if not os.path.exists(path):
        return nets

    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.add(ipaddress.ip_network(line, strict=False))
            except ValueError:
                warnings.warn(f"[exclusions] Skipping invalid CIDR at line {lineno}: {line}")
    return nets


def _subtract_one(net: IPNet, excludes: Iterable[IPNet]) -> List[IPNet]:
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
    excludes_v4 = [e for e in excludes if isinstance(e, ipaddress.IPv4Network)]
    excludes_v6 = [e for e in excludes if isinstance(e, ipaddress.IPv6Network)]

    out: List[IPNet] = []
    for n in nets:
        exs = excludes_v4 if isinstance(n, ipaddress.IPv4Network) else excludes_v6
        out.extend(_subtract_one(n, exs))

    # Collapse any adjacent/sibling prefixes produced by subtraction
    collapsed = list(ipaddress.collapse_addresses(out))

    # Sort deterministically: family, network address, prefix length
    collapsed.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return collapsed
