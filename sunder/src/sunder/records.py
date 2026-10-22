"""Apex DNS records and AXFR zone-transfer attempts."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.query
import dns.zone

QUERY_PLAN: tuple[tuple[str, str], ...] = (
    ("NS", "@"),
    ("MX", "@"),
    ("TXT", "@"),
    ("CAA", "@"),
    ("SOA", "@"),
    ("A", "@"),
    ("TXT", "_dmarc"),
)


async def apex_records(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, list[str]]:
    """Collect the apex DNS record set: NS, MX, TXT/SPF, DMARC, CAA, SOA, A."""
    out: dict[str, list[str]] = {}
    for rdtype, label in QUERY_PLAN:
        name = domain if label == "@" else f"{label}.{domain}"
        try:
            answer = await resolver.resolve(name, rdtype)
            key = rdtype if label == "@" else f"{label} {rdtype}"
            out.setdefault(key, sorted({str(rr) for rr in answer}))
        except Exception:
            continue
    return out


async def try_axfr(
    domain: str, nameservers: list[str], resolver: dns.asyncresolver.Resolver, timeout: float = 6.0
) -> tuple[str, int] | None:
    """Attempt a zone transfer against each nameserver. Returns (ns_ip, entries) on success."""
    for ns in nameservers:
        ns = ns.rstrip(".")
        try:
            answer = await resolver.resolve(ns, "A")
            ns_ip = str(answer[0])
        except Exception:
            continue

        def attempt(target_ip: str) -> int:
            zone = dns.zone.from_xfr(dns.query.xfr(target_ip, domain, timeout=timeout))
            return len(zone.nodes)

        try:
            count = await asyncio.to_thread(attempt, ns_ip)
            return ns_ip, count
        except Exception:
            continue
    return None
