"""Passive intel for IP targets: PTR, RDAP registration data, ASN."""

from __future__ import annotations

import dns.asyncresolver
import httpx


def _vcard_org(entity: dict) -> str | None:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == "fn":
                return str(item[3])
    except (IndexError, TypeError, AttributeError):
        pass
    return None


async def ip_report(
    client: httpx.AsyncClient, ip: str, resolver: dns.asyncresolver.Resolver
) -> dict[str, str]:
    """Collect everything we can learn about an IP without touching it."""
    report = {"ip": ip, "ptr": "", "asn": "", "as_name": "", "netrange": "", "country": "", "org": ""}

    ptr = await _ptr(ip, resolver)
    if ptr:
        report["ptr"] = ptr

    asn_info = await _asn_cymru(ip, resolver)
    if asn_info:
        report["asn"], report["netrange"], report["country"], registry = asn_info
        report["registry"] = registry

    try:
        resp = await client.get(f"https://rdap.org/ip/{ip}", timeout=30)
        resp.raise_for_status()
        data = resp.json()
        report["org"] = data.get("name") or ""
        start, end = data.get("startAddress"), data.get("endAddress")
        if start and end and start != end:
            report.setdefault("netrange", report.get("netrange") or f"{start} - {end}")
        report["country"] = report.get("country") or data.get("country") or ""
        for entity in data.get("entities", []) or []:
            org = _vcard_org(entity)
            if org:
                report["as_name"] = report.get("as_name") or org
                break
    except Exception:
        pass

    return report


async def _ptr(ip: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    try:
        answer = await resolver.resolve_address(ip)
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


async def _asn_cymru(
    ip: str, resolver: dns.asyncresolver.Resolver
) -> tuple[str, str, str, str] | None:
    """Team Cymru origin ASN over DNS: 'asn | prefix | cc | registry | allocated'."""
    try:
        import ipaddress

        if ":" in ip:  # IPv6: nibble-reversed names under origin6.asn.cymru.com
            addr = ipaddress.ip_address(ip)
            nibbles = f"{addr.int:032x}"
            query = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
        else:
            query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        answer = await resolver.resolve(query, "TXT")
        fields = [f.strip().strip('"') for f in str(answer[0]).split("|")]
        asn = f"AS{fields[0].split()[0]}" if fields else ""
        netrange = fields[1] if len(fields) > 1 else ""
        country = fields[2] if len(fields) > 2 else ""
        registry = fields[3] if len(fields) > 3 else ""
        return asn, netrange, country, registry
    except Exception:
        return None


def summarize(report: dict[str, str]) -> str:
    parts = []
    if report.get("asn"):
        parts.append(report["asn"])
    if report.get("as_name"):
        parts.append(report["as_name"].upper()[:40])
    elif report.get("org"):
        parts.append(report["org"].upper()[:40])
    if report.get("country"):
        parts.append(report["country"])
    if report.get("netrange"):
        parts.append(report["netrange"])
    if report.get("registry"):
        parts.append(report["registry"])
    return " · ".join(parts) if parts else "no registration data"
