"""DNS resolution, wildcard detection and HTTP probing."""

from __future__ import annotations

import asyncio
import random
import re
import string
from dataclasses import dataclass, field

import dns.asyncresolver
import httpx

from .fingerprint import detect_panel
from .takeover import body_service

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass(slots=True)
class ProbeResult:
    status: int | None
    title: str
    url: str
    scheme: str
    panel: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    takeover_hint: str = ""


def make_resolver(timeout: float = 3.0, lifetime: float = 6.0) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def system_resolver(timeout: float = 3.0, lifetime: float = 6.0) -> dns.asyncresolver.Resolver:
    """Resolver that uses the nameservers configured on this host."""
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


async def _answers(resolver: dns.asyncresolver.Resolver, host: str) -> bool:
    """Report whether the resolver can complete a DNS exchange at all."""
    try:
        await resolver.resolve(host, "A", raise_on_no_answer=False)
    except Exception:
        return False
    return True


async def build_resolver(
    timeout: float = 3.0, lifetime: float = 6.0, probe: str = "example.com"
) -> tuple[dns.asyncresolver.Resolver, str]:
    """Build a resolver, falling back to the system DNS when it is needed.

    Public resolvers are preferred so that queries do not leak to the ISP's
    DNS.  Some networks block them though - locked-down LANs, VPN-only
    egress, filtered egress - and every lookup would then fail.  When the
    public resolvers do not answer, the nameservers from /etc/resolv.conf
    are used instead.

    Returns the resolver and a label describing where it came from.
    """
    public = make_resolver(timeout=timeout, lifetime=lifetime)
    if await _answers(public, probe):
        return public, "public"

    fallback = system_resolver(timeout=timeout, lifetime=lifetime)
    if not fallback.nameservers:
        return public, "public (unreachable)"
    if await _answers(fallback, probe):
        return fallback, "system"
    return public, "public (unreachable)"


async def resolve_ips(host: str, resolver: dns.asyncresolver.Resolver) -> list[str]:
    ips: set[str] = set()
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rdtype)
            ips.update(str(rr) for rr in answer)
        except Exception:
            pass
    return sorted(ips)


async def detect_wildcard(
    domain: str, resolver: dns.asyncresolver.Resolver, probes: int = 3
) -> set[str]:
    """Resolve random labels; any answer means the zone has wildcard DNS."""

    async def probe() -> set[str]:
        label = "sunder-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        return set(await resolve_ips(f"{label}.{domain}", resolver))

    results = await asyncio.gather(*(probe() for _ in range(probes)))
    wildcard_ips: set[str] = set()
    for ips in results:
        wildcard_ips.update(ips)
    return wildcard_ips


async def resolve_cname(host: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    try:
        answer = await resolver.resolve(host, "CNAME")
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


async def reverse_ptr(ip: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    try:
        answer = await resolver.resolve_address(ip)
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


async def probe_host(client: httpx.AsyncClient, host: str) -> ProbeResult:
    """Try https then http; return status, title, final url and any admin panel found."""
    for scheme in ("https", "http"):
        try:
            async with client.stream(
                "GET", f"{scheme}://{host}/", follow_redirects=True, timeout=12
            ) as resp:
                title = ""
                body_text = ""
                content_type = resp.headers.get("content-type", "")
                if "html" in content_type or not content_type:
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > 131_072:
                            break
                    body_text = body.decode("utf-8", "ignore")
                    match = TITLE_RE.search(body_text)
                    if match:
                        title = re.sub(r"\s+", " ", match.group(1)).strip()[:120]
                url = str(resp.url)
                panel = detect_panel(url=url, title=title, body=body_text)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                hint = body_service(body_text)
                return ProbeResult(resp.status_code, title, url, scheme, panel, headers, hint)
        except Exception:
            continue
    return ProbeResult(None, "", "", "")
