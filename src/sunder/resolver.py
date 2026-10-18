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
