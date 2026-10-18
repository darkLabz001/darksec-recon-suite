"""Passive and active subdomain sources."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from urllib.parse import urlsplit

import dns.asyncresolver
import httpx

HOST_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


def normalize_hosts(raw: set[str] | list[str], domain: str) -> set[str]:
    """Keep only plausible hostnames that belong to `domain`."""
    out: set[str] = set()
    suffix = "." + domain
    for host in raw:
        host = str(host).strip().lower().rstrip(".").removeprefix("*.")
        if not host or "/" in host or " " in host or "*" in host:
            continue
        if host != domain and not host.endswith(suffix):
            continue
        if not HOST_RE.match(host):
            continue
        out.add(host)
    return out


async def crtsh(client: httpx.AsyncClient, domain: str, attempts: int = 3) -> set[str]:
    """Certificate Transparency logs via crt.sh (with retries — it 502s often)."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=90,
            )
            resp.raise_for_status()
            break
        except Exception as exc:
            last_error = exc
            if attempt < attempts - 1:
                await asyncio.sleep(2 * (attempt + 1))
    else:
        raise last_error  # type: ignore[misc]

    try:
        rows = json.loads(resp.text)
    except json.JSONDecodeError:
        # crt.sh occasionally streams broken JSON; salvage what we can.
        rows = []
        for line in resp.text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    hosts: set[str] = set()
    for row in rows:
        name_value = row.get("name_value") or ""
        for part in str(name_value).split("\n"):
            hosts.add(part)
    return normalize_hosts(hosts, domain)


async def wayback(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Hostnames harvested from the Wayback Machine CDX index."""
    resp = await client.get(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "30000",
        },
        timeout=90,
    )
    resp.raise_for_status()

    hosts: set[str] = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line == "original":
            continue
        url = line if "://" in line else "http://" + line
        host = urlsplit(url).hostname
        if host:
            hosts.add(host)
    return normalize_hosts(hosts, domain)


async def hackertarget(client: httpx.AsyncClient, domain: str) -> tuple[set[str], dict[str, str]]:
    """HackerTarget hostsearch; also returns the IPs it already knows."""
    resp = await client.get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
        timeout=30,
    )
    resp.raise_for_status()

    text = resp.text.strip()
    if text.lower().startswith("error"):
        raise RuntimeError(text)

    hosts: set[str] = set()
    known_ips: dict[str, str] = {}
    for line in text.splitlines():
        host, _, ip = line.partition(",")
        host = host.strip().lower().rstrip(".")
        if host:
            hosts.add(host)
        if ip.strip():
            known_ips[host] = ip.strip()
    return normalize_hosts(hosts, domain), known_ips


async def bruteforce(
    domain: str,
    words: list[str],
    resolver: dns.asyncresolver.Resolver,
    sem: asyncio.Semaphore,
    progress: Callable[[int, int], None] | None = None,
) -> set[str]:
    """Resolve word.domain for every candidate; surviving names are real hosts."""
    found: set[str] = set()
    done = 0

    async def attempt(word: str) -> None:
        nonlocal done
        host = f"{word}.{domain}"
        async with sem:
            try:
                await resolver.resolve(host, "A")
                found.add(host)
            except Exception:
                pass
        done += 1
        if progress and done % 250 == 0:
            progress(done, len(words))

    await asyncio.gather(*(attempt(w) for w in dict.fromkeys(words)))
    return found
