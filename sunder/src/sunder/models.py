from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum


class TargetKind(Enum):
    DOMAIN = "domain"
    IP = "ip"


@dataclass(slots=True)
class Target:
    raw: str
    kind: TargetKind
    normalized: str


def classify(raw: str) -> Target | None:
    """Turn a user-supplied string into a Target, or None if it is nonsense."""
    s = raw.strip()
    if not s:
        return None

    # Accept pasted URLs: https://sub.example.com:8443/path -> sub.example.com
    body = s.lower()
    body = body.removeprefix("https://").removeprefix("http://")
    if "/" in body:
        body = body.split("/", 1)[0]
    body = body.rstrip(".")

    # An IPv6 literal may legitimately contain colons, check it before stripping a port.
    try:
        ip = ipaddress.ip_address(body)
        return Target(raw=s, kind=TargetKind.IP, normalized=str(ip))
    except ValueError:
        pass

    if ":" in body:  # strip :port from hostnames
        body = body.rsplit(":", 1)[0]

    labels = body.split(".")
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 or label.startswith("-") for label in labels):
        return None
    if not all(c.isalnum() or c in "-." for c in body):
        return None
    return Target(raw=s, kind=TargetKind.DOMAIN, normalized=body)


@dataclass
class Finding:
    """One enumerated host (or one IP with its reverse/registration info)."""

    target: str
    host: str
    kind: str = "host"  # host | apex | wildcard | ip
    sources: set[str] = field(default_factory=set)
    ips: list[str] = field(default_factory=list)
    resolved: bool = False
    status: int | None = None
    scheme: str = ""
    title: str = ""
    url: str = ""
    note: str = ""
    panel: str = ""
    cname: str = ""
    takeover: str = ""
    cert_days: int | None = None
    cert_issuer: str = ""
    cert_sans: int = 0
    tech: str = ""
    sec: str = ""

    @property
    def source_str(self) -> str:
        src = ",".join(sorted(self.sources))
        if self.kind == "wildcard":
            src += " ⚠wild"
        return src
