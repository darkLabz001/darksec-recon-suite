"""Orchestrates a scan: sources run concurrently, then resolve + probe phases."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from .fingerprint import analyze_headers
from .ipinfo import ip_report, summarize
from .models import Finding, Target, TargetKind
from .records import apex_records, try_axfr
from .resolver import detect_wildcard, make_resolver, probe_host, resolve_cname, resolve_ips
from .sources import bruteforce, crtsh, hackertarget, wayback
from .sslinfo import cert_info
from .takeover import cname_service
from .wordlist import DEFAULT_SUBDOMAINS

USER_AGENT = "sunder/0.1 (subdomain enumeration tool)"

LogFn = Callable[[str, str, str], None]
FindingFn = Callable[[Finding], None]
RecordsFn = Callable[[str, dict[str, list[str]], tuple[str, int] | None], None]


@dataclass
class Options:
    crtsh: bool = True
    wayback: bool = True
    hackertarget: bool = True
    bruteforce: bool = True
    resolve: bool = True
    probe: bool = True
    admin: bool = True
    takeover: bool = True
    cert: bool = True
    records: bool = True
    axfr: bool = True
    wordlist: list[str] = field(default_factory=lambda: list(DEFAULT_SUBDOMAINS))
    max_hosts: int = 4000
    resolve_concurrency: int = 60
    probe_concurrency: int = 30


class Engine:
    """Runs every enabled source against every target, streaming findings out
    through `on_finding` as they appear (findings are mutated in place on
    later resolve/probe passes, and re-emitted)."""

    def __init__(
        self,
        options: Options,
        on_log: LogFn,
        on_finding: FindingFn,
        on_records: RecordsFn | None = None,
    ) -> None:
        self.o = options
        self._log_fn = on_log
        self._finding_fn = on_finding
        self._records_cb = on_records
        self.client: httpx.AsyncClient | None = None
        self.resolver = None
        self._dns_sem: asyncio.Semaphore | None = None

    # ------------------------------------------------------------------ #

    def log(self, source: str, level: str, message: str) -> None:
        self._log_fn(source, level, message)

    def emit(self, finding: Finding) -> None:
        self._finding_fn(finding)

    # ------------------------------------------------------------------ #

    async def run(self, targets: list[Target]) -> None:
        self.client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            http2=True,
            timeout=30,
            follow_redirects=True,
        )
        self.resolver = make_resolver()
        self._dns_sem = asyncio.Semaphore(self.o.resolve_concurrency)
        try:
            await asyncio.gather(*(self._run_one(t) for t in targets))
        finally:
            await self.client.aclose()

    async def _run_one(self, target: Target) -> None:
        if target.kind is TargetKind.IP:
            await self._run_ip(target)
        else:
            await self._run_domain(target)

    # ------------------------------------------------------------------ #

    async def _run_ip(self, target: Target) -> None:
        ip = target.normalized
        self.log("ip", "run", f"looking up {ip} …")
        report = await ip_report(self.client, ip, self.resolver)
        note = summarize(report)
        finding = Finding(
            target=ip,
            host=report["ptr"] or "(no reverse dns)",
            kind="ip",
            sources={"ptr", "rdap", "cymru"},
            ips=[ip],
            resolved=True,
            note=note,
        )
        self.emit(finding)
        self.log("ip", "ok", note)

    async def _run_domain(self, target: Target) -> None:
        domain = target.normalized
        findings: dict[str, Finding] = {}
        passive_ips: dict[str, str] = {}

        def make(host: str, source: str) -> None:
            finding = findings.get(host)
            if finding is None:
                finding = Finding(
                    target=domain,
                    host=host,
                    kind="apex" if host == domain else "host",
                )
                findings[host] = finding
            finding.sources.add(source)
            self.emit(finding)

        # The apex is part of the picture: its records, cert and title count.
        make(domain, "apex")

        async def run_source(name: str, fn) -> None:
            started = time.monotonic()
            self.log(name, "run", f"querying {domain} …")
            try:
                result = await fn()
                if isinstance(result, tuple):
                    result, known_ips = result
                    passive_ips.update(known_ips)
                for host in result:
                    make(host, name)
                self.log(name, "ok", f"{len(result)} hosts in {time.monotonic() - started:.1f}s")
            except Exception as exc:
                self.log(name, "err", f"{type(exc).__name__}: {exc}")

        jobs = []
        if self.o.crtsh:
            jobs.append(run_source("crt.sh", lambda: crtsh(self.client, domain)))
        if self.o.wayback:
            jobs.append(run_source("wayback", lambda: wayback(self.client, domain)))
        if self.o.hackertarget:
            jobs.append(run_source("hackertarget", lambda: hackertarget(self.client, domain)))
        if self.o.bruteforce:
            jobs.append(self._brute_job(domain, make))
        if self.o.records:
            jobs.append(self._records_job(domain))

        if jobs:
            await asyncio.gather(*jobs)

        hosts = sorted(findings)
        if len(hosts) > self.o.max_hosts:
            self.log("engine", "warn", f"truncating to {self.o.max_hosts} hosts (had {len(hosts)})")
            hosts = hosts[: self.o.max_hosts]

        if self.o.resolve:
            wildcard_ips = set()
            if self.o.bruteforce:
                wildcard_ips = await detect_wildcard(domain, self.resolver)
                if wildcard_ips:
                    self.log(
                        "wildcard",
                        "warn",
                        f"{domain} answers for ANY name — wildcard DNS, brute hits may be noise",
                    )

            async def resolve_one(host: str) -> None:
                finding = findings[host]
                async with self._dns_sem:
                    ips = await resolve_ips(host, self.resolver)
                    cname = await resolve_cname(host, self.resolver) if self.o.takeover else None
                known = passive_ips.get(host)
                if known:
                    ips.append(known)
                finding.ips = sorted(set(ips))
                finding.resolved = True
                finding.cname = cname or ""
                if (
                    wildcard_ips
                    and finding.ips
                    and set(finding.ips) <= wildcard_ips
                    and finding.sources <= {"brute", "wayback"}
                ):
                    finding.kind = "wildcard"
                if cname and not finding.ips:
                    service = cname_service(cname)
                    if service:
                        finding.takeover = f"{service} (dangling)"
                        self.log("takeover", "warn", f"⚠ {host} → {cname} — no A record, {service} looks claimable")
                self.emit(finding)

            await asyncio.gather(*(resolve_one(h) for h in hosts))

            if self.o.probe:
                probe_sem = asyncio.Semaphore(self.o.probe_concurrency)

                async def probe_one(host: str) -> None:
                    finding = findings[host]
                    if not finding.ips or finding.kind == "wildcard":
                        return
                    async with probe_sem:
                        result = await probe_host(self.client, host)
                    finding.status = result.status
                    finding.title = result.title
                    finding.url = result.url
                    finding.scheme = result.scheme
                    if result.headers:
                        finding.tech, finding.sec = analyze_headers(
                            result.headers, https=result.scheme == "https"
                        )
                    if self.o.admin and result.panel:
                        finding.panel = result.panel
                        self.log("probe", "warn", f"⚡ {result.panel}: {host} ({result.url})")
                    if self.o.takeover and result.takeover_hint:
                        service = cname_service(finding.cname)
                        if service == result.takeover_hint or not finding.cname:
                            finding.takeover = f"{result.takeover_hint} (confirmed)"
                            self.log(
                                "takeover",
                                "warn",
                                f"⚠ {host} serves a {result.takeover_hint} dead-service page — takeover confirmed",
                            )
                    self.emit(finding)

                self.log("probe", "run", f"probing {sum(1 for h in hosts if findings[h].ips)} live hosts …")
                await asyncio.gather(*(probe_one(h) for h in hosts))

            if self.o.cert:
                cert_sem = asyncio.Semaphore(10)

                async def cert_one(host: str) -> None:
                    finding = findings[host]
                    if not finding.ips or finding.scheme != "https":
                        return
                    async with cert_sem:
                        info = await cert_info(host)
                    if not info:
                        return
                    finding.cert_days = info["days"]
                    finding.cert_issuer = info["issuer"]
                    finding.cert_sans = info["sans"]
                    if info["days"] <= 14:
                        state = "EXPIRED" if info["days"] < 0 else f"expires in {info['days']}d"
                        self.log("cert", "warn", f"⚠ cert for {host} {state} ({info['issuer']})")
                    self.emit(finding)

                await asyncio.gather(*(cert_one(h) for h in hosts))

        panels = sum(1 for f in findings.values() if f.panel)
        takeovers = sum(1 for f in findings.values() if f.takeover)
        summary = f"{domain}: {len(findings)} unique hosts"
        if panels:
            summary += f" — ⚡ {panels} admin panel{'s' if panels != 1 else ''}"
        if takeovers:
            summary += f" — ⚠ {takeovers} possible takeover{'s' if takeovers != 1 else ''}"
        self.log("engine", "ok", summary)

    async def _records_job(self, domain: str) -> None:
        try:
            records = await apex_records(domain, self.resolver)
            nameservers = records.get("NS", [])
            axfr = None
            if self.o.axfr and nameservers:
                self.log("axfr", "run", f"trying zone transfer against {len(nameservers)} nameserver(s) …")
                axfr = await try_axfr(domain, nameservers, self.resolver)
            if self._records_cb:
                self._records_cb(domain, records, axfr)
            self.log("records", "ok", f"{domain}: {sum(len(v) for v in records.values())} apex records")
        except Exception as exc:
            self.log("records", "err", f"{type(exc).__name__}: {exc}")

    async def _brute_job(self, domain: str, make) -> None:
        started = time.monotonic()
        words = self.o.wordlist
        self.log("brute", "run", f"trying {len(words)} candidate names …")

        def progress(done: int, total: int) -> None:
            self.log("brute", "run", f"{done}/{total} names tried …")

        try:
            found = await bruteforce(domain, words, self.resolver, self._dns_sem, progress)
            for host in found:
                make(host, "brute")
            self.log("brute", "ok", f"{len(found)} hosts in {time.monotonic() - started:.1f}s")
        except Exception as exc:
            self.log("brute", "err", f"{type(exc).__name__}: {exc}")
