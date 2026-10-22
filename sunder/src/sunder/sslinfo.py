"""TLS certificate intel: issuer, expiry countdown, SAN count."""

from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID


async def cert_info(host: str, port: int = 443, timeout: float = 10.0) -> dict | None:
    """Grab the live leaf certificate for a host (no verification — we want the
    cert even when it's expired or self-signed, that's the interesting part)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
        )
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()

    if not der:
        return None

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None

    days = (cert.not_valid_after_utc - datetime.now(UTC)).days

    orgs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    cns = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = str(orgs[0].value if orgs else cns[0].value if cns else "?")[:60]

    try:
        sans = len(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        sans = 0

    return {"days": days, "issuer": issuer, "sans": sans}
