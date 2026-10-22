"""Detect admin panels and login surfaces from a probed HTTP response.

Detection runs on data the probe already collected (final URL, title, body
snippet), so flagging costs no extra requests.
"""

from __future__ import annotations

import re

# Product-specific signals, checked first — most precise.
TITLE_MARKERS: tuple[tuple[str, str], ...] = (
    (r"phpmyadmin", "phpmyadmin"),
    (r"\bgrafana\b", "grafana"),
    (r"\bjenkins\b", "jenkins"),
    (r"\bkibana\b", "kibana"),
    (r"prometheus", "prometheus"),
    (r"sonarqube", "sonarqube"),
    (r"zabbix", "zabbix"),
    (r"nagios", "nagios"),
    (r"portainer", "portainer"),
    (r"rancher", "rancher"),
    (r"argo ?cd", "argocd"),
    (r"netdata", "netdata"),
    (r"proxmox", "proxmox"),
    (r"vmware|vsphere", "vmware"),
    (r"webmin", "webmin"),
    (r"plesk", "plesk"),
    (r"\bcpanel\b", "cpanel"),
    (r"adminer", "adminer"),
    (r"roundcube", "roundcube"),
    (r"apache tomcat", "tomcat"),
)

URL_MARKERS: tuple[tuple[str, str], ...] = (
    (r"/wp-(?:admin|login)(?:/|$|\?|\.php)", "wordpress"),
    (r"/phpmyadmin|/pma(?:/|$)|/pmahomme", "phpmyadmin"),
    (r"/adminer(?:/|$|\.)", "adminer"),
    (r"/manager/html", "tomcat manager"),
    (r"/(?:cpanel|cpsession)(?:/|$|\?)", "cpanel"),
    (r"/owa(?:/|$|\?)|/ecp(?:/|$)", "exchange"),
    (r"/roundcube(?:/|$)", "roundcube"),
    (r"/webmin(?:/|$)", "webmin"),
    (r"/plesk(?:/|$)", "plesk"),
    (r"/grafana(?:/|$)", "grafana"),
    (r"/(?:siteadmin|administrator|admin)(?:/|$|\?|\.php|\.html?)", "admin path"),
    (r"/(?:panel|dashboard|backend|console|manage|management|controlpanel|control-panel|sysadmin)(?:/|$|\?|\.php)", "panel path"),
)

# Strong, unambiguous body fingerprints.
BODY_MARKERS: tuple[tuple[str, str], ...] = (
    (r"wp-login\.php", "wordpress"),
    (r"Drupal\.settings", "drupal"),
    (r"Joomla!", "joomla"),
    (r"phpMyAdmin", "phpmyadmin"),
    (r"Jenkins-Crumb|x-jenkins", "jenkins"),
)

# Generic catches: last resort, only if nothing above matched.
# Deliberately excludes "administration" — that word in prose is usually marketing.
GENERIC_TITLE = r"\badmin\b|\badministrator\b|\bdashboard\b|\bcontrol panel\b"

PASSWORD_INPUT = re.compile(r"<input[^>]+type=[\"']?password", re.IGNORECASE)
LOGIN_CONTEXT = re.compile(
    r"admin|log ?in|sign ?in|auth|dashboard|panel|manage|cpanel", re.IGNORECASE
)

# ---------------------------------------------------------------- tech audit #

TECH_HEADER_MARKERS: tuple[tuple[str, str], ...] = (
    ("cf-ray", "cloudflare"),
    ("x-amz-cf-id", "cloudfront"),
    ("x-vercel-id", "vercel"),
    ("x-squarespace-version", "squarespace"),
    ("x-shopify-stage", "shopify"),
    ("x-github-request-id", "github"),
    ("x-azure-ref", "azure"),
    ("x-fastly-request-id", "fastly"),
    ("x-drupal-dynamic-cache", "drupal"),
    ("x-aspnet-version", "asp.net"),
    ("x-generator", ""),
    ("x-pingback", ""),
)

COOKIE_MARKERS: tuple[tuple[str, str], ...] = (
    ("phpsessid", "php"),
    ("asp.net_sessionid", "asp.net"),
    ("jsessionid", "java"),
    ("laravel_session", "php/laravel"),
    ("connect.sid", "node/express"),
    ("play_session", "play/java"),
    ("csrftoken", "django"),
)

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "no-hsts"),
    ("content-security-policy", "no-csp"),
    ("x-content-type-options", "no-xcto"),
    ("x-frame-options", "no-xfo"),
)


def analyze_headers(headers: dict[str, str], https: bool = True) -> tuple[str, str]:
    """Fingerprint tech from response headers and note missing security headers.

    Returns (tech_summary, security_issues), both comma-joined strings.
    """
    tech: list[str] = []
    issues: list[str] = []

    server = headers.get("server", "")
    if server:
        tech.append(server[:40])
        if re.search(r"/[\d.]+", server):
            issues.append("server version exposed")

    powered = headers.get("x-powered-by", "")
    if powered:
        tech.append(powered[:40])

    generator = headers.get("x-generator", "")
    if generator:
        tech.append(generator[:40])

    for header, name in TECH_HEADER_MARKERS:
        if name and header in headers and name not in tech:
            tech.append(name)

    cookie_str = headers.get("set-cookie", "").lower()
    for marker, name in COOKIE_MARKERS:
        if marker in cookie_str and name not in tech:
            tech.append(name)

    for header, label in SECURITY_HEADERS:
        if header in headers:
            continue
        if label == "no-hsts" and not https:
            continue  # HSTS over plain http is meaningless
        issues.append(label)

    return ", ".join(tech), ", ".join(issues)

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in (*TITLE_MARKERS, *URL_MARKERS, *BODY_MARKERS)
]
_GENERIC_TITLE_RE = re.compile(GENERIC_TITLE, re.IGNORECASE)


def detect_panel(url: str = "", title: str = "", body: str = "") -> str:
    """Return a short panel name if this response smells like an admin surface."""
    title = title or ""
    body = body or ""

    # Product titles beat everything (a /admin path serving Grafana is Grafana).
    for pattern, name in TITLE_MARKERS:
        if re.search(pattern, title, re.IGNORECASE):
            return name

    for compiled, name in _COMPILED:
        if compiled.search(url) or (body and compiled.search(body)):
            return name

    if _GENERIC_TITLE_RE.search(title):
        return "admin page"

    if PASSWORD_INPUT.search(body) and LOGIN_CONTEXT.search(title or url):
        return "admin login"

    return ""
