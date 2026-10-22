"""Subdomain takeover detection: dangling CNAMEs and dead-service bodies."""

from __future__ import annotations

import re

# CNAME targets that point at services where an unclaimed name stays live.
SERVICE_CNAME: tuple[tuple[str, str], ...] = (
    (r"\.herokuapp\.com$", "heroku"),
    (r"\.herokussl\.com$", "heroku"),
    (r"\.github\.io$", "github pages"),
    (r"\.azurewebsites\.net$", "azure"),
    (r"\.cloudapp\.net$", "azure"),
    (r"\.azure-cloud\.net$", "azure"),
    (r"\.trafficmanager\.net$", "azure"),
    (r"\.blob\.core\.windows\.net$", "azure blob"),
    (r"\.s3-website[.-]", "s3"),
    (r"\.amazonaws\.com$", "s3/aws"),
    (r"\.elasticbeanstalk\.com$", "aws beanstalk"),
    (r"\.cloudfront\.net$", "cloudfront"),
    (r"\.fastly\.net$", "fastly"),
    (r"\.edgekey\.net$", "akamai"),
    (r"\.akamaized\.net$", "akamai"),
    (r"\.zendesk\.com$", "zendesk"),
    (r"\.myshopify\.com$", "shopify"),
    (r"\.shopify\.com$", "shopify"),
    (r"\.wordpress\.com$", "wordpress.com"),
    (r"\.tumblr\.com$", "tumblr"),
    (r"\.surge\.sh$", "surge"),
    (r"\.bitbucket\.io$", "bitbucket"),
    (r"\.pantheon\.io$", "pantheon"),
    (r"\.statuspage\.io$", "statuspage"),
    (r"\.uservoice\.com$", "uservoice"),
    (r"\.unbounce\.com$", "unbounce"),
    (r"\.webflow\.io$", "webflow"),
    (r"\.readthedocs\.io$", "readthedocs"),
    (r"\.helpjuice\.com$", "helpjuice"),
    (r"\.campaignmonitor\.com$", "campaignmonitor"),
    (r"\.smugmug\.com$", "smugmug"),
    (r"\.ghost\.io$", "ghost"),
    (r"\.netlify\.app$", "netlify"),
    (r"\.vercel\.app$", "vercel"),
    (r"\.firebaseapp\.com$", "firebase"),
    (r"\.web\.app$", "firebase"),
    (r"\.ngrok\.(?:io|app)$", "ngrok"),
)

# Bodies the dead services themselves serve on unclaimed names.
BODY_MARKERS: tuple[tuple[str, str], ...] = (
    (r"There (?:isn'?t|is no) a GitHub Pages site here", "github pages"),
    (r"No such app", "heroku"),
    (r"404 Web Site not found", "azure"),
    (r"The specified bucket does not exist|NoSuchBucket", "s3/aws"),
    (r"Fastly error: unknown domain", "fastly"),
    (r"Reference #\w+\.\w+\.edgesuite\.net", "akamai"),
    (r"Help Center Closed|this help center no longer exists", "zendesk"),
    (r"Sorry, this shop is currently unavailable", "shopify"),
    (r"There ?s nothing here", "tumblr"),
    (r"project not found", "surge"),
    (r"Repository not found", "bitbucket"),
    (r"404 error unknown site", "pantheon"),
    (r"Sorry, this page is no longer available", "statuspage"),
    (r"This UserVoice subdomain no longer exists", "uservoice"),
)

_CNAME_COMPILED = tuple((re.compile(p, re.IGNORECASE), name) for p, name in SERVICE_CNAME)
_BODY_COMPILED = tuple((re.compile(p, re.IGNORECASE), name) for p, name in BODY_MARKERS)


def cname_service(cname: str | None) -> str | None:
    """Which takeover-prone service does this CNAME target?"""
    if not cname:
        return None
    cname = cname.strip().lower().rstrip(".")
    for pattern, name in _CNAME_COMPILED:
        if pattern.search(cname):
            return name
    return None


def body_service(body: str | None) -> str | None:
    """Does this page body match a dead-service error page?"""
    if not body:
        return None
    for pattern, name in _BODY_COMPILED:
        if pattern.search(body):
            return name
    return None
