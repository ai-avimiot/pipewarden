"""Wildcard hints for generated policies.

When several sibling subdomains of the same registrable domain are observed
(e.g. registry.npmjs.org + www.npmjs.org), suggest a single `*.parent` rule —
as a **comment only**. We never auto-apply wildcards: they widen the allowlist,
and for multi-tenant suffixes (s3.amazonaws.com, cloudfront.net, …) a wildcard
would allow other tenants. Those suffixes are excluded from hints entirely.
"""

import ipaddress
from collections import defaultdict

# Suffixes where a `*.suffix` wildcard would span multiple tenants/owners or is
# otherwise too broad to suggest. Hints are suppressed for hosts under these.
SHARED_SUFFIXES = {
    # AWS
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net",
    # Azure
    "core.windows.net", "blob.core.windows.net", "azureedge.net",
    "azurewebsites.net",
    # GCP
    "googleapis.com", "storage.googleapis.com", "appspot.com", "run.app",
    # Cloudflare / hosting / PaaS
    "cloudflarestorage.com", "r2.cloudflarestorage.com", "workers.dev",
    "pages.dev", "herokuapp.com", "vercel.app", "netlify.app",
    # CDNs / object stores
    "fastly.net", "akamaized.net", "digitaloceanspaces.com",
    # Pages-style user content
    "github.io", "githubusercontent.com",
    # Common multi-label public suffixes (avoid "*.co.uk" etc.)
    "co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in",
}

MIN_SIBLINGS = 2  # need at least this many subdomains to suggest a wildcard


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable_parent(host: str) -> str | None:
    """Approximate eTLD+1 as the last two labels.

    Used only for hints, so an occasional imperfect grouping is acceptable;
    dangerous/multi-tenant cases are filtered by SHARED_SUFFIXES.
    Returns None for apex/single-label hosts (nothing to wildcard).
    """
    parts = host.split(".")
    if len(parts) < 3:
        return None
    return ".".join(parts[-2:])


def _under_shared_suffix(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in SHARED_SUFFIXES)


def wildcard_hints(hosts) -> dict[str, list[str]]:
    """Map ``parent -> sorted subdomains`` for groups worth a `*.parent` hint.

    Skips IPs, existing wildcards, apex hosts, multi-tenant suffixes, and
    groups smaller than ``MIN_SIBLINGS``.
    """
    groups: dict[str, set] = defaultdict(set)
    for h in hosts:
        if not h or h.startswith("*") or _is_ip(h) or _under_shared_suffix(h):
            continue
        parent = _registrable_parent(h)
        if not parent or parent in SHARED_SUFFIXES:
            continue
        groups[parent].add(h)
    return {
        parent: sorted(subs)
        for parent, subs in groups.items()
        if len(subs) >= MIN_SIBLINGS
    }


def hint_comment_lines(hosts, prefix: str = "# ") -> list[str]:
    """Render wildcard hints as comment lines (empty list if none)."""
    hints = wildcard_hints(hosts)
    if not hints:
        return []
    lines = [
        f"{prefix}Wildcard hints (review before using — wildcards widen the allowlist):",
    ]
    for parent in sorted(hints):
        subs = ", ".join(hints[parent])
        lines.append(f'{prefix}  consider "*.{parent}"  (seen: {subs})')
    return lines
