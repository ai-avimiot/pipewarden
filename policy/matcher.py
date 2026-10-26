"""Policy matching engine for PipeWarden."""

import fnmatch
import functools
import ipaddress
import re
from urllib.parse import unquote

from policy.models import ConnectionEntry, PolicyRule

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Metadata first so the more specific label wins over "link-local".
_INTERNAL_NETWORKS: tuple[tuple[IPNetwork, str], ...] = tuple(
    (ipaddress.ip_network(cidr), label)
    for cidr, label in (
        ("169.254.169.254/32", "cloud metadata"),
        ("fd00:ec2::254/128", "cloud metadata"),
        ("168.63.129.16/32", "cloud metadata"),
        ("192.0.0.192/32", "cloud metadata"),
        ("127.0.0.0/8", "loopback"),
        ("::1/128", "loopback"),
        ("0.0.0.0/8", "unspecified"),
        ("::/128", "unspecified"),
        ("169.254.0.0/16", "link-local"),
        ("fe80::/10", "link-local"),
        ("10.0.0.0/8", "private"),
        ("172.16.0.0/12", "private"),
        ("192.168.0.0/16", "private"),
        ("100.64.0.0/10", "CGNAT"),
        ("fc00::/7", "unique-local"),
        ("192.0.0.0/24", "reserved"),
        ("198.18.0.0/15", "reserved"),
        ("240.0.0.0/4", "reserved"),
    )
)


def internal_network_category(network: IPNetwork) -> str:
    """Label of the internal range wholly containing *network*, or ""."""
    for internal, label in _INTERNAL_NETWORKS:
        if (
            network.version == internal.version
            and network.network_address in internal
            and network.broadcast_address in internal
        ):
            return label
    return ""


def internal_ip_category(ip: str) -> str:
    """Why *ip* is an internal destination (loopback, private, metadata, ...).

    Returns "" for a public address or a value that is not an IP literal, so
    a hostname that was never resolved is left to the ordinary policy check.
    """
    addr = _parse_ip(ip)
    if addr is None:
        return ""
    return internal_network_category(ipaddress.ip_network(addr))


def _parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]").split("%", 1)[0])
    except (ValueError, AttributeError):
        return None
    # ::ffff:10.0.0.1 reaches 10.0.0.1, so it must be judged as that address.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def rule_exempts_ip(rule: PolicyRule, ip: str) -> bool:
    """True if *rule* may reach internal *ip*: a v1 rule, ``allowed_ips``, or the IP named literally."""
    return (
        not rule.internal_ip_guard
        or _ip_listed(rule.allowed_ips, ip)
        or _names_ip(rule.domains, ip)
    )


def _names_ip(domains: list[str], ip: str) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    for pattern in domains:
        if pattern.lower() == "localhost" and addr.is_loopback:
            return True
        if _parse_ip(pattern) == addr:
            return True
    return False


@functools.lru_cache(maxsize=1024)
def _network(cidr: str) -> IPNetwork:
    return ipaddress.ip_network(cidr, strict=False)


def _ip_listed(allowed: list[str], ip: str) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    for cidr in allowed:
        try:
            if addr in _network(cidr):
                return True
        except ValueError:
            continue
    return False


class PolicyEngine:
    """Evaluates network connections against a set of allowlist rules.

    Supports two modes:
    - "enforce": blocks connections that don't match any rule
    - "monitor": logs but never blocks connections
    """

    def __init__(self, rules: list[PolicyRule], mode: str = "enforce"):
        self.rules = rules
        self.mode = mode  # "monitor" or "enforce"

    def allows(self, connection: ConnectionEntry) -> bool:
        """Check if a connection matches at least one policy rule.

        For DNS queries, the domain is checked against ALL rules' domain
        patterns (ignoring protocol/port), because DNS resolution must be
        allowed for any domain the pipeline is permitted to connect to.
        This also blocks DNS exfiltration to unknown domains.
        """
        if connection.protocol == "dns":
            return self._allows_dns(connection.host)
        return any(self._matches(rule, connection) for rule in self.rules)

    def _allows_dns(self, qname: str) -> bool:
        """Check if a DNS query domain matches any rule's domain patterns.

        Strips common DNS-SD prefixes (e.g. _http._tcp.) before matching
        so that SRV/HTTPS record lookups for allowed domains still pass.
        """
        # Strip DNS-SD service prefixes like _http._tcp.
        clean = qname
        while clean.startswith("_"):
            dot = clean.find(".")
            if dot < 0:
                break
            clean = clean[dot + 1:]

        for rule in self.rules:
            if self._domain_matches(rule.domains, clean):
                return True
            # Also try the original name in case it's a literal match
            if clean != qname and self._domain_matches(rule.domains, qname):
                return True
        return False

    def evaluate(self, connection: ConnectionEntry) -> str:
        """Evaluate a connection and return a mode-aware status.

        Returns:
            "allowed" — connection matches a rule
            "blocked" — no match and mode is "enforce"
            "would_block" — no match and mode is "monitor"
        """
        if self.allows(connection):
            return "allowed"
        if self.mode == "monitor":
            return "would_block"
        return "blocked"

    def method_miss(self, connection: ConnectionEntry) -> str:
        """Block reason if *connection* fails only on its HTTP method, else ""."""
        for rule in self.rules:
            if rule.methods and self._matches_except_method(rule, connection):
                return (
                    f"method {connection.method} not in methods "
                    f"[{', '.join(rule.methods)}] of rule {rule.name!r}"
                )
        return ""

    def allows_request_body(self, connection: ConnectionEntry) -> bool:
        """True if *any* rule matching *connection* opts it out of payload
        scanning.

        Any-match, not first-match, on purpose. Policies routinely put a broad
        wildcard rule (``*.example.com``) ahead of the specific one carrying
        ``allow_request_body: true``; taking the first match made the opt-out
        silently inert in exactly that ordinary layout. Rule order must not
        change what a rule's own settings mean. DNS is excluded because
        ``_allows_dns`` matches on qname alone and no single rule owns the
        verdict.
        """
        if connection.protocol == "dns":
            return False
        return any(
            rule.allow_request_body and self._matches(rule, connection)
            for rule in self.rules
        )

    def internal_ip_violation(self, connection: ConnectionEntry, ip: str) -> str:
        """Block reason if *ip* is an internal address no matching rule exempts, else "".

        Only meaningful for a connection the policy otherwise allows: an
        allowlisted name that resolves (or is rebound) to loopback, a private
        range or the cloud metadata endpoint is the classic SSRF pivot, so the
        destination needs its own explicit ``allowed_ips`` entry.
        """
        category = internal_ip_category(ip)
        if not category:
            return ""
        if connection.protocol == "dns":
            if self.dns_allows_internal_ip(connection.host, ip):
                return ""
        elif any(
            rule_exempts_ip(rule, ip) and self._matches(rule, connection)
            for rule in self.rules
        ):
            return ""
        return (
            f"destination {ip} is a {category} address not listed in "
            f"allowed_ips of any rule matching {connection.host!r}"
        )

    def dns_allows_internal_ip(self, qname: str, ip: str) -> bool:
        """True if a rule whose domains match *qname* lists *ip* in ``allowed_ips``."""
        name = qname.rstrip(".")
        return any(
            rule_exempts_ip(rule, ip) and self._domain_matches(rule.domains, name)
            for rule in self.rules
        )

    def _matches(self, rule: PolicyRule, conn: ConnectionEntry) -> bool:
        """Check if a single rule matches a connection."""
        return (
            self._matches_except_method(rule, conn)
            and self._method_matches(rule.methods, conn)
        )

    def _matches_except_method(self, rule: PolicyRule, conn: ConnectionEntry) -> bool:
        return (
            self._domain_matches(rule.domains, conn.host)
            and self._port_matches(rule.ports, conn.port)
            and conn.protocol in rule.protocols
            and self._path_matches(rule.paths, conn.path)
        )

    @staticmethod
    def _domain_matches(patterns: list[str], host: str) -> bool:
        """Check if a host matches any of the domain patterns.

        Hostnames are case-insensitive (RFC 4343), so both the host and the
        patterns are lowercased before matching. ``fnmatchcase`` is used rather
        than ``fnmatch`` so behaviour is identical across operating systems:
        ``fnmatch`` applies ``os.path.normcase``, which is case-sensitive on
        Linux but case-insensitive on macOS/Windows — meaning a mixed-case SNI
        such as ``CDN.Example.COM`` would silently fail to match ``*.example.com``
        on the Linux CI runners this tool targets.

        Uses wildcards for subdomain support (e.g. ``*.example.com``).
        """
        host_lower = host.lower()
        return any(
            fnmatch.fnmatchcase(host_lower, pattern.lower()) for pattern in patterns
        )

    @staticmethod
    def _port_matches(ports: list[int], port: int) -> bool:
        """Check if a port is in the allowed list.

        An empty ports list means all ports are allowed.
        """
        return not ports or port in ports

    @staticmethod
    def _method_matches(methods: list[str], conn: ConnectionEntry) -> bool:
        """Check if an HTTP request's method is allowed; non-HTTP traffic is unaffected.

        Case-sensitive (RFC 9110 9.1): a lowercase ``get`` is not ``GET``.
        """
        if not methods or conn.protocol not in ("http", "https"):
            return True
        return conn.method in methods

    @staticmethod
    def _path_matches(patterns: list[str], path: str) -> bool:
        """Check if a request path matches any of the path patterns.

        An empty patterns list means all paths are allowed.
        Uses fnmatch for wildcard support (e.g. /api/*, /simple/*).

        Unlike hostnames, URL paths are case-sensitive, so matching preserves
        case. ``fnmatchcase`` is used so the result does not depend on the host
        operating system's filename case semantics.
        """
        if not patterns:
            return True
        normalised = _normalise_path(path)
        if normalised is None:
            return False
        return any(fnmatch.fnmatchcase(normalised, pattern) for pattern in patterns)


# After one percent-decode: an encoded separator or dot is read differently by
# different servers, so a path that still carries one cannot be matched safely.
_AMBIGUOUS_PATH = re.compile(r"%(?:2[ef]|5c)|\\", re.IGNORECASE)


def _normalise_path(path: str) -> str | None:
    """Percent-decode *path* and resolve dot-segments (RFC 3986 5.2.4).

    Returns None for a path no rule should match: one that climbs above the
    root, or whose meaning depends on how the server decodes it.
    """
    if _AMBIGUOUS_PATH.search(path):
        return None
    decoded = unquote(path)
    if _AMBIGUOUS_PATH.search(decoded):
        return None
    out: list[str] = []
    segments = decoded.split("/")
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == ".":
            if last:
                out.append("")
            continue
        if seg == "..":
            if len(out) <= 1:
                return None
            out.pop()
            if last:
                out.append("")
            continue
        out.append(seg)
    return "/".join(out)
