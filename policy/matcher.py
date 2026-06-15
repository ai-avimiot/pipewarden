"""Policy matching engine for PipeWarden."""

import fnmatch

from policy.models import ConnectionEntry, PolicyRule


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

    def _matches(self, rule: PolicyRule, conn: ConnectionEntry) -> bool:
        """Check if a single rule matches a connection."""
        return (
            self._domain_matches(rule.domains, conn.host)
            and self._port_matches(rule.ports, conn.port)
            and conn.protocol in rule.protocols
            and self._path_matches(rule.paths, conn.path)
        )

    @staticmethod
    def _domain_matches(patterns: list[str], host: str) -> bool:
        """Check if a host matches any of the domain patterns.

        Uses fnmatch for wildcard support (e.g. *.example.com).
        """
        return any(fnmatch.fnmatch(host, pattern) for pattern in patterns)

    @staticmethod
    def _port_matches(ports: list[int], port: int) -> bool:
        """Check if a port is in the allowed list.

        An empty ports list means all ports are allowed.
        """
        return not ports or port in ports

    @staticmethod
    def _path_matches(patterns: list[str], path: str) -> bool:
        """Check if a request path matches any of the path patterns.

        An empty patterns list means all paths are allowed.
        Uses fnmatch for wildcard support (e.g. /api/*, /simple/*).
        """
        if not patterns:
            return True
        return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
