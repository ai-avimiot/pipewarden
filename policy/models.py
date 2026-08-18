"""Data models for PipeWarden."""

from dataclasses import asdict, dataclass, field

from policy.exfil import ExfilConfig


@dataclass
class ConnectionEntry:
    """Represents a single network connection observed by the proxy."""

    timestamp: str
    protocol: str  # "http", "https", "tcp"
    host: str
    port: int
    path: str = ""  # for HTTP/S only
    method: str = ""  # for HTTP/S only
    status: str = ""  # "allowed", "blocked", "would_block"
    bytes_transferred: int = 0
    # TLS metadata
    tls_sni: str = ""  # Server Name Indication from ClientHello
    tls_cert_issuer: str = ""  # Issuer CN of the server certificate
    tls_cert_valid: bool = True  # False if cert is untrusted / private CA
    tls_cert_error: str = ""  # Description of cert validation failure
    server_ip: str = ""  # Resolved IP address of the server
    # Payload-scan results (see policy/exfil.py). Each item is a serialized
    # exfil.Finding: detector, label, count, salted fingerprint — never the
    # matched value, because this log becomes an uploaded build artifact.
    exfil_findings: list[dict] = field(default_factory=list)
    # Who made the connection (see policy/attribution.py). A serialized
    # attribution.Attribution: the self-reported client, and — when the
    # privileged helper is running — the process behind it.
    attribution: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a dictionary, omitting empty TLS fields."""
        d = asdict(self)
        # Drop empty TLS fields to keep logs compact for non-TLS connections
        for key in ("tls_sni", "tls_cert_issuer", "tls_cert_error", "server_ip"):
            if not d.get(key):
                del d[key]
        if d.get("tls_cert_valid") is True:
            del d["tls_cert_valid"]
        if not d.get("exfil_findings"):
            del d["exfil_findings"]
        if not d.get("attribution"):
            del d["attribution"]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectionEntry":
        """Deserialize from a dictionary."""
        return cls(
            timestamp=data["timestamp"],
            protocol=data["protocol"],
            host=data["host"],
            port=data["port"],
            path=data.get("path", ""),
            method=data.get("method", ""),
            status=data.get("status", ""),
            bytes_transferred=data.get("bytes_transferred", 0),
            tls_sni=data.get("tls_sni", ""),
            tls_cert_issuer=data.get("tls_cert_issuer", ""),
            tls_cert_valid=data.get("tls_cert_valid", True),
            tls_cert_error=data.get("tls_cert_error", ""),
            server_ip=data.get("server_ip", ""),
            exfil_findings=data.get("exfil_findings", []),
            attribution=data.get("attribution", {}),
        )


@dataclass
class PolicyRule:
    """Represents a single allowlist rule from the network policy."""

    name: str
    domains: list[str] = field(default_factory=list)  # supports wildcards like *.example.com
    ports: list[int] = field(default_factory=list)  # empty = all ports
    protocols: list[str] = field(default_factory=list)  # http, https, tcp
    paths: list[str] = field(default_factory=list)  # URL path patterns, empty = all paths
    # How often this rule's traffic is expected to appear: "always" (default) or
    # "sometimes". "sometimes" rules (e.g. cache-dependent or conditional steps)
    # are NOT flagged as unused when not seen in a run. Report-only — does not
    # change what traffic is allowed.
    appears: str = "always"
    # Opt this destination out of payload scanning. For endpoints whose whole
    # purpose is to receive credentials — a secrets manager, an artifact store
    # you deliberately push tokens to — where a finding would be correct but
    # unhelpful. Scoped per rule so exempting one destination does not disable
    # detection everywhere.
    allow_request_body: bool = False

    def to_dict(self) -> dict:
        """Serialize to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyRule":
        """Deserialize from a dictionary."""
        return cls(
            name=data["name"],
            domains=data.get("domains", []),
            ports=data.get("ports", []),
            protocols=data.get("protocols", []),
            paths=data.get("paths", []),
            appears=data.get("appears", "always"),
            allow_request_body=data.get("allow_request_body", False),
        )


@dataclass
class Policy:
    """A parsed policy file in full.

    ``parse_policy_string``/``parse_policy_file`` return ``(mode, rules)`` and
    are kept that way — the proxy, the DNS server and a large body of tests all
    unpack that tuple. This carries the settings those two values cannot
    express, for callers that need them.
    """

    mode: str
    rules: list[PolicyRule] = field(default_factory=list)
    exfil: ExfilConfig = field(default_factory=ExfilConfig)
