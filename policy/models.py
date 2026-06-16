"""Data models for PipeWarden."""

from dataclasses import dataclass, field, asdict


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

    def to_dict(self) -> dict:
        """Serialize to a dictionary, omitting empty TLS fields."""
        d = asdict(self)
        # Drop empty TLS fields to keep logs compact for non-TLS connections
        for key in ("tls_sni", "tls_cert_issuer", "tls_cert_error", "server_ip"):
            if not d.get(key):
                del d[key]
        if d.get("tls_cert_valid") is True:
            del d["tls_cert_valid"]
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
        )
