"""mitmproxy addon for PipeWarden.

Intercepts HTTP/HTTPS/TCP connections, evaluates them against a network
policy, and writes structured JSONL log entries.

In transparent proxy mode, HTTPS domain names are extracted from the TLS
SNI (Server Name Indication) in the ClientHello. Server certificates are
verified against the system trust store to detect rogue/private certs.
"""

import fcntl
import json
import logging
import os
import ssl
import sys
from datetime import datetime, timezone

# mitmproxy may not be installed in the test environment.
try:
    from mitmproxy import http, tcp  # noqa: F401
except ImportError:
    pass

# Ensure the project root is importable when running inside the
# proxy container (where addon.py lives at /addon.py and policy/ at /policy/).
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
_parent = os.path.dirname(_project_root)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from policy.parser import parse_policy_file  # noqa: E402
from policy.matcher import PolicyEngine  # noqa: E402
from policy.models import ConnectionEntry  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "/var/log/connections.jsonl"
DNS_IP_MAP_PATH = "/var/log/dns_ip_map.json"


# ---------------------------------------------------------------------------
# Certificate verification helper
# ---------------------------------------------------------------------------

def _build_trust_store() -> ssl.SSLContext | None:
    """Build an SSL context loaded with the system trust store.

    Returns None if the trust store cannot be loaded (e.g. certifi missing).
    """
    try:
        ctx = ssl.create_default_context()
        # Also try loading certifi bundle if available
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except ImportError:
            pass
        return ctx
    except Exception:
        return None


def verify_server_cert(cert_pem: bytes, hostname: str,
                       trust_ctx: ssl.SSLContext | None,
                       chain_pems: list[bytes] | None = None,
                       ) -> tuple[bool, str]:
    """Verify a server certificate against the system trust store.

    Uses pyOpenSSL's X509StoreContext with the full intermediate chain
    so that certs from CAs like Amazon, Google Trust Services, etc.
    validate correctly.

    Args:
        cert_pem: PEM-encoded leaf (server) certificate bytes.
        hostname: The expected hostname (from SNI).
        trust_ctx: Pre-built SSL context with trusted CAs.
        chain_pems: Optional list of PEM-encoded intermediate certificates.

    Returns:
        (is_valid, error_message) — is_valid is True if the cert chains
        to a trusted public CA.
    """
    if trust_ctx is None:
        return True, ""  # Can't verify, assume OK

    from cryptography import x509 as crypto_x509

    def _extract_issuer_cn(cert) -> str:
        for attr in cert.issuer:
            if attr.oid == crypto_x509.oid.NameOID.COMMON_NAME:
                return attr.value
        return ""

    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem)

        # Check if self-signed (issuer == subject)
        if cert.issuer == cert.subject:
            cn = _extract_issuer_cn(cert)
            return False, f"self-signed certificate (issuer: {cn})"

        # Verify the certificate chain using pyOpenSSL's X509Store
        from OpenSSL import crypto as openssl_crypto

        store = openssl_crypto.X509Store()
        try:
            import certifi
            store.load_locations(certifi.where())
        except (ImportError, Exception):
            store.set_default_paths()

        x509_leaf = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem
        )

        # Build list of intermediate certs for chain verification
        intermediates = []
        for pem in (chain_pems or []):
            try:
                intermediates.append(
                    openssl_crypto.load_certificate(
                        openssl_crypto.FILETYPE_PEM, pem
                    )
                )
            except Exception:
                pass

        ctx = openssl_crypto.X509StoreContext(
            store, x509_leaf, intermediates or None
        )
        ctx.verify_certificate()
        return True, ""

    except openssl_crypto.X509StoreContextError as e:
        cn = _extract_issuer_cn(cert)
        return False, f"untrusted certificate (issuer: {cn}, error: {e})"
    except Exception as e:
        return False, f"certificate verification error: {e}"


# ---------------------------------------------------------------------------
# Addon
# ---------------------------------------------------------------------------

class NetworkMonitorAddon:
    """mitmproxy addon that logs and optionally enforces a network policy.

    Configuration is read from environment variables:
        POLICY_FILE — path to the YAML policy file (required)
        MODE        — "monitor" (default) or "enforce"
        LOG_PATH    — path to the JSONL log file
    """

    def __init__(
        self,
        policy_file: str | None = None,
        mode: str | None = None,
        log_path: str | None = None,
    ):
        policy_file = policy_file or os.environ.get("POLICY_FILE", "network-policy.yml")
        mode = mode or os.environ.get("MODE", "monitor")
        self.log_path = log_path or os.environ.get("LOG_PATH", DEFAULT_LOG_PATH)

        try:
            parsed_mode, rules = parse_policy_file(policy_file)
            self.mode = mode if mode else parsed_mode
        except FileNotFoundError:
            logger.info(
                "Policy file not found: %r — running in discovery mode "
                "(monitor all connections, block nothing)",
                policy_file,
            )
            rules = []
            self.mode = mode if mode else "monitor"
        self.engine = PolicyEngine(rules, mode=self.mode)

        # Pre-build the trust store once for cert verification
        self._trust_ctx = _build_trust_store()

        # DNS IP→domain map (populated by dns_server.py)
        self._dns_ip_map: dict[str, str] = {}
        self._dns_map_mtime: float = 0

    def _resolve_host_from_dns(self, ip: str) -> str:
        """Look up a domain name for an IP from the DNS resolver's map."""
        try:
            mtime = os.path.getmtime(DNS_IP_MAP_PATH)
            if mtime > self._dns_map_mtime:
                with open(DNS_IP_MAP_PATH, "r") as f:
                    import json as _json
                    self._dns_ip_map = _json.load(f)
                self._dns_map_mtime = mtime
        except (FileNotFoundError, ValueError, OSError):
            pass
        return self._dns_ip_map.get(ip, "")

    # ------------------------------------------------------------------
    # HTTP / HTTPS interception
    # ------------------------------------------------------------------

    def request(self, flow) -> None:
        """Intercept an HTTP or HTTPS request."""
        req = flow.request
        is_https = req.scheme == "https"

        # In transparent mode, use SNI for the hostname
        sni = ""
        if hasattr(flow, "client_conn") and hasattr(flow.client_conn, "sni"):
            sni = flow.client_conn.sni or ""

        # Use SNI as the host if available and the current host is an IP
        host = req.host
        if sni and is_https and _looks_like_ip(host):
            host = sni

        # If host is still an IP, try the DNS resolver's map
        if _looks_like_ip(host):
            dns_domain = self._resolve_host_from_dns(host)
            if dns_domain:
                host = dns_domain

        entry = ConnectionEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            protocol="https" if is_https else "http",
            host=host,
            port=req.port,
            path=req.path,
            method=req.method,
            tls_sni=sni if is_https else "",
        )

        # Verify server certificate for HTTPS
        if is_https and hasattr(flow, "server_conn"):
            self._check_server_cert(flow.server_conn, sni or host, entry)

        # Record the resolved server IP
        if hasattr(flow, "server_conn") and hasattr(flow.server_conn, "address"):
            addr = flow.server_conn.address
            if addr:
                entry.server_ip = addr[0] if isinstance(addr, tuple) else str(addr)

        status = self.engine.evaluate(entry)
        entry.status = status

        if status == "blocked":
            try:
                flow.response = http.Response.make(
                    403,
                    b"Blocked by network policy",
                    {"Content-Type": "text/plain"},
                )
            except NameError:
                flow.response = _make_blocked_response()

        self._write_log(entry)

    # ------------------------------------------------------------------
    # HTTP / HTTPS response — capture transfer size
    # ------------------------------------------------------------------

    def response(self, flow) -> None:
        """Capture response size after the server replies."""
        resp = flow.response
        if resp is None:
            return

        req = flow.request
        req_bytes = len(req.raw_content) if req and req.raw_content else 0
        resp_bytes = len(resp.raw_content) if resp.raw_content else 0
        total = req_bytes + resp_bytes

        if total > 0:
            is_https = req.scheme == "https"
            sni = ""
            if hasattr(flow, "client_conn") and hasattr(flow.client_conn, "sni"):
                sni = flow.client_conn.sni or ""
            host = req.host
            if sni and is_https and _looks_like_ip(host):
                host = sni
            if _looks_like_ip(host):
                dns_domain = self._resolve_host_from_dns(host)
                if dns_domain:
                    host = dns_domain

            entry = ConnectionEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                protocol="https" if is_https else "http",
                host=host,
                port=req.port,
                path=req.path,
                method=req.method,
                status="data",
                bytes_transferred=total,
                tls_sni=sni if is_https else "",
            )
            self._write_log(entry)

    # ------------------------------------------------------------------
    # Server certificate verification
    # ------------------------------------------------------------------

    def _check_server_cert(self, server_conn, hostname: str,
                           entry: ConnectionEntry) -> None:
        """Verify the upstream server's TLS certificate."""
        try:
            cert_list = getattr(server_conn, "certificate_list", None)
            if not cert_list:
                return

            leaf_cert = cert_list[0]

            # Extract issuer CN
            issuer_cn = ""
            if hasattr(leaf_cert, "issuer"):
                for key, val in leaf_cert.issuer:
                    if key == "CN":
                        issuer_cn = val
                        break
            entry.tls_cert_issuer = issuer_cn

            # Collect intermediate cert PEMs for chain verification
            chain_pems = []
            for c in cert_list[1:]:
                try:
                    chain_pems.append(c.to_pem())
                except Exception:
                    pass

            # Verify against system trust store
            cert_pem = leaf_cert.to_pem()
            is_valid, error = verify_server_cert(
                cert_pem, hostname, self._trust_ctx, chain_pems
            )
            entry.tls_cert_valid = is_valid
            if error:
                entry.tls_cert_error = error

        except Exception as e:
            logger.debug(f"Certificate check failed: {e}")

    # ------------------------------------------------------------------
    # TCP connection logging
    # ------------------------------------------------------------------

    def tcp_message(self, flow) -> None:
        """Log a raw TCP connection message."""
        server_addr = flow.server_conn.address
        message = flow.messages[-1] if flow.messages else None
        bytes_transferred = len(message.content) if message else 0

        host = server_addr[0]
        if _looks_like_ip(host):
            dns_domain = self._resolve_host_from_dns(host)
            if dns_domain:
                host = dns_domain

        entry = ConnectionEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            protocol="tcp",
            host=host,
            port=server_addr[1],
            bytes_transferred=bytes_transferred,
            server_ip=server_addr[0] if host != server_addr[0] else "",
        )

        status = self.engine.evaluate(entry)
        entry.status = status
        self._write_log(entry)

    # ------------------------------------------------------------------
    # JSONL logging
    # ------------------------------------------------------------------

    def _write_log(self, entry: ConnectionEntry) -> None:
        """Append a connection entry as a JSON line to the log file."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(entry.to_dict()) + "\n")
            fcntl.flock(fh, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _looks_like_ip(host: str) -> bool:
    """Return True if host looks like an IP address rather than a domain."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class _BlockedResponse:
    """Minimal stand-in for ``mitmproxy.http.Response`` used in tests."""

    def __init__(self):
        self.status_code = 403
        self.content = b"Blocked by network policy"
        self.headers = {"Content-Type": "text/plain"}


def _make_blocked_response() -> _BlockedResponse:
    return _BlockedResponse()


# ------------------------------------------------------------------
# mitmproxy entry-point
# ------------------------------------------------------------------

# Only instantiate when loaded by mitmproxy (not during test imports).
# Tests create their own addon instances with explicit arguments.
try:
    addons = [NetworkMonitorAddon()]
except (FileNotFoundError, Exception):
    addons = []
