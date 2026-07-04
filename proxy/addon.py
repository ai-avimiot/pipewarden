"""mitmproxy addon for PipeWarden.

Intercepts HTTP/HTTPS/TCP connections, evaluates them against a network
policy, and writes structured JSONL log entries.

In transparent proxy mode, HTTPS domain names are extracted from the TLS
SNI (Server Name Indication) in the ClientHello. Server certificates are
verified against the system trust store to detect rogue/private certs.
"""

import fcntl
import ipaddress
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

from policy.matcher import PolicyEngine  # noqa: E402
from policy.models import ConnectionEntry  # noqa: E402
from policy.parser import parse_policy_file  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "/var/log/connections.jsonl"
DNS_IP_MAP_PATH = "/var/log/dns_ip_map.json"


# ---------------------------------------------------------------------------
# Certificate verification helper
# ---------------------------------------------------------------------------

_x509_store = None


def _get_x509_store():
    """Return a process-wide pyOpenSSL X509Store, built on first use.

    Loading the certifi CA bundle parses ~150 certificates from disk;
    doing that once instead of per HTTPS request matters on busy
    pipelines. The store is only read during verification, so reuse
    across X509StoreContext instances is safe.
    """
    global _x509_store
    if _x509_store is None:
        from OpenSSL import crypto as openssl_crypto
        store = openssl_crypto.X509Store()
        try:
            import certifi
            store.load_locations(certifi.where())
        except ImportError:
            store.set_default_paths()
        _x509_store = store
    return _x509_store


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


def _cert_dns_names(cert) -> list[str]:
    """Return the DNS names a certificate is valid for.

    Prefers the SubjectAlternativeName dNSName entries (the authoritative
    source per RFC 6125); falls back to the subject CommonName only when no
    SAN is present.
    """
    from cryptography import x509 as crypto_x509

    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(
            crypto_x509.SubjectAlternativeName
        )
        names.extend(san.value.get_values_for_type(crypto_x509.DNSName))
    except crypto_x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    if not names:
        for attr in cert.subject:
            if attr.oid == crypto_x509.oid.NameOID.COMMON_NAME:
                names.append(attr.value)
    return names


def _hostname_matches_cert_names(hostname: str, names: list[str]) -> bool:
    """Check a hostname against a certificate's DNS names (RFC 6125).

    Matching is case-insensitive. A leading ``*.`` wildcard matches exactly
    one left-most label (``*.example.com`` matches ``a.example.com`` but not
    ``example.com`` or ``a.b.example.com``).
    """
    host = hostname.lower().rstrip(".")
    if not host:
        return False
    for name in names:
        name = name.lower().rstrip(".")
        if not name:
            continue
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            first_dot = host.find(".")
            if first_dot > 0 and host[first_dot:] == suffix:
                return True
        elif host == name:
            return True
    return False


def verify_server_cert(cert_pem: bytes, hostname: str,
                       trust_ctx: ssl.SSLContext | None,
                       chain_pems: list[bytes] | None = None,
                       ) -> tuple[bool | None, str]:
    """Verify a server certificate against the system trust store.

    Uses pyOpenSSL's X509StoreContext with the full intermediate chain
    so that certs from CAs like Amazon, Google Trust Services, etc.
    validate correctly, then checks the certificate was actually issued for
    ``hostname`` (SAN/CN match). The hostname check is what makes the result
    meaningful for policy attribution: without it, a valid certificate for an
    attacker-controlled domain would "pass" even when the client spoofed the
    SNI of an allowlisted host.

    Args:
        cert_pem: PEM-encoded leaf (server) certificate bytes.
        hostname: The expected hostname (from SNI).
        trust_ctx: Pre-built SSL context with trusted CAs.
        chain_pems: Optional list of PEM-encoded intermediate certificates.

    Returns:
        (status, error_message) where status is:
          True  — chains to a trusted public CA and is valid for hostname
          False — definitively invalid (self-signed, untrusted chain, or
                  issued for a different host): a MITM/impersonation signal
          None  — could not be verified (no trust store, parse/verify error);
                  callers must treat this as "unknown", never as trusted.
    """
    if trust_ctx is None:
        return None, "trust store unavailable — certificate not verified"

    from cryptography import x509 as crypto_x509

    def _extract_issuer_cn(cert) -> str:
        for attr in cert.issuer:
            if attr.oid == crypto_x509.oid.NameOID.COMMON_NAME:
                return attr.value
        return ""

    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return None, f"certificate parse error: {e}"

    # Check if self-signed (issuer == subject)
    if cert.issuer == cert.subject:
        cn = _extract_issuer_cn(cert)
        return False, f"self-signed certificate (issuer: {cn})"

    from OpenSSL import crypto as openssl_crypto

    # Verify the certificate chain using the shared pyOpenSSL X509Store
    try:
        store = _get_x509_store()

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
    except openssl_crypto.X509StoreContextError as e:
        cn = _extract_issuer_cn(cert)
        return False, f"untrusted certificate (issuer: {cn}, error: {e})"
    except Exception as e:
        return None, f"certificate verification error: {e}"

    # Chain is trusted — now confirm the cert was issued for this host, so a
    # spoofed SNI can't borrow an allowlisted domain's identity.
    if hostname:
        names = _cert_dns_names(cert)
        if names and not _hostname_matches_cert_names(hostname, names):
            shown = ", ".join(names[:5])
            return False, f"certificate not valid for {hostname} (cert names: {shown})"

    return True, ""


# ---------------------------------------------------------------------------
# Addon
# ---------------------------------------------------------------------------

class NetworkMonitorAddon:
    """mitmproxy addon that logs and optionally enforces a network policy.

    Configuration is read from environment variables:
        POLICY_FILE — path to the YAML policy file (required)
        MODE        — "monitor" or "enforce"
        LOG_PATH    — path to the JSONL log file

    Mode precedence: constructor argument, then the MODE environment
    variable, then the policy file's own ``mode:`` field, then "monitor".

    An invalid (unparseable) policy file fails closed: the addon runs with
    an empty allowlist and, once mitmproxy is serving, shuts the proxy down
    via the ``running`` hook so the CI run fails visibly instead of
    silently proxying unfiltered traffic.
    """

    def __init__(
        self,
        policy_file: str | None = None,
        mode: str | None = None,
        log_path: str | None = None,
    ):
        policy_file = policy_file or os.environ.get("POLICY_FILE", "network-policy.yml")
        env_mode = os.environ.get("MODE", "")
        self.log_path = log_path or os.environ.get("LOG_PATH", DEFAULT_LOG_PATH)

        self.init_error: str | None = None
        parsed_mode = ""
        try:
            parsed_mode, rules = parse_policy_file(policy_file)
        except FileNotFoundError:
            logger.info(
                "Policy file not found: %r — running in discovery mode "
                "(monitor all connections, block nothing)",
                policy_file,
            )
            rules = []
        except ValueError as exc:
            # Fail closed: an empty allowlist blocks everything in enforce
            # mode, and running() shuts the proxy down so the error surfaces.
            self.init_error = f"invalid policy file {policy_file!r}: {exc}"
            logger.critical("%s", self.init_error)
            rules = []
        self.mode = mode or env_mode or parsed_mode or "monitor"
        self.engine = PolicyEngine(rules, mode=self.mode)

        # Pre-build the trust store once for cert verification
        self._trust_ctx = _build_trust_store()
        if self._trust_ctx is None:
            logger.warning(
                "TLS trust store unavailable — upstream certificate "
                "verification is disabled; certificate-based enforcement "
                "(blocking spoofed-SNI / MITM certs) will not trigger."
            )

        # DNS IP→domain map (populated by dns_server.py)
        self._dns_ip_map: dict[str, str] = {}
        self._dns_map_mtime: float = 0

        # Cache of definitive cert-verification verdicts keyed by
        # (leaf PEM, hostname, chain PEMs): pipelines hammer the same few
        # hosts, and chain verification costs milliseconds per request.
        # None ("could not verify") results are never cached so transient
        # errors don't stick.
        self._cert_verify_cache: dict[tuple, tuple[bool, str]] = {}
        self._log_dir_ready = False

    def _resolve_host_from_dns(self, ip: str) -> str:
        """Look up a domain name for an IP from the DNS resolver's map."""
        try:
            mtime = os.path.getmtime(DNS_IP_MAP_PATH)
            if mtime > self._dns_map_mtime:
                with open(DNS_IP_MAP_PATH, "r") as f:
                    self._dns_ip_map = json.load(f)
                self._dns_map_mtime = mtime
        except (FileNotFoundError, ValueError, OSError):
            pass
        return self._dns_ip_map.get(ip, "")

    # ------------------------------------------------------------------
    # mitmproxy lifecycle
    # ------------------------------------------------------------------

    def running(self) -> None:
        """mitmproxy hook: refuse to serve if the policy failed to load.

        mitmproxy keeps proxying (unfiltered) when an addon errors, so a
        broken policy must actively shut the proxy down to fail closed.
        Until this hook fires, the empty allowlist set in __init__ blocks
        all traffic in enforce mode.
        """
        if not self.init_error:
            return
        logger.critical(
            "Shutting down proxy: %s — fix the policy file and re-run.",
            self.init_error,
        )
        try:
            from mitmproxy import ctx
            ctx.master.shutdown()
        except Exception:
            # Not running under mitmproxy (e.g. direct instantiation in
            # tests) — nothing to shut down.
            pass

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

        # Certificate-based enforcement: in enforce mode, a connection the
        # policy would allow but whose upstream cert is *definitively* invalid
        # (self-signed, untrusted chain, or not issued for this SNI host) is a
        # TLS impersonation / SNI-spoofing signal. Block it so a forged SNI
        # can't borrow an allowlisted domain's identity. Monitor mode only
        # records the finding (tls_cert_valid=False) and never blocks.
        if (
            status == "allowed"
            and is_https
            and self.mode == "enforce"
            and entry.tls_cert_valid is False
        ):
            status = "blocked"
            reason = entry.tls_cert_error or "invalid TLS certificate"
            logger.warning(
                "Blocking %s:%s — allowed by policy but %s",
                host, req.port, reason,
            )

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

            # Verify against system trust store (cached per cert+hostname)
            cert_pem = leaf_cert.to_pem()
            cache_key = (cert_pem, hostname, tuple(chain_pems))
            cached = self._cert_verify_cache.get(cache_key)
            if cached is not None:
                is_valid, error = cached
            else:
                is_valid, error = verify_server_cert(
                    cert_pem, hostname, self._trust_ctx, chain_pems
                )
                if is_valid is not None:
                    if len(self._cert_verify_cache) >= 512:
                        self._cert_verify_cache.clear()
                    self._cert_verify_cache[cache_key] = (is_valid, error)
            # Only flag tls_cert_valid=False on a definitive failure. A None
            # result means "could not verify" — leave the default so we don't
            # falsely claim invalidity (and don't trigger enforce blocking).
            if is_valid is False:
                entry.tls_cert_valid = False
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
        if not self._log_dir_ready:
            log_dir = os.path.dirname(self.log_path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            self._log_dir_ready = True
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(entry.to_dict()) + "\n")
            fcntl.flock(fh, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _looks_like_ip(host: str) -> bool:
    """Return True if host looks like an IP address rather than a domain."""
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

# __init__ never raises for policy problems: a missing policy file means
# discovery mode, and an invalid one stores init_error so the running()
# hook shuts the proxy down (fail closed). Swallowing errors here would
# leave mitmproxy serving with no addon at all — unfiltered traffic.
addons = [NetworkMonitorAddon()]
