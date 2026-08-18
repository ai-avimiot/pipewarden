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

from policy.attribution import (  # noqa: E402
    Attribution,
    AttributionConfig,
    attribution_from_user_agent,
    better,
)
from policy.exfil import (  # noqa: E402
    ExfilConfig,
    WatchedSecret,
    blocking_findings,
    build_watchlist,
    load_watch_values,
    scan,
)
from policy.matcher import PolicyEngine  # noqa: E402
from policy.models import ConnectionEntry  # noqa: E402
from policy.parser import parse_policy_file, parse_policy_file_full  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "/var/log/connections.jsonl"
DNS_IP_MAP_PATH = "/var/log/dns_ip_map.json"

# One entry per client TCP connection, not per request: keep-alive means a
# single npm install is dozens of requests over a handful of sockets, and the
# helper lookup walks /proc.
_ATTRIBUTION_CACHE_SIZE = 512


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
        # setup.sh exports POLICY_FILE="" in discovery mode, so the key exists
        # and a two-arg os.environ.get returns "" rather than the default —
        # and Path("") is Path("."), which read_text()s as IsADirectoryError.
        policy_file = policy_file or os.environ.get("POLICY_FILE") or "network-policy.yml"
        env_mode = os.environ.get("MODE", "")
        self.log_path = log_path or os.environ.get("LOG_PATH", DEFAULT_LOG_PATH)

        self.init_error: str | None = None
        parsed_mode = ""
        # Salt for exfil finding fingerprints. Random per run and never
        # written anywhere, so fingerprints collapse repeats inside one report
        # while remaining useless to whoever reads the uploaded artifact.
        self._exfil_salt = os.urandom(32)
        self.exfil_cfg = ExfilConfig()
        self.exfil_watchlist: list[WatchedSecret] = []
        try:
            parsed_mode, rules = parse_policy_file(policy_file)
        except FileNotFoundError:
            logger.info(
                "Policy file not found: %r — running in discovery mode "
                "(monitor all connections, block nothing)",
                policy_file,
            )
            rules = []
        except (OSError, ValueError) as exc:
            # Fail closed: an empty allowlist blocks everything in enforce
            # mode, and running() shuts the proxy down so the error surfaces.
            # OSError covers a path that resolves but cannot be read (a
            # directory, bad permissions). That is not the same as "no policy
            # committed" — the caller asked for a policy, so degrading to
            # discovery here would silently drop enforcement.
            self.init_error = f"invalid policy file {policy_file!r}: {exc}"
            logger.critical("%s", self.init_error)
            rules = []
        self.mode = mode or env_mode or parsed_mode or "monitor"
        self.engine = PolicyEngine(rules, mode=self.mode)

        # Payload scanning is configured by the same policy file, but read
        # separately: parse_policy_file returns (mode, rules) and a large body
        # of callers unpack exactly that. A failure here must not take the
        # proxy down — losing egress control because a detector could not be
        # configured would be a strictly worse outcome than losing the
        # detector, so this degrades to "scanning off" and says so loudly.
        try:
            self.exfil_cfg = parse_policy_file_full(policy_file).exfil
        except (FileNotFoundError, OSError, ValueError) as exc:
            if self.init_error is None:
                logger.warning(
                    "Payload scanning disabled — could not read exfiltration "
                    "config from %r: %s",
                    policy_file,
                    exc,
                )
        if self.exfil_cfg.enabled():
            # In transparent mode the proxy is launched via `sudo -u
            # pipewardenuser env POLICY_FILE=... MODE=... LOG_PATH=...`, so
            # os.environ holds those three and nothing else — none of the
            # job's secrets. setup.sh materialises them into a 0600 file for
            # exactly this reason; os.environ is the fallback for the
            # non-transparent path, where the proxy inherits the job's env.
            secrets_file = os.environ.get("EXFIL_SECRETS_FILE", "")
            values: dict[str, str] | os._Environ[str] = (
                load_watch_values(secrets_file) if secrets_file else os.environ
            )
            self.exfil_watchlist = build_watchlist(
                values,
                self.exfil_cfg.watch_env,
                self.exfil_cfg.min_secret_length,
            )
            logger.info(
                "Payload scanning: mode=%s detectors=%s watching %d/%d secrets",
                self.exfil_cfg.mode,
                ",".join(self.exfil_cfg.detectors),
                len(self.exfil_watchlist),
                len(self.exfil_cfg.watch_env),
            )
            missing = len(self.exfil_cfg.watch_env) - len(self.exfil_watchlist)
            if missing > 0:
                # Naming which ones would be unhelpful noise for secrets this
                # job legitimately lacks, but a silent count of zero would hide
                # a policy that watches nothing at all.
                logger.warning(
                    "%d watched secret(s) were absent from the environment or "
                    "shorter than min_secret_length and will not be detected.",
                    missing,
                )

        # Attribution. Configured from the environment rather than from the
        # policy file: it decides whether a privileged helper runs on the
        # runner, not what traffic is permitted — the same class of decision as
        # dns: or tls-intercept:, both of which are action inputs too.
        self.attribution_cfg = AttributionConfig(
            mode=os.environ.get("ATTRIBUTION_MODE", "client") or "client",
        )
        self._attribution_socket = os.environ.get("ATTRIBUTION_SOCKET", "")
        self._attribution_cache: dict[int, dict] = {}
        self._attribution_failures = 0
        if self.attribution_cfg.wants_process() and not self._attribution_socket:
            logger.warning(
                "Process attribution was requested but no helper socket was "
                "provided — recording the self-reported client only."
            )
            self.attribution_cfg.mode = "client"

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
            path=_redact_path(req.path),
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

        entry.attribution = self._attribute(flow, req, entry)

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

        # Payload scanning. Runs even when the destination is allowed — that is
        # the entire point: a token POSTed to an allowlisted host is an
        # ordinary POST to the policy, and the destination check has already
        # said yes. Skipped for connections already blocked, where the request
        # never reaches the network anyway.
        if status != "blocked" and self.exfil_cfg.enabled():
            findings = self._scan_request(req, entry)
            if findings and self.exfil_cfg.mode == "block" and self.mode == "enforce":
                status = "blocked"
                labels = ", ".join(sorted({f.label for f in findings}))
                logger.warning(
                    "Blocking %s:%s — request carries secret material (%s)",
                    host, req.port, labels,
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

    def _attribute(self, flow, req, entry: ConnectionEntry) -> dict:
        """Work out who sent this request.

        The ``User-Agent`` costs nothing and is only readable because the TLS
        session terminates here — a tool that watches packets cannot see it.
        It identifies tools rather than adversaries, since a client that lies is
        believed, so ``process`` mode additionally asks the root helper which
        process owns the client socket. Both are best-effort: attribution is
        reporting, and a failed lookup must never affect whether traffic flows.
        """
        if not self.attribution_cfg.enabled():
            return {}

        result = Attribution()
        try:
            headers = getattr(req, "headers", None)
            if headers is not None:
                result = attribution_from_user_agent(headers.get("user-agent", "") or "")
        except Exception:  # noqa: BLE001 - header containers vary across versions
            pass

        if self.attribution_cfg.wants_process():
            src_port = _client_port(flow)
            cached = self._attribution_cache.get(src_port) if src_port else None
            if cached is None:
                cached = self._ask_helper(src_port, entry)
                if src_port:
                    if len(self._attribution_cache) >= _ATTRIBUTION_CACHE_SIZE:
                        self._attribution_cache.clear()
                    self._attribution_cache[src_port] = cached
            if cached:
                result = better(result, Attribution.from_dict(cached))

        return result.to_dict()

    def _ask_helper(self, src_port: int, entry: ConnectionEntry) -> dict:
        """Query the privileged helper, giving up quietly once it stops answering.

        A helper that died mid-job would otherwise cost a connect attempt on
        every request for the rest of the run. Attribution is worth a socket
        round trip; it is not worth slowing the pipeline down indefinitely.
        """
        if self._attribution_failures >= 5:
            return {}
        try:
            from scripts.attribution_helper import query
        except ImportError:
            self._attribution_failures = 99
            return {}
        answer = query(
            self._attribution_socket,
            {
                "src_port": src_port,
                "dst_ip": entry.server_ip or entry.host,
                "dst_port": entry.port,
            },
        )
        # None is "could not reach the helper"; {} is "the helper does not
        # know", which is routine for a client that exited before the lookup
        # and must not count against it.
        if answer is None:
            self._attribution_failures += 1
            if self._attribution_failures == 5:
                logger.warning(
                    "Attribution helper stopped answering — recording the "
                    "self-reported client only for the rest of this run."
                )
            return {}
        self._attribution_failures = 0
        return answer

    def _scan_request(self, req, entry) -> list:
        """Scan a request for secret material and record findings on *entry*.

        Returns the findings that justify blocking (see
        ``exfil.blocking_findings``); advisory ones are still recorded on the
        entry so they reach the report.
        """
        if self.engine.allows_request_body(entry):
            return []

        try:
            payload = _request_payload(
                req, self.exfil_cfg.max_scan_bytes, self.exfil_cfg.scan_headers
            )
        except Exception as exc:  # noqa: BLE001 - never break a request to scan it
            logger.debug("Skipping payload scan for %s: %s", entry.host, exc)
            return []

        findings = scan(
            payload, self.exfil_watchlist, self.exfil_cfg, self._exfil_salt
        )
        if not findings:
            return []

        entry.exfil_findings = [
            {
                "detector": f.detector,
                "label": f.label,
                "count": f.count,
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ]
        return blocking_findings(findings)

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
                path=_redact_path(req.path),
                method=req.method,
                status="data",
                bytes_transferred=total,
                tls_sni=sni if is_https else "",
            )
            # Cheap: the client socket is the same one request() already
            # resolved, so this reads the cache rather than walking /proc again.
            entry.attribution = self._attribute(flow, req, entry)
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

        # No User-Agent on a raw TCP stream, so this is process-mode only —
        # and it is where process attribution earns its keep, since nothing
        # else in the entry says what made the connection.
        entry.attribution = self._attribute(flow, None, entry)

        status = self.engine.evaluate(entry)
        entry.status = status
        self._write_log(entry)

    # ------------------------------------------------------------------
    # JSONL logging
    # ------------------------------------------------------------------

    def tls_failed_client(self, data) -> None:
        """A client refused the certificate PipeWarden presented for a host.

        This is the signature of certificate pinning: the client validates the
        real site's key and rejects our per-job forged leaf, exactly as pinning
        is designed to. It fires at the TLS layer, before any HTTP request or
        status exists, so it is the earliest and clearest place to recognise
        "this client cannot be intercepted" — and to tell the user what to do
        about it rather than leaving them with an opaque handshake error in
        their own build step.

        Recorded as a distinct status so teardown can surface a hint. Never
        fatal here: whether a pinned connection should fail the job is a policy
        question for enforce mode, not something to decide at the TLS callback.
        """
        try:
            sni = ""
            conn = getattr(data, "conn", None) or getattr(data, "client", None)
            if conn is not None:
                sni = getattr(conn, "sni", "") or ""
            context = getattr(data, "context", None)
            server = getattr(context, "server", None) if context else None
            host = sni or (getattr(server, "address", ("", 0))[0] if server else "")
            if not host:
                return
            entry = ConnectionEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                protocol="https",
                host=host,
                port=443,
                status="tls_pinned",
                tls_sni=sni,
            )
            self._write_log(entry)
            logger.warning(
                "TLS handshake refused by client for %s — looks like certificate "
                "pinning. That client cannot be MITM-intercepted; exclude it with "
                "tls-passthrough, or run the action with tls-intercept: false.",
                host,
            )
        except Exception as exc:  # noqa: BLE001 - a diagnostic must never crash the proxy
            logger.debug("tls_failed_client handler error: %s", exc)

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

def _client_port(flow) -> int:
    """The client's source port, which is the join key for a /proc lookup.

    In transparent mode the redirect happens below the socket layer, so the
    client's socket still carries its own ephemeral source port and the
    original destination — meaning the kernel's socket table can be searched
    for it directly.
    """
    try:
        peer = getattr(flow.client_conn, "peername", None)
        if isinstance(peer, tuple) and len(peer) >= 2:
            return int(peer[1])
    except Exception:  # noqa: BLE001 - connection shapes vary across versions
        pass
    return 0


def _looks_like_ip(host: str) -> bool:
    """Return True if host looks like an IP address rather than a domain."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _request_payload(req, max_bytes: int, scan_headers: bool = False) -> bytes:
    """Assemble the bytes worth scanning from a request.

    Query string and body by default; headers only when *scan_headers* is set.
    Headers are where legitimate authentication lives — an ``Authorization:
    Bearer`` to the very host the credential belongs to is not exfiltration,
    and scanning headers by default 403'd every authenticated request to an
    allowlisted host. The query string is different: ``_redact_path`` strips it
    before logging, so this is the only place it can still be examined.

    Ordering matters: headers go last so that, when enabled, a large cookie
    jar cannot push the body past the scan window — the scanner truncates the
    joined payload to ``max_bytes``, and the body is the carrier that matters.

    ``req.content`` is bounded here rather than in the caller because reading
    it is what materialises the body; slicing afterwards would already have
    paid the cost.
    """
    parts: list[bytes] = []

    path = getattr(req, "path", "") or ""
    if "?" in path:
        parts.append(path.split("?", 1)[1].encode("utf-8", errors="ignore"))

    # A streamed request has no materialised content; mitmproxy raises rather
    # than block, and a scan is not worth stalling the flow for.
    content = getattr(req, "content", None)
    if content:
        parts.append(content[:max_bytes])

    if scan_headers:
        headers = getattr(req, "headers", None)
        if headers is not None:
            try:
                for name, value in headers.items():
                    parts.append(f"{name}: {value}".encode(errors="ignore"))
            except Exception:  # noqa: BLE001 - header containers vary across versions
                pass

    return b"\n".join(p for p in parts if p)


def _redact_path(path: str) -> str:
    """Strip the query string from a request path before it is logged.

    mitmproxy decrypts HTTPS, so ``req.path`` carries the full query string —
    which routinely holds credentials (presigned-URL signatures like
    ``?X-Amz-Signature=``, ``?access_token=``, ``?api_key=``, SAS tokens). Those
    would otherwise land verbatim in report.json, which is uploaded as a build
    artifact, contradicting the metadata-only guarantee. The path itself is kept
    (policy path-matching runs on it) with a marker so a stripped query is still
    visible as a fact. Fragments never reach the server, but are dropped too.
    """
    if not path:
        return path
    base = path.split("?", 1)[0].split("#", 1)[0]
    return base + "?<redacted>" if "?" in path else base


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
