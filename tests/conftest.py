"""Shared test fixtures for PipeWarden tests."""

import textwrap

import pytest

from policy.matcher import PolicyEngine
from policy.models import PolicyRule

# ------------------------------------------------------------------
# Policy fixtures
# ------------------------------------------------------------------

SAMPLE_POLICY_YAML = textwrap.dedent("""\
    version: "1"
    mode: enforce

    rules:
      - name: "npm registry"
        allow:
          domains:
            - "registry.npmjs.org"
            - "*.npmjs.org"
          ports: [443]
          protocols: [https]

      - name: "GitHub"
        allow:
          domains:
            - "*.github.com"
            - "*.githubusercontent.com"
          ports: [443]
          protocols: [https]

      - name: "DNS"
        allow:
          domains: ["*"]
          ports: [53]
          protocols: [tcp, udp]
""")


@pytest.fixture
def sample_policy_file(tmp_path):
    """Write the sample policy YAML to a temp file and return its path."""
    policy_path = tmp_path / "network-policy.yml"
    policy_path.write_text(SAMPLE_POLICY_YAML)
    return str(policy_path)


@pytest.fixture
def sample_rules():
    """Return a list of PolicyRule objects matching the sample YAML."""
    return [
        PolicyRule(
            name="npm registry",
            domains=["registry.npmjs.org", "*.npmjs.org"],
            ports=[443],
            protocols=["https"],
        ),
        PolicyRule(
            name="GitHub",
            domains=["*.github.com", "*.githubusercontent.com"],
            ports=[443],
            protocols=["https"],
        ),
        PolicyRule(
            name="DNS",
            domains=["*"],
            ports=[53],
            protocols=["tcp", "udp"],
        ),
    ]


@pytest.fixture
def enforce_engine(sample_rules):
    """PolicyEngine in enforce mode."""
    return PolicyEngine(sample_rules, mode="enforce")


@pytest.fixture
def monitor_engine(sample_rules):
    """PolicyEngine in monitor mode."""
    return PolicyEngine(sample_rules, mode="monitor")


# ------------------------------------------------------------------
# Mock mitmproxy flow objects (avoid importing mitmproxy in tests)
# ------------------------------------------------------------------

class MockRequest:
    """Minimal stand-in for ``mitmproxy.http.HTTPFlow.request``."""

    def __init__(self, scheme="https", host="example.com", port=443,
                 path="/", method="GET", raw_content=b"",
                 content=None, headers=None):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.method = method
        self.raw_content = raw_content
        # mitmproxy exposes the decoded body as .content (gzip/br already
        # undone) and the wire bytes as .raw_content. Payload scanning wants
        # the decoded form — a compressed body would otherwise hide a secret
        # from every detector.
        self.content = raw_content if content is None else content
        self.headers = MockHeaders(headers)


class MockHeaders(dict):
    """Case-insensitive header lookup, as mitmproxy's ``Headers`` provides.

    A plain dict would make ``headers.get("user-agent")`` miss a header the
    client sent as ``User-Agent`` — production code that works would fail here,
    which is the wrong way round for a test double.
    """

    def __init__(self, headers=None):
        super().__init__(headers or {})
        self._lower = {k.lower(): v for k, v in (headers or {}).items()}

    def get(self, key, default=None):
        return self._lower.get(key.lower(), default)

    def __getitem__(self, key):
        return self._lower[key.lower()]

    def __contains__(self, key):
        return key.lower() in self._lower

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._lower[key.lower()] = value


class MockClientConn:
    """Minimal stand-in for ``mitmproxy.connection.Client``."""

    def __init__(self, sni=None, peername=None):
        self.sni = sni
        # (ip, port). The port is the join key attribution uses against the
        # kernel socket table; None mimics a connection mitmproxy has torn down.
        self.peername = peername


class MockCert:
    """Minimal stand-in for ``mitmproxy.certs.Cert``."""

    def __init__(self, cn="example.com", issuer_cn="DigiCert Inc",
                 pem=None, is_self_signed=False):
        self.cn = cn
        self._issuer_cn = issuer_cn
        self._pem = pem or b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        self._is_self_signed = is_self_signed

    @property
    def issuer(self):
        return [("CN", self._issuer_cn)]

    def to_pem(self):
        return self._pem


class MockServerConnWithCert:
    """Server connection mock with certificate_list support."""

    def __init__(self, host="93.184.216.34", port=443, cert=None):
        self.address = (host, port)
        self.certificate_list = [cert] if cert else []


class MockResponse:
    """Minimal stand-in for ``mitmproxy.http.Response``."""

    def __init__(self, status_code=200, raw_content=b""):
        self.status_code = status_code
        self.raw_content = raw_content
        self.headers = {"Content-Type": "text/plain"}


class MockHTTPFlow:
    """Minimal stand-in for ``mitmproxy.http.HTTPFlow``."""

    def __init__(self, request: MockRequest | None = None,
                 client_conn: MockClientConn | None = None,
                 server_conn: MockServerConnWithCert | None = None):
        self.request = request or MockRequest()
        self.response = None
        self.client_conn = client_conn or MockClientConn()
        self.server_conn = server_conn or MockServerConnWithCert()


class MockServerConn:
    """Minimal stand-in for ``mitmproxy.connection.ServerConnection``."""

    def __init__(self, host="10.0.0.1", port=5432):
        self.address = (host, port)


class MockTCPMessage:
    """Minimal stand-in for a TCP message."""

    def __init__(self, content=b"hello"):
        self.content = content


class MockTCPFlow:
    """Minimal stand-in for ``mitmproxy.tcp.TCPFlow``."""

    def __init__(self, server_conn=None, messages=None):
        self.server_conn = server_conn or MockServerConn()
        self.messages = messages or [MockTCPMessage()]


# ------------------------------------------------------------------
# JSONL log helpers
# ------------------------------------------------------------------

@pytest.fixture
def log_file(tmp_path):
    """Return a path to a temporary JSONL log file."""
    return str(tmp_path / "connections.jsonl")
