"""Guard against the pinned mitmproxy version drifting across its many homes.

The version is hardcoded in eight places that Dependabot cannot keep in lockstep
(shell/JS defaults, a Docker base tag, the bundled dist, and four requirements
files). setup.sh only hash-verifies the install when its default matches the
native lock, so drift there silently turns verification off. A bump that misses one silently ships a different proxy on the runner
than in the container image. This test fails loudly when they disagree so the
bump is caught in CI, not in production.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def _search(pattern: str, text: str, label: str) -> str:
    m = re.search(pattern, text, re.MULTILINE)
    assert m, f"could not find the mitmproxy version in {label}"
    return m.group(1)


def test_mitmproxy_version_is_consistent_everywhere():
    versions = {
        "requirements-lock.txt": _search(
            r"^mitmproxy==([0-9]+\.[0-9]+\.[0-9]+)",
            _read("requirements/requirements-lock.txt"),
            "requirements-lock.txt",
        ),
        "requirements.txt": _search(
            r"mitmproxy>=([0-9]+\.[0-9]+\.[0-9]+)",
            _read("requirements/requirements.txt"),
            "requirements.txt",
        ),
        "native-proxy/requirements.txt": _search(
            r"^mitmproxy==([0-9]+\.[0-9]+\.[0-9]+)",
            _read("native-proxy/requirements.txt"),
            "native-proxy/requirements.txt",
        ),
        "native-proxy/requirements-lock.txt": _search(
            r"^mitmproxy==([0-9]+\.[0-9]+\.[0-9]+)",
            _read("native-proxy/requirements-lock.txt"),
            "native-proxy/requirements-lock.txt",
        ),
        "proxy/Dockerfile": _search(
            r"FROM mitmproxy/mitmproxy:([0-9]+\.[0-9]+\.[0-9]+)",
            _read("proxy/Dockerfile"),
            "proxy/Dockerfile",
        ),
        "native-proxy/setup.sh": _search(
            r'MITMPROXY_VERSION="\$\{INPUT_MITMPROXY_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"',
            _read("native-proxy/setup.sh"),
            "native-proxy/setup.sh",
        ),
        "native-proxy/action/src/main.js": _search(
            r'MITMPROXY_VERSION[\s\S]{0,120}?"([0-9]+\.[0-9]+\.[0-9]+)"',
            _read("native-proxy/action/src/main.js"),
            "native-proxy/action/src/main.js",
        ),
    }

    distinct = set(versions.values())
    assert len(distinct) == 1, (
        "mitmproxy version drifted across pin sites: "
        + ", ".join(f"{k}={v}" for k, v in versions.items())
    )
