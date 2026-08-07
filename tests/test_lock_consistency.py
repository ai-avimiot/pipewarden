"""Guard that each lock file actually satisfies its own source requirements.

The locks are consumed with `pip install --require-hashes`, which installs the
pinned versions verbatim. Nothing in CI installs `proxy/requirements-lock.txt`
at all — it is only used by the Docker build — so a pin that contradicts its
declared range goes unnoticed until an image build fails.

That is not hypothetical: Dependabot raised pyopenssl to 26.3.0 in /proxy while
cryptography stayed capped at <49, and pyOpenSSL 26.3.0 requires
cryptography>=49. The resulting lock was unsatisfiable and the proxy image
could not be built. It merged because auto-merge runs under GITHUB_TOKEN, whose
pushes do not trigger build-image.yml, so nothing ever tried.

These checks are offline and cheap: they compare declared specifiers against
pinned versions, no network and no install.
"""

import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent

LOCK_PAIRS = [
    ("proxy/requirements.txt", "proxy/requirements-lock.txt"),
    ("requirements/requirements.txt", "requirements/requirements-lock.txt"),
]

# A lock line pins with `name==version \` before the hash block.
_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;\\]+)", re.MULTILINE)


def _parse_pins(lock_text: str) -> dict[str, str]:
    # Names normalise per PEP 503 so pyOpenSSL and pyopenssl compare equal.
    return {
        name.lower().replace("_", "-"): version
        for name, version in _PIN.findall(lock_text)
    }


def _parse_requirements(source_text: str) -> list[Requirement]:
    reqs = []
    for raw in source_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        reqs.append(Requirement(line))
    return reqs


@pytest.mark.parametrize(("source", "lock"), LOCK_PAIRS)
def test_lock_pins_satisfy_declared_ranges(source: str, lock: str):
    pins = _parse_pins((REPO_ROOT / lock).read_text(encoding="utf-8"))
    assert pins, f"no pins parsed out of {lock}"

    for req in _parse_requirements((REPO_ROOT / source).read_text(encoding="utf-8")):
        key = req.name.lower().replace("_", "-")
        assert key in pins, f"{req.name} is declared in {source} but absent from {lock}"

        pinned = pins[key]
        assert req.specifier.contains(Version(pinned), prereleases=True), (
            f"{lock} pins {req.name}=={pinned}, which violates "
            f"'{req}' in {source}. Regenerate with scripts/update-lock-files.sh."
        )


def test_proxy_and_test_locks_agree_on_shared_pins():
    """The runner installs one lock and the proxy image the other; a shared
    package resolving differently means the two run different code."""
    proxy = _parse_pins((REPO_ROOT / "proxy/requirements-lock.txt").read_text("utf-8"))
    tests = _parse_pins(
        (REPO_ROOT / "requirements/requirements-lock.txt").read_text("utf-8")
    )

    for name in sorted(set(proxy) & set(tests)):
        assert proxy[name] == tests[name], (
            f"{name} is pinned to {proxy[name]} in proxy/requirements-lock.txt "
            f"but {tests[name]} in requirements/requirements-lock.txt"
        )
