"""Detection of secrets leaving the runner inside request payloads.

PipeWarden already pays for TLS interception — a CA on the runner, cert-pinned
clients breaking, a proxy in the path of every build — but spends it on URL
logging alone. Destination-based enforcement cannot see the case that matters
most: a token POSTed to an *allowlisted* host. A gist, a chat webhook, the
project's own object store, any CI service already in the policy. The request
looks like an ordinary POST and is permitted.

This module reads the payload instead of the destination.

Everything here is pure and offline — no mitmproxy import, no I/O, no clock —
so it can be exercised exhaustively in unit tests, the same way
``policy.matcher`` stays independent of the addon.

Nothing in this module ever returns, logs, or embeds a secret value. See
:class:`Finding` for why that is load-bearing rather than merely tidy.
"""

from __future__ import annotations

import base64
import hmac
import math
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256

# Values shorter than this are ignored no matter what the policy watches.
# CI environments are full of short "secrets" ("1", "true", "prod", a port
# number) whose bytes appear in almost every request. Matching those produces
# constant false positives and trains people to ignore the detector.
MIN_SECRET_LENGTH = 12

# Upper bound on bytes scanned per request. Uploads are routinely far larger
# than anything worth scanning, and an unbounded scan turns the proxy into the
# build's bottleneck. A secret being smuggled past this offset inside an
# otherwise enormous body is a real gap — stated in the docs, not hidden.
DEFAULT_MAX_SCAN_BYTES = 1 << 20  # 1 MiB

# Shannon entropy (bits/char) above which a base64/hex run looks like key
# material rather than prose or an identifier.
ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_RUN = 24

# Well-known credential shapes. Deliberately anchored on issuer-assigned
# prefixes rather than "looks random": these have negligible false-positive
# rates, which is what makes them safe to *block* on.
_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("github-pat", re.compile(rb"\bghp_[A-Za-z0-9]{36,}")),
    ("github-fine-grained-pat", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("github-oauth", re.compile(rb"\bgho_[A-Za-z0-9]{36,}")),
    ("github-app-token", re.compile(rb"\bghs_[A-Za-z0-9]{36,}")),
    ("github-refresh-token", re.compile(rb"\bghr_[A-Za-z0-9]{36,}")),
    ("aws-access-key-id", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(rb"\bAIza[A-Za-z0-9_\-]{35}\b")),
    ("slack-token", re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("npm-token", re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
)

VALID_MODES = ("off", "warn", "block")
VALID_DETECTORS = ("env-secrets", "patterns", "entropy")


@dataclass(frozen=True)
class Finding:
    """One detection. Carries no secret material, by construction.

    ``report.json`` is uploaded as a build artifact, and ``_redact_path`` in
    ``proxy/addon.py`` already strips query strings to keep that artifact
    metadata-only. A detector that recorded what it matched would defeat that
    guarantee and turn PipeWarden into the exfiltration channel it exists to
    stop — the artifact is far easier to read than the traffic was.

    So: ``label`` names the *source* (an env var name, or a pattern class),
    never the value. ``fingerprint`` is keyed with a per-run salt, so identical
    values can be collapsed within one report while remaining useless outside
    it — an unsalted digest of a low-entropy secret is guessable offline.
    """

    detector: str
    label: str
    count: int
    fingerprint: str


@dataclass
class ExfilConfig:
    """Policy configuration for payload scanning (``exfiltration:`` block)."""

    mode: str = "off"
    detectors: list[str] = field(default_factory=lambda: ["env-secrets", "patterns"])
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES
    watch_env: list[str] = field(default_factory=list)
    min_secret_length: int = MIN_SECRET_LENGTH
    # Headers are opt-in. A credential sent to the service it belongs to is
    # authentication, not exfiltration — and headers are where legitimate auth
    # lives. Scanning them by default 403'd every `Authorization: Bearer` to an
    # allowlisted host, i.e. broke ordinary `gh`/`git`/upload-artifact traffic
    # under the documented recommended config.
    scan_headers: bool = False

    def enabled(self) -> bool:
        return self.mode in ("warn", "block")


@dataclass(frozen=True)
class WatchedSecret:
    """A secret value to look for, with the encodings it might travel in."""

    label: str
    variants: tuple[bytes, ...]


def _encodings(value: str) -> tuple[bytes, ...]:
    """Return the forms a secret plausibly takes in a request body.

    Exfiltration rarely puts the raw value on the wire: it lands base64'd in a
    JSON field, percent-encoded in a form post, or hex in a custom protocol.
    Matching only the literal bytes would miss all of those for the cost of one
    ``base64.b64encode`` call, so the cheap variants are covered.
    """
    raw = value.encode("utf-8", errors="ignore")
    variants = {
        raw,
        base64.b64encode(raw),
        base64.b64encode(raw).rstrip(b"="),
        base64.urlsafe_b64encode(raw),
        base64.urlsafe_b64encode(raw).rstrip(b"="),
        urllib.parse.quote(value, safe="").encode("ascii", errors="ignore"),
        raw.hex().encode("ascii"),
    }
    return tuple(sorted((v for v in variants if v), key=len, reverse=True))


def load_watch_values(path: str) -> dict[str, str]:
    """Read the name→value map written by scripts/write_watch_secrets.py.

    The proxy runs under sudo with a stripped environment, so this file is the
    only route by which the job's secrets reach it. A missing or malformed file
    yields an empty map: the caller warns and continues with detection reduced
    rather than taking the proxy — and with it egress control — down.
    """
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def build_watchlist(
    env: Mapping[str, str],
    names: list[str],
    min_length: int = MIN_SECRET_LENGTH,
) -> list[WatchedSecret]:
    """Resolve watched env var *names* into the values to search for.

    Values below *min_length* are dropped — see :data:`MIN_SECRET_LENGTH`.
    Names absent from *env* are skipped silently: a policy that watches a
    secret this particular job was not granted is normal, not an error.
    """
    watchlist: list[WatchedSecret] = []
    for name in names:
        value = env.get(name)
        if not value or len(value) < min_length:
            continue
        watchlist.append(WatchedSecret(label=name, variants=_encodings(value)))
    return watchlist


def _fingerprint(salt: bytes, value: bytes) -> str:
    return hmac.new(salt, value, sha256).hexdigest()[:12]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values()
    )


_TOKENISH = re.compile(rb"[A-Za-z0-9+/=_\-]{%d,}" % ENTROPY_MIN_RUN)


def scan(
    payload: bytes,
    watchlist: list[WatchedSecret],
    cfg: ExfilConfig,
    salt: bytes,
) -> list[Finding]:
    """Scan *payload* for secret material.

    Args:
        payload: Raw request bytes (body, or headers and query joined in).
        watchlist: Values from :func:`build_watchlist`.
        cfg: Which detectors to run and how much to read.
        salt: Per-run random bytes keying the fingerprints. Must not be
            derived from anything in the report, or fingerprints become
            reversible by whoever reads the artifact.

    Returns:
        Findings, ordered by detector confidence: exact matches against the
        job's own secrets first, then known credential shapes, then entropy.
        Callers that block should act on the first two and treat ``entropy``
        as advisory — see :data:`VALID_DETECTORS`.
    """
    if not payload:
        return []

    window = payload[: max(0, cfg.max_scan_bytes)]
    findings: list[Finding] = []

    if "env-secrets" in cfg.detectors:
        for secret in watchlist:
            # Variants overlap: a padded base64 occurrence contains its
            # unpadded form as a substring, so summing per-variant counts
            # reported one leak as 2-4. Longest variants are counted first and
            # blanked out so shorter forms cannot re-match the same bytes.
            work = window
            hits = 0
            for variant in secret.variants:
                found = work.count(variant)
                if found:
                    hits += found
                    work = work.replace(variant, b"\x00")
            if hits:
                findings.append(
                    Finding(
                        detector="env-secrets",
                        label=secret.label,
                        count=hits,
                        fingerprint=_fingerprint(salt, secret.variants[0]),
                    )
                )

    if "patterns" in cfg.detectors:
        for pattern_name, regex in _PATTERNS:
            matches = regex.findall(window)
            if matches:
                findings.append(
                    Finding(
                        detector="patterns",
                        label=pattern_name,
                        count=len(matches),
                        fingerprint=_fingerprint(salt, matches[0]),
                    )
                )

    if "entropy" in cfg.detectors:
        seen: set[bytes] = set()
        for run in _TOKENISH.findall(window):
            if run in seen:
                continue
            seen.add(run)
            if _shannon_entropy(run) >= ENTROPY_THRESHOLD:
                findings.append(
                    Finding(
                        detector="entropy",
                        label=f"high-entropy-{len(run)}b",
                        count=1,
                        fingerprint=_fingerprint(salt, run),
                    )
                )

    return findings


def blocking_findings(findings: list[Finding]) -> list[Finding]:
    """Subset of *findings* strong enough to justify failing a request.

    ``entropy`` is excluded on purpose. It fires on checksums, minified assets,
    cache keys and compressed blobs, so blocking on it would break ordinary
    builds — it earns its place in the report, not in the enforcement path.
    """
    return [f for f in findings if f.detector in ("env-secrets", "patterns")]
