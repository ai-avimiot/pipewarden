"""Tests for payload scanning (policy/exfil.py).

The leak tests in TestNeverLeaksSecrets are the important ones. Everything else
here is ordinary detector coverage; those assert the property that makes the
feature safe to ship at all — findings travel into report.json, which is
uploaded as a build artifact, so a detector that recorded what it matched would
publish the secret more conveniently than the exfiltration attempt did.
"""

import base64
import json
import urllib.parse

import pytest
from hypothesis import given
from hypothesis import strategies as st

from policy.exfil import (
    ExfilConfig,
    Finding,
    blocking_findings,
    build_watchlist,
    scan,
)

SALT = b"test-salt-not-a-real-run-salt"
TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _cfg(**kw) -> ExfilConfig:
    kw.setdefault("mode", "block")
    kw.setdefault("detectors", ["env-secrets", "patterns"])
    return ExfilConfig(**kw)


class TestBuildWatchlist:
    def test_resolves_named_env_vars(self):
        wl = build_watchlist({"MY_TOKEN": "s" * 20}, ["MY_TOKEN"])
        assert [w.label for w in wl] == ["MY_TOKEN"]

    def test_skips_absent_names(self):
        """A job not granted a watched secret is normal, not an error."""
        assert build_watchlist({}, ["NOT_GRANTED"]) == []

    def test_skips_short_values(self):
        """CI is full of short 'secrets' whose bytes appear in every request."""
        assert build_watchlist({"CI": "true", "PORT": "8080"}, ["CI", "PORT"]) == []

    def test_includes_encoded_variants(self):
        wl = build_watchlist({"T": "supersecretvalue123"}, ["T"])
        variants = wl[0].variants
        assert b"supersecretvalue123" in variants
        assert base64.b64encode(b"supersecretvalue123") in variants


class TestEnvSecretDetector:
    def test_detects_raw_value(self):
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        found = scan(b'{"data":"supersecretvalue123"}', wl, _cfg(), SALT)
        assert [f.label for f in found] == ["TOKEN"]
        assert found[0].detector == "env-secrets"

    @pytest.mark.parametrize(
        "encode",
        [
            lambda v: base64.b64encode(v.encode()),
            lambda v: base64.b64encode(v.encode()).rstrip(b"="),
            lambda v: base64.urlsafe_b64encode(v.encode()),
            lambda v: urllib.parse.quote(v, safe="").encode(),
            lambda v: v.encode().hex().encode(),
        ],
        ids=["b64", "b64-unpadded", "b64-urlsafe", "percent", "hex"],
    )
    def test_detects_encoded_value(self, encode):
        """Exfiltration rarely puts the raw value on the wire."""
        secret = "supersecret/value+123"
        wl = build_watchlist({"TOKEN": secret}, ["TOKEN"])
        found = scan(b"payload=" + encode(secret), wl, _cfg(), SALT)
        assert [f.label for f in found] == ["TOKEN"]

    def test_counts_repeats(self):
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        found = scan(b"supersecretvalue123 supersecretvalue123", wl, _cfg(), SALT)
        assert found[0].count >= 2

    def test_clean_payload_yields_nothing(self):
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        assert scan(b'{"ok":true}', wl, _cfg(), SALT) == []

    def test_respects_max_scan_bytes(self):
        """A documented gap: a secret past the scan window is not seen."""
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        payload = b"x" * 100 + b"supersecretvalue123"
        assert scan(payload, wl, _cfg(max_scan_bytes=50), SALT) == []
        assert scan(payload, wl, _cfg(max_scan_bytes=10_000), SALT) != []


class TestPatternDetector:
    @pytest.mark.parametrize(
        ("label", "sample"),
        [
            ("github-pat", TOKEN),
            ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
            ("google-api-key", "AIza" + "B" * 35),
            ("slack-token", "xoxb-1234567890-abcdefghij"),
            ("private-key", "-----BEGIN RSA PRIVATE KEY-----"),
        ],
    )
    def test_detects_known_shapes(self, label, sample):
        found = scan(sample.encode(), [], _cfg(), SALT)
        assert label in [f.label for f in found]

    def test_ordinary_json_is_clean(self):
        payload = json.dumps(
            {"name": "pipewarden", "version": "1.4.1", "ok": True}
        ).encode()
        assert scan(payload, [], _cfg(), SALT) == []


class TestEntropyDetector:
    def test_flags_high_entropy_run(self):
        blob = base64.b64encode(bytes(range(64)))
        found = scan(blob, [], _cfg(detectors=["entropy"]), SALT)
        assert found and found[0].detector == "entropy"

    def test_entropy_never_blocks(self):
        """Entropy fires on checksums and minified assets; blocking on it
        would break ordinary builds."""
        blob = base64.b64encode(bytes(range(64)))
        found = scan(blob, [], _cfg(detectors=["entropy"]), SALT)
        assert found != []
        assert blocking_findings(found) == []

    def test_prose_is_not_flagged(self):
        text = b"the quick brown fox jumps over the lazy dog " * 4
        assert scan(text, [], _cfg(detectors=["entropy"]), SALT) == []


class TestDetectorSelection:
    def test_disabled_detector_does_not_run(self):
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        found = scan(b"supersecretvalue123", wl, _cfg(detectors=["patterns"]), SALT)
        assert found == []

    def test_empty_payload_short_circuits(self):
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        assert scan(b"", wl, _cfg(), SALT) == []

    def test_blocking_subset_covers_confident_detectors(self):
        findings = [
            Finding("env-secrets", "TOKEN", 1, "abc"),
            Finding("patterns", "github-pat", 1, "def"),
            Finding("entropy", "high-entropy-40b", 1, "ghi"),
        ]
        assert {f.detector for f in blocking_findings(findings)} == {
            "env-secrets",
            "patterns",
        }


class TestNeverLeaksSecrets:
    """The property that makes this feature safe to ship.

    Findings are serialized into connections.jsonl and report.json, which are
    uploaded as build artifacts. If any secret material reached a Finding, the
    detector would publish the credential more conveniently than the
    exfiltration attempt it caught.
    """

    def test_env_secret_value_absent_from_finding(self):
        secret = "supersecretvalue123"
        wl = build_watchlist({"TOKEN": secret}, ["TOKEN"])
        found = scan(f'{{"x":"{secret}"}}'.encode(), wl, _cfg(), SALT)

        blob = json.dumps([f.__dict__ for f in found])
        assert secret not in blob
        assert base64.b64encode(secret.encode()).decode() not in blob
        assert secret.encode().hex() not in blob

    def test_matched_token_value_absent_from_finding(self):
        found = scan(f"token={TOKEN}".encode(), [], _cfg(), SALT)
        blob = json.dumps([f.__dict__ for f in found])
        assert found != []
        assert TOKEN not in blob
        # The label names the *class* of credential, never the credential.
        assert "github-pat" in blob

    def test_fingerprint_is_salted(self):
        """An unsalted digest of a low-entropy secret is guessable offline by
        whoever reads the artifact."""
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        a = scan(b"supersecretvalue123", wl, _cfg(), b"salt-one")
        b = scan(b"supersecretvalue123", wl, _cfg(), b"salt-two")
        assert a[0].fingerprint != b[0].fingerprint

    def test_fingerprint_is_stable_within_a_run(self):
        """Same salt, same value — so a report can collapse repeats."""
        wl = build_watchlist({"TOKEN": "supersecretvalue123"}, ["TOKEN"])
        a = scan(b"supersecretvalue123", wl, _cfg(), SALT)
        b = scan(b"...supersecretvalue123...", wl, _cfg(), SALT)
        assert a[0].fingerprint == b[0].fingerprint

    @given(
        secret=st.text(
            alphabet=st.characters(min_codepoint=33, max_codepoint=126),
            min_size=12,
            max_size=60,
        )
    )
    def test_no_secret_of_any_shape_reaches_a_finding(self, secret):
        wl = build_watchlist({"S": secret}, ["S"])
        if not wl:
            return
        found = scan(secret.encode(), wl, _cfg(), SALT)
        blob = json.dumps([f.__dict__ for f in found])
        assert secret not in blob


class TestCountAccuracy:
    def test_one_occurrence_counts_once_despite_variant_overlap(self):
        """A padded base64 occurrence contains its unpadded form as a
        substring; summing per-variant counts reported one leak as 2-4."""
        secret = "supersecret/value+123"
        wl = build_watchlist({"T": secret}, ["T"])
        found = scan(
            b"x=" + base64.b64encode(secret.encode()), wl, _cfg(), SALT
        )
        assert found[0].count == 1

    def test_raw_occurrence_counts_once(self):
        wl = build_watchlist({"T": "supersecretvalue123"}, ["T"])
        found = scan(b"supersecretvalue123", wl, _cfg(), SALT)
        assert found[0].count == 1
