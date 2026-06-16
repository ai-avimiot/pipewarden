"""Tests for the fail-fast watcher detection logic."""

import json

from scripts.fail_fast_watcher import first_blocked


def _line(**kw):
    return json.dumps(kw)


def test_detects_blocked():
    lines = [
        _line(host="registry.npmjs.org", status="allowed"),
        _line(host="evil.example", port=443, status="blocked"),
    ]
    rec = first_blocked(lines)
    assert rec is not None and rec["host"] == "evil.example"


def test_returns_first_blocked_only():
    lines = [
        _line(host="a", status="blocked"),
        _line(host="b", status="blocked"),
    ]
    assert first_blocked(lines)["host"] == "a"


def test_ignores_allowed_and_would_block():
    # would_block is monitor-mode only; fail-fast acts on enforce 'blocked'.
    lines = [
        _line(host="a", status="allowed"),
        _line(host="b", status="would_block"),
    ]
    assert first_blocked(lines) is None


def test_ignores_blank_and_malformed():
    assert first_blocked(["", "   ", "not json", "{bad}"]) is None


def test_empty():
    assert first_blocked([]) is None
