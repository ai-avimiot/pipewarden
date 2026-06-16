"""Tests for wildcard policy hints."""

from scripts.policy_hints import hint_comment_lines, wildcard_hints


def test_groups_siblings():
    hints = wildcard_hints(["registry.npmjs.org", "www.npmjs.org"])
    assert hints == {"npmjs.org": ["registry.npmjs.org", "www.npmjs.org"]}


def test_single_subdomain_no_hint():
    assert wildcard_hints(["registry.npmjs.org"]) == {}


def test_apex_no_hint():
    assert wildcard_hints(["github.com", "example.com"]) == {}


def test_ips_ignored():
    assert wildcard_hints(["10.0.0.1", "10.0.0.2"]) == {}


def test_existing_wildcard_ignored():
    assert wildcard_hints(["*.npmjs.org", "registry.npmjs.org"]) == {}


def test_multitenant_suffixes_suppressed():
    # These must NEVER be suggested as wildcards.
    assert wildcard_hints(["a.s3.amazonaws.com", "b.s3.amazonaws.com"]) == {}
    assert wildcard_hints(["x.cloudfront.net", "y.cloudfront.net"]) == {}
    assert wildcard_hints(["u.blob.core.windows.net", "v.blob.core.windows.net"]) == {}
    assert wildcard_hints(["p.fastly.net", "q.fastly.net"]) == {}


def test_multi_label_public_suffix_suppressed():
    assert wildcard_hints(["foo.co.uk", "bar.co.uk"]) == {}


def test_comment_lines_render():
    lines = hint_comment_lines(["registry.npmjs.org", "www.npmjs.org"])
    assert any("*.npmjs.org" in l for l in lines)
    assert all(l.startswith("#") for l in lines)


def test_no_comment_when_no_hints():
    assert hint_comment_lines(["github.com"]) == []
