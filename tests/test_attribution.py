"""Tests for the attribution core (policy/attribution.py).

The tests in ``TestNeverLeaksSecrets`` are the load-bearing ones. Attribution
strings come from two attacker-influenced places — a ``User-Agent`` header and a
process ``argv`` — and both end up in ``report.json`` and in Markdown rendered
into the job summary. Everything else here is ordinary behaviour coverage.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from policy.attribution import (
    MAX_FIELD_LENGTH,
    Attribution,
    AttributionConfig,
    apply_events,
    attribution_from_user_agent,
    better,
    client_from_user_agent,
    index_events,
    redact_cmdline,
    sanitize,
    summarise,
)
from policy.exfil import WatchedSecret

TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class TestConfig:
    def test_default_is_client(self):
        cfg = AttributionConfig()
        assert cfg.mode == "client"
        assert cfg.enabled()
        assert not cfg.wants_process()

    def test_off_disables_everything(self):
        cfg = AttributionConfig(mode="off")
        assert not cfg.enabled()
        assert not cfg.wants_process()

    def test_process_implies_client(self):
        cfg = AttributionConfig(mode="process")
        assert cfg.enabled()
        assert cfg.wants_process()


class TestUserAgent:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("npm/10.2.4 node/v20.11.0 linux x64 workspaces/false", "npm/10.2.4"),
            ("curl/8.5.0", "curl/8.5.0"),
            ("Mozilla/5.0 (X11; Linux x86_64)", "Mozilla/5.0"),
            ("pip/24.0 {\"ci\":null}", "pip/24.0"),
            ("git/2.43.0", "git/2.43.0"),
            ("", ""),
            ("   ", ""),
            ("(only a comment)", ""),
        ],
    )
    def test_product_token_extracted(self, header, expected):
        assert client_from_user_agent(header) == expected

    def test_stable_across_runners(self):
        """The point of keeping only the product token: two runners agree."""
        a = "npm/10.2.4 node/v20.11.0 linux x64 workspaces/false"
        b = "npm/10.2.4 node/v20.11.0 linux arm64 workspaces/true"
        assert client_from_user_agent(a) == client_from_user_agent(b)

    def test_missing_header_yields_empty_attribution(self):
        assert attribution_from_user_agent("").is_empty()

    def test_present_header_yields_sourced_attribution(self):
        attribution = attribution_from_user_agent("curl/8.5.0")
        assert attribution.source == "user-agent"
        assert attribution.client == "curl/8.5.0"
        assert not attribution.is_empty()


class TestSanitize:
    def test_strips_markup(self):
        assert "<" not in sanitize("<script>alert(1)</script>")
        assert "|" not in sanitize("evil|table|injection")

    def test_strips_newlines(self):
        assert "\n" not in sanitize("first\nsecond")
        assert "\r" not in sanitize("first\r\nsecond")

    def test_truncates(self):
        assert len(sanitize("a" * 500)) == MAX_FIELD_LENGTH

    def test_keeps_ordinary_paths_and_versions(self):
        assert sanitize("/usr/bin/node") == "/usr/bin/node"
        assert sanitize("npm/10.2.4") == "npm/10.2.4"

    def test_keeps_underscores(self):
        """Real script names contain them; stripping would name a missing file."""
        assert sanitize("/home/runner/run_tests.sh") == "/home/runner/run_tests.sh"

    @given(st.text())
    def test_never_produces_markdown_or_html_metacharacters(self, raw):
        cleaned = sanitize(raw)
        # Underscore is deliberately absent: it is legal in filenames, and the
        # Markdown writer wraps these values in a code span anyway.
        for char in "<>|`*[]()\n\r\t{}\\\"'&#!":
            assert char not in cleaned


class TestNeverLeaksSecrets:
    """A recorded command line must not republish a credential.

    This is the same failure mode ``exfil`` fingerprinting exists to avoid: the
    detector itself becoming the most convenient place to read the secret.
    """

    def test_watched_value_removed(self):
        watchlist = [WatchedSecret("MY_TOKEN", (b"s3cr3t-value-here",))]
        out = redact_cmdline("curl -H token:s3cr3t-value-here https://x", watchlist)
        assert "s3cr3t-value-here" not in out
        assert "MY_TOKEN" in out

    def test_generic_pattern_removed_without_watchlist(self):
        """A token nobody added to watch_env is still scrubbed."""
        out = redact_cmdline(f"git push https://{TOKEN}@github.com/o/r")
        assert TOKEN not in out

    def test_authorization_header_removed(self):
        out = redact_cmdline(f"curl -H 'Authorization: Bearer {TOKEN}' https://x")
        assert TOKEN not in out

    def test_empty_stays_empty(self):
        assert redact_cmdline("") == ""

    def test_redactor_never_raises(self):
        """Losing a command line is acceptable; taking down the proxy is not."""
        watchlist = [WatchedSecret("BINARY", (b"\xff\xfe\x00raw",))]
        assert isinstance(redact_cmdline("anything at all", watchlist), str)

    @given(st.text(min_size=8, max_size=40, alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"))))
    def test_any_watched_value_is_removed(self, secret):
        watchlist = [WatchedSecret("W", (secret.encode(),))]
        out = redact_cmdline(f"tool --flag={secret} --other", watchlist)
        assert secret not in out


class TestLabel:
    def test_prefers_exe_basename_over_truncated_comm(self):
        a = Attribution(source="proc", comm="node-gyp-build", exe="/usr/bin/node-gyp-build-x")
        assert a.label() == "node-gyp-build-x"

    def test_falls_back_to_comm(self):
        assert Attribution(source="proc", comm="npm").label() == "npm"

    def test_falls_back_to_client(self):
        assert Attribution(source="user-agent", client="curl/8.5.0").label() == "curl/8.5.0"

    def test_disagreement_is_shown(self):
        """A curl User-Agent from a process that is not curl is the finding."""
        a = Attribution(source="proc", exe="/tmp/postinstall.sh", client="curl/8.5.0")
        assert a.label() == "postinstall.sh (curl/8.5.0)"

    def test_agreement_is_not_duplicated(self):
        a = Attribution(source="proc", exe="/usr/bin/curl", client="curl/8.5.0")
        assert a.label() == "curl"


class TestSerialization:
    def test_empty_fields_are_dropped(self):
        assert Attribution(source="user-agent", client="npm/10").to_dict() == {
            "source": "user-agent",
            "client": "npm/10",
        }

    def test_round_trip(self):
        a = Attribution(source="proc", client="npm/10", pid=42, comm="npm",
                        exe="/usr/bin/npm", ppid=7, pcomm="bash", cmdline="npm ci")
        assert Attribution.from_dict(a.to_dict()) == a

    def test_from_dict_tolerates_missing_and_null(self):
        a = Attribution.from_dict({"source": "audit", "pid": None})
        assert a.source == "audit"
        assert a.pid == 0


class TestBetter:
    def test_proc_beats_audit_beats_user_agent(self):
        ua = Attribution(source="user-agent", client="curl/8")
        audit = Attribution(source="audit", comm="curl")
        proc = Attribution(source="proc", comm="curl", pid=9)
        assert better(ua, audit).source == "audit"
        assert better(audit, proc).source == "proc"
        assert better(proc, ua).source == "proc"

    def test_client_is_merged_into_the_winner(self):
        ua = Attribution(source="user-agent", client="curl/8.5.0")
        proc = Attribution(source="proc", comm="sh", pid=9)
        merged = better(ua, proc)
        assert merged.source == "proc"
        assert merged.client == "curl/8.5.0"
        assert merged.comm == "sh"

    def test_empty_candidate_does_not_erase(self):
        proc = Attribution(source="proc", comm="npm", pid=9)
        assert better(proc, Attribution()) == proc

    def test_none_current_takes_candidate(self):
        c = Attribution(source="audit", comm="npm")
        assert better(None, c) == c


class TestApplyEvents:
    def test_conntrack_row_gains_a_name(self):
        """The tls-intercept:false path: conntrack knows addresses, not processes."""
        conns = [{"host": "1.2.3.4", "port": 443}]
        events = [{"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "curl", "pid": 5}]
        assert apply_events(conns, events) == 1
        assert conns[0]["attribution"]["comm"] == "curl"
        assert conns[0]["attribution"]["source"] == "audit"

    def test_matches_on_server_ip_when_host_is_a_name(self):
        conns = [{"host": "example.com", "port": 443, "server_ip": "1.2.3.4"}]
        events = [{"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "git"}]
        assert apply_events(conns, events) == 1
        assert conns[0]["attribution"]["comm"] == "git"

    def test_existing_attribution_wins(self):
        """A source-port match beat a destination match; do not downgrade it."""
        conns = [{"host": "1.2.3.4", "port": 443,
                  "attribution": {"source": "proc", "comm": "npm"}}]
        events = [{"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "curl"}]
        assert apply_events(conns, events) == 0
        assert conns[0]["attribution"]["comm"] == "npm"

    def test_no_events_is_a_no_op(self):
        conns = [{"host": "1.2.3.4", "port": 443}]
        assert apply_events(conns, []) == 0
        assert "attribution" not in conns[0]

    def test_port_mismatch_does_not_attribute(self):
        conns = [{"host": "1.2.3.4", "port": 80}]
        events = [{"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "curl"}]
        assert apply_events(conns, events) == 0

    def test_later_event_wins_for_the_same_destination(self):
        index = index_events([
            {"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "first"},
            {"dst_ip": "1.2.3.4", "dst_port": 443, "comm": "second"},
        ])
        assert index[("1.2.3.4", 443)].comm == "second"

    def test_events_without_a_destination_are_skipped(self):
        assert index_events([{"comm": "curl"}, {"dst_ip": "", "dst_port": 443}]) == {}


class TestSummarise:
    def test_counts_and_deduplicates_destinations(self):
        conns = [
            {"host": "a.com", "port": 443, "attribution": {"source": "proc", "comm": "npm"}},
            {"host": "a.com", "port": 443, "attribution": {"source": "proc", "comm": "npm"}},
            {"host": "b.com", "port": 443, "attribution": {"source": "proc", "comm": "npm"}},
        ]
        out = summarise(conns)
        assert out["attributed_connections"] == 3
        assert out["unattributed_connections"] == 0
        assert out["actors"][0]["connections"] == 3
        assert sorted(out["actors"][0]["destinations"]) == ["a.com:443", "b.com:443"]

    def test_unattributed_are_counted_not_hidden(self):
        conns = [
            {"host": "a.com", "port": 443, "attribution": {"source": "proc", "comm": "npm"}},
            {"host": "b.com", "port": 443},
        ]
        out = summarise(conns)
        assert out["attributed_connections"] == 1
        assert out["unattributed_connections"] == 1

    def test_actor_with_findings_is_promoted_above_a_noisier_one(self):
        conns = [
            {"host": "a.com", "port": 443, "attribution": {"comm": "npm"}} for _ in range(10)
        ] + [
            {"host": "evil.com", "port": 443, "exfil_findings": [{"detector": "x"}],
             "attribution": {"comm": "postinstall"}}
        ]
        out = summarise(conns)
        assert out["actors"][0]["actor"] == "postinstall"
        assert out["actors"][0]["with_findings"] == 1

    def test_blocked_actor_is_promoted_above_a_quiet_one(self):
        conns = [
            {"host": "a.com", "port": 443, "attribution": {"comm": "npm"}} for _ in range(5)
        ] + [
            {"host": "evil.com", "port": 443, "status": "blocked",
             "attribution": {"comm": "curl"}}
        ]
        assert summarise(conns)["actors"][0]["actor"] == "curl"

    def test_would_block_counts_as_blocked(self):
        conns = [{"host": "e.com", "port": 443, "status": "would_block",
                  "attribution": {"comm": "curl"}}]
        assert summarise(conns)["actors"][0]["blocked"] == 1

    def test_empty_input(self):
        out = summarise([])
        assert out == {"attributed_connections": 0, "unattributed_connections": 0,
                       "actors": []}
