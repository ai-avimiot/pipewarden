"""Every rule setup adds must be removed by both rollback and teardown.

A REJECT rule that outlives the job does not fail loudly — it silently breaks
whatever the next step or the next job on that runner tries to do, and the
symptom appears somewhere with no connection to PipeWarden. The DNS rules make
this sharper than it was: a leftover reject on port 53 leaves the runner unable
to resolve anything at all.

Asserted against the scripts' source rather than a helper, because the rules are
written inline there and a helper test would not have seen them.
"""

import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_SH = os.path.join(REPO_ROOT, "native-proxy", "setup.sh")
TEARDOWN_SH = os.path.join(REPO_ROOT, "native-proxy", "teardown.sh")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _added_reject_rules(source: str) -> list[str]:
    """The body of every `iptables -A ... -j REJECT ...` line, minus the verb.

    Returned in a normalised form so it can be compared against the matching
    `-D` line regardless of which chain-editing verb was used.
    """
    rules = []
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("#") or "-j REJECT" not in line:
            continue
        m = re.search(r"ip6?tables\s+-A\s+(.*)", line)
        if not m:
            continue
        body = m.group(1)
        # Trailing shell noise is not part of the rule.
        body = body.split("2>/dev/null")[0].split("||")[0].split("; then")[0]
        rules.append(body.rstrip(" \\"))
    return rules


def _deleted_rules(source: str) -> list[str]:
    rules = []
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        m = re.search(r"ip6?tables\s+-D\s+(.*)", line)
        if not m:
            continue
        body = m.group(1)
        body = body.split("2>/dev/null")[0].split("||")[0].strip()
        rules.append(body)
    return rules


class TestEveryRejectRuleIsRemoved:
    def test_setup_rollback_removes_every_rule_setup_adds(self):
        """A failed setup must not leave the runner filtered."""
        source = _read(SETUP_SH)
        deleted = _deleted_rules(source)
        for rule in _added_reject_rules(source):
            assert rule in deleted, (
                f"setup.sh adds a REJECT rule its rollback never removes:\n  {rule}"
            )

    def test_teardown_removes_every_rule_setup_adds(self):
        """A rule surviving teardown outlives the job that installed it."""
        added = _added_reject_rules(_read(SETUP_SH))
        deleted = _deleted_rules(_read(TEARDOWN_SH))
        for rule in added:
            assert rule in deleted, (
                f"setup.sh adds a REJECT rule teardown never removes:\n  {rule}"
            )

    def test_there_are_rules_to_check(self):
        """Guards the guard: a broken regex would make both tests vacuous."""
        assert len(_added_reject_rules(_read(SETUP_SH))) >= 5


class TestDnsRejectShape:
    """The DNS rules are the ones where a wrong uid filter is unrecoverable."""

    def test_dns_reject_exempts_root_not_the_proxy_user(self):
        """dns_server.py runs as root and forwards upstream on port 53.

        Filtering on the proxy user instead would reject the interceptor's own
        forwarding and leave the runner unable to resolve anything — the whole
        job, not just the traffic the rule was meant to catch.
        """
        for line in _read(SETUP_SH).splitlines():
            if "--dport 53" in line and "-A" in line:
                assert "! --uid-owner 0" in line, line
                assert "pipewardenuser" not in line, line

    def test_dns_reject_spares_the_local_interceptor(self):
        """resolv.conf points at us; rejecting that destination too would mean
        nothing could resolve at all."""
        for line in _read(SETUP_SH).splitlines():
            if "--dport 53" in line and "-A" in line:
                assert "! -d 127.0.0.0/8" in line, line

    def test_dns_reject_is_enforce_and_dns_mode_only(self):
        """With dns: false there is no interceptor, so the rule would leave the
        runner with no resolver at all rather than a redirected one."""
        source = _read(SETUP_SH)
        # The rollback's own `-D` line also mentions port 53 and comes first in
        # the file, so anchor on the line that actually installs the rule.
        install = [ln for ln in source.splitlines()
                   if "--dport 53" in ln and re.search(r"iptables\s+-A", ln)]
        assert install, "no rule installing a port 53 reject was found"
        preceding = source[:source.index(install[0])]
        assert preceding.rindex('if [ "${ENABLE_DNS}" = "true" ]') > \
            preceding.rindex('if [ "${MODE}" = "enforce" ]')


def _rule_key(binary: str, table: str, body: str) -> tuple[str, str, str]:
    body = body.split("2>/dev/null")[0].split("||")[0].split("; then")[0].rstrip("\\ ").strip()
    return (binary, table or "filter", body)


def _added_rules(source: str) -> list[tuple[str, str, str]]:
    rules = []
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        m = re.search(r"(ip6?tables)\s+(?:-t\s+(\w+)\s+)?-A\s+(.*)", line)
        if m:
            rules.append(_rule_key(m.group(1), m.group(2), m.group(3)))
    return rules


def _integrity_checked_rules(source: str) -> list[tuple[str, str, str]]:
    rules = []
    for line in source.splitlines():
        m = re.match(r"\s*boundary_has\s+(ip6?tables)\s+(?:-t\s+(\w+)\s+)?-C\s+(.*)", line)
        if m:
            rules.append(_rule_key(m.group(1), m.group(2), m.group(3)))
    return rules


class TestEveryRuleIsIntegrityChecked:
    """A rule setup adds but teardown never re-checks could be deleted mid-job
    and the run would still report a boundary that was intact."""

    def test_teardown_checks_every_rule_setup_adds(self):
        checked = _integrity_checked_rules(_read(TEARDOWN_SH))
        for rule in _added_rules(_read(SETUP_SH)):
            assert rule in checked, (
                f"setup.sh adds a rule teardown's boundary check never verifies:\n  {rule}"
            )

    def test_every_checked_rule_is_one_setup_adds(self):
        """A check for a rule setup never installs would fail every run."""
        added = _added_rules(_read(SETUP_SH))
        for rule in _integrity_checked_rules(_read(TEARDOWN_SH)):
            assert rule in added, f"teardown checks a rule setup.sh never adds:\n  {rule}"

    def test_check_runs_before_any_rule_is_removed(self):
        source = _read(TEARDOWN_SH)
        first_check = source.index("boundary_has iptables")
        first_delete = re.search(r"sudo ip6?tables (-t nat )?-D ", source)
        assert first_delete is not None
        assert first_check < first_delete.start()

    def test_there_are_rules_to_check(self):
        assert len(_added_rules(_read(SETUP_SH))) >= 15
        assert len(_integrity_checked_rules(_read(TEARDOWN_SH))) >= 15

    def test_intercept_off_branch_checks_its_own_rules(self):
        """The LOG rule text also appears in the transparent branch, so the
        file-wide match above would pass even if this branch skipped it."""
        setup = _read(SETUP_SH)
        start = setup.index("Configure connection logging (no interception)")
        added = _added_rules(setup[start:setup.index('elif [ "${ENABLE_TRANSPARENT}" = "true" ]', start)])
        teardown = _read(TEARDOWN_SH)
        start = teardown.index('elif [ "${TLS_INTERCEPT}" != "true" ]')
        checked = _integrity_checked_rules(
            teardown[start:teardown.index('if [ "${BOUNDARY_INTACT}" = "true" ]', start)])
        assert len(added) >= 8
        assert any("NFW-CONN: " in r[2] for r in added)
        for rule in added:
            assert rule in checked, (
                f"tls-intercept: false adds a rule its boundary check never verifies:\n  {rule}"
            )


def test_enforce_ip6_rejects_fail_setup_instead_of_being_skipped():
    """Teardown requires these rules, so setup must not tolerate their absence."""
    for line in _read(SETUP_SH).splitlines():
        if "ip6tables -A" in line and "-j REJECT" in line:
            assert "|| true" not in line, line
