"""The attribution inputs must survive the whole path from action.yml to setup.sh.

The node wrapper forwards inputs by name rather than passing the environment
through, so an input can be declared, documented and defaulted and still never
reach the shell. That failure is silent — attribution simply stays off — which
is why it is asserted here rather than left to a demo run to notice.
"""

import os

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_ACTION = os.path.join(REPO_ROOT, "native-proxy", "action", "action.yml")
SETUP_ACTION = os.path.join(REPO_ROOT, "native-proxy", "action-setup", "action.yml")
MAIN_JS = os.path.join(REPO_ROOT, "native-proxy", "action", "src", "main.js")
SETUP_SH = os.path.join(REPO_ROOT, "native-proxy", "setup.sh")
TEARDOWN_SH = os.path.join(REPO_ROOT, "native-proxy", "teardown.sh")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _inputs(path: str) -> dict:
    return yaml.safe_load(_read(path))["inputs"]


class TestActionInputs:
    def test_declared_in_both_actions(self):
        for path in (MAIN_ACTION, SETUP_ACTION):
            inputs = _inputs(path)
            assert "attribution" in inputs, path
            assert "attribution-cmdline" in inputs, path

    def test_defaults_match_across_actions(self):
        """Two manifests describing one feature must not drift apart."""
        main, setup = _inputs(MAIN_ACTION), _inputs(SETUP_ACTION)
        for key in ("attribution", "attribution-cmdline"):
            assert main[key]["default"] == setup[key]["default"]

    def test_cmdline_defaults_off(self):
        """Recording argv can republish a token; it must be opted into."""
        for path in (MAIN_ACTION, SETUP_ACTION):
            assert _inputs(path)["attribution-cmdline"]["default"] == "false"

    def test_attribution_defaults_to_client(self):
        for path in (MAIN_ACTION, SETUP_ACTION):
            assert _inputs(path)["attribution"]["default"] == "client"

    def test_inputs_are_documented(self):
        for path in (MAIN_ACTION, SETUP_ACTION):
            inputs = _inputs(path)
            for key in ("attribution", "attribution-cmdline"):
                assert len(inputs[key].get("description", "")) > 40


class TestForwarding:
    def test_node_wrapper_forwards_both_inputs(self):
        """A dashed input arrives as INPUT_ATTRIBUTION-CMDLINE, not underscored."""
        source = _read(MAIN_JS)
        assert "INPUT_ATTRIBUTION:" in source
        assert 'process.env["INPUT_ATTRIBUTION-CMDLINE"]' in source

    def test_bundled_action_was_rebuilt(self):
        """dist/ is what actually runs; editing src/ alone changes nothing."""
        bundle = os.path.join(REPO_ROOT, "native-proxy", "action",
                              "dist", "setup", "index.js")
        assert "ATTRIBUTION" in _read(bundle)

    def test_composite_action_forwards_both_inputs(self):
        source = _read(SETUP_ACTION)
        assert "INPUT_ATTRIBUTION: ${{ inputs.attribution }}" in source
        assert "INPUT_ATTRIBUTION_CMDLINE: ${{ inputs.attribution-cmdline }}" in source


class TestSetupScript:
    def test_reads_both_inputs(self):
        source = _read(SETUP_SH)
        assert 'ATTRIBUTION_MODE="${INPUT_ATTRIBUTION:-client}"' in source
        assert 'ATTRIBUTION_CMDLINE="${INPUT_ATTRIBUTION_CMDLINE:-false}"' in source

    def test_rejects_an_unknown_mode(self):
        """An unrecognised mode must fail setup, not quietly disable the feature."""
        source = _read(SETUP_SH)
        assert "off|client|process" in source

    def test_passes_mode_and_socket_to_the_proxy(self):
        """sudo strips the environment, so the env block is the only channel."""
        source = _read(SETUP_SH)
        assert source.count('ATTRIBUTION_MODE="${ATTRIBUTION_MODE}"') >= 2
        assert source.count('ATTRIBUTION_SOCKET="${ATTRIBUTION_SOCKET}"') >= 2

    def test_helper_starts_before_the_proxy(self):
        """The addon writes off a helper that refuses several connections, and
        the startup canary generates traffic immediately."""
        source = _read(SETUP_SH)
        assert source.index("attribution_helper.py") < source.index("MITMDUMP_PATH=")

    def test_helper_runs_as_root(self):
        """/proc/<pid>/fd is readable only by the process owner or root."""
        source = _read(SETUP_SH)
        assert "sudo python3 " in source
        assert "attribution_helper.py" in source

    def test_helper_ignores_the_proxy_user(self):
        """Attributing every request to mitmdump is worse than no attribution."""
        assert '--ignore-user "pipewardenuser"' in _read(SETUP_SH)

    def test_the_runner_user_is_never_the_ignored_user(self):
        """`--ignore-user "$(id -un)"` names the user the build steps run as.

        The helper drops connect() records belonging to the ignored uid, so
        passing the runner's own user discards the entire job's traffic rather
        than the proxy's — and process attribution then reports nothing at all
        while still announcing itself as enabled. Explicit-proxy mode is exactly
        where that mistake is easy to make, because there the proxy really does
        run as the runner user.
        """
        source = _read(SETUP_SH)
        assert '--ignore-user "$(id -un)"' not in source
        assert "--ignore-user \"${ATTRIBUTION_IGNORE_USER}\"" not in source

    def test_a_failed_helper_downgrades_instead_of_failing_the_job(self):
        source = _read(SETUP_SH)
        assert 'ATTRIBUTION_MODE="client"' in source

    def test_state_is_exported_for_teardown(self):
        source = _read(SETUP_SH)
        for key in ("NFW_ATTRIBUTION_MODE", "NFW_ATTRIBUTION_EVENTS",
                    "NFW_ATTRIBUTION_PID_FILE", "NFW_ATTRIBUTION_SOCKET"):
            assert key in source

    def test_rollback_stops_the_helper(self):
        """An audit rule left installed outlives the job that added it."""
        source = _read(SETUP_SH)
        rollback = source[source.index("rollback_on_failure() {"):
                          source.index("trap rollback_on_failure EXIT")]
        assert "attribution_helper.py" in rollback
        assert "kill -TERM" in rollback


class TestTeardownScript:
    def test_reads_the_exported_state(self):
        source = _read(TEARDOWN_SH)
        assert 'ATTRIBUTION_EVENTS="${NFW_ATTRIBUTION_EVENTS:-' in source
        assert 'ATTRIBUTION_PID_FILE="${NFW_ATTRIBUTION_PID_FILE:-' in source

    def test_stops_the_helper_with_sigterm_first(self):
        """SIGKILL would leave the audit rule installed."""
        source = _read(TEARDOWN_SH)
        assert 'sudo kill -TERM "$(cat "${ATTRIBUTION_PID_FILE}")"' in source

    def test_merges_events_before_generating_the_report(self):
        source = _read(TEARDOWN_SH)
        assert source.index("apply_events") < source.index("# 4. Generate report")

    def test_stops_the_helper_before_merging_its_events(self):
        """A helper still appending would make the merge read a partial file."""
        source = _read(TEARDOWN_SH)
        assert source.index("Stop attribution helper") < source.index("apply_events")

    def test_removes_the_events_file(self):
        """It names processes and can carry redacted command lines — job-scoped."""
        source = _read(TEARDOWN_SH)
        cleanup = source[source.index("# 7. Cleanup"):]
        assert "${ATTRIBUTION_EVENTS}" in cleanup

    def test_kills_a_helper_whose_pid_file_was_lost(self):
        source = _read(TEARDOWN_SH)
        cleanup = source[source.index("# 7. Cleanup"):]
        assert 'pkill -f "attribution_helper.py"' in cleanup

    def test_records_the_effective_mode_in_the_report(self):
        """Teardown read the exported mode and then dropped it on the floor.

        setup downgrades process to client when the helper cannot start, so the
        exported value is the only record of what actually ran. Without it a
        report with no named processes is indistinguishable from a report where
        attribution was never running at all.
        """
        source = _read(TEARDOWN_SH)
        assert "--attribution-mode ${ATTRIBUTION_MODE}" in source
        assert source.index("ATTRIBUTION_MODE=\"${NFW_ATTRIBUTION_MODE") < \
            source.index("--attribution-mode")
