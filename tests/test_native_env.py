"""Tests for native-proxy/env_vars.py — environment variable generation and exit logic."""

import os
import sys

# Ensure native-proxy is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "native-proxy"))

from env_vars import (
    determine_exit_code,
    generate_ca_env_vars,
    generate_proxy_env_vars,
    generate_state_env_vars,
    generate_transparent_state_vars,
)
from hypothesis import given, settings
from hypothesis import strategies as st

# ------------------------------------------------------------------
# generate_proxy_env_vars
# ------------------------------------------------------------------

class TestGenerateProxyEnvVars:
    def test_default_port(self):
        result = generate_proxy_env_vars(8080)
        assert result == [
            "HTTP_PROXY=http://127.0.0.1:8080",
            "HTTPS_PROXY=http://127.0.0.1:8080",
            "http_proxy=http://127.0.0.1:8080",
            "https_proxy=http://127.0.0.1:8080",
        ]

    def test_custom_port(self):
        result = generate_proxy_env_vars(3128)
        for line in result:
            assert "3128" in line

    def test_returns_four_entries(self):
        result = generate_proxy_env_vars(9999)
        assert len(result) == 4

    def test_all_entries_are_key_value(self):
        for line in generate_proxy_env_vars(8080):
            key, _, value = line.partition("=")
            assert key
            assert value.startswith("http://127.0.0.1:")


# ------------------------------------------------------------------
# generate_ca_env_vars
# ------------------------------------------------------------------

class TestGenerateCaEnvVars:
    EXPECTED_KEYS = [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "NODE_EXTRA_CA_CERTS",
        "NPM_CONFIG_CAFILE",
        "PIP_CERT",
        "CARGO_HTTP_CAINFO",
    ]

    def test_all_keys_present(self):
        result = generate_ca_env_vars("/tmp/nfw-ca/ca.pem")
        keys = [line.split("=", 1)[0] for line in result]
        assert keys == self.EXPECTED_KEYS

    def test_all_values_point_to_ca_path(self):
        ca = "/custom/path/cert.pem"
        for line in generate_ca_env_vars(ca):
            assert line.endswith(ca)

    def test_returns_eight_entries(self):
        assert len(generate_ca_env_vars("/ca.pem")) == 8


# ------------------------------------------------------------------
# generate_state_env_vars
# ------------------------------------------------------------------

class TestGenerateStateEnvVars:
    def test_all_nfw_keys(self):
        result = generate_state_env_vars(
            ca_dir="/tmp/ca",
            log_dir="/tmp/logs",
            proxy_pid="1234",
            action_path="/actions/native-proxy",
            mode="monitor",
            policy_file="network-policy.yml",
            proxy_port="8080",
        )
        keys = [line.split("=", 1)[0] for line in result]
        assert keys == [
            "NFW_CA_DIR",
            "NFW_LOG_DIR",
            "NFW_PROXY_PID",
            "NFW_ACTION_PATH",
            "NFW_MODE",
            "NFW_POLICY_FILE",
            "NFW_PROXY_PORT",
        ]

    def test_values_match_inputs(self):
        result = generate_state_env_vars(
            ca_dir="/a",
            log_dir="/b",
            proxy_pid="42",
            action_path="/c",
            mode="enforce",
            policy_file="pol.yml",
            proxy_port="9090",
        )
        mapping = dict(line.split("=", 1) for line in result)
        assert mapping["NFW_CA_DIR"] == "/a"
        assert mapping["NFW_LOG_DIR"] == "/b"
        assert mapping["NFW_PROXY_PID"] == "42"
        assert mapping["NFW_ACTION_PATH"] == "/c"
        assert mapping["NFW_MODE"] == "enforce"
        assert mapping["NFW_POLICY_FILE"] == "pol.yml"
        assert mapping["NFW_PROXY_PORT"] == "9090"

    def test_returns_seven_entries(self):
        result = generate_state_env_vars("/a", "/b", "1", "/c", "m", "p", "8080")
        assert len(result) == 7


# ------------------------------------------------------------------
# determine_exit_code
# ------------------------------------------------------------------

class TestDetermineExitCode:
    def test_enforce_with_blocked_returns_one(self):
        assert determine_exit_code("enforce", 5) == 1

    def test_enforce_no_blocked_returns_pipeline_code(self):
        assert determine_exit_code("enforce", 0, 0) == 0
        assert determine_exit_code("enforce", 0, 42) == 42

    def test_monitor_with_blocked_returns_pipeline_code(self):
        assert determine_exit_code("monitor", 10, 0) == 0

    def test_monitor_no_blocked_returns_pipeline_code(self):
        assert determine_exit_code("monitor", 0, 3) == 3

    def test_default_pipeline_exit_code_is_zero(self):
        assert determine_exit_code("monitor", 0) == 0
        assert determine_exit_code("enforce", 0) == 0

    def test_enforce_blocked_ignores_pipeline_code(self):
        assert determine_exit_code("enforce", 1, 99) == 1


# ------------------------------------------------------------------
# Property 6: Transparent state variable generation
# ------------------------------------------------------------------

@given(transparent=st.booleans())
@settings(max_examples=100)
def test_p6_transparent_state_vars(transparent: bool):
    """Feature: native-transparent-proxy, Property 6: Transparent state variable generation
    **Validates: Requirements 9.1, 9.2, 9.3**
    """
    result = generate_transparent_state_vars(transparent)
    assert len(result) == 1
    expected = f"NFW_TRANSPARENT={'true' if transparent else 'false'}"
    assert result[0] == expected


# ------------------------------------------------------------------
# generate_transparent_state_vars (unit tests)
# ------------------------------------------------------------------

class TestGenerateTransparentStateVars:
    def test_transparent_true(self):
        assert generate_transparent_state_vars(True) == ["NFW_TRANSPARENT=true"]

    def test_transparent_false(self):
        assert generate_transparent_state_vars(False) == ["NFW_TRANSPARENT=false"]
