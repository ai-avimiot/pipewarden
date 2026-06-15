#!/usr/bin/env python3
"""Environment variable generation for the native proxy mode.

Generates KEY=value lines suitable for appending to GITHUB_ENV,
covering proxy settings, CA trust, and NFW state variables.
"""


def generate_proxy_env_vars(port: int) -> list[str]:
    """Generate proxy environment variable lines.

    Args:
        port: The proxy listening port (e.g. 8080).

    Returns:
        List of KEY=value strings for HTTP_PROXY, HTTPS_PROXY,
        http_proxy, and https_proxy.
    """
    proxy_url = f"http://127.0.0.1:{port}"
    return [
        f"HTTP_PROXY={proxy_url}",
        f"HTTPS_PROXY={proxy_url}",
        f"http_proxy={proxy_url}",
        f"https_proxy={proxy_url}",
    ]


def generate_ca_env_vars(ca_path: str) -> list[str]:
    """Generate CA trust environment variable lines.

    Args:
        ca_path: Absolute path to the CA certificate file.

    Returns:
        List of KEY=value strings for all supported CA trust variables.
    """
    return [
        f"SSL_CERT_FILE={ca_path}",
        f"REQUESTS_CA_BUNDLE={ca_path}",
        f"CURL_CA_BUNDLE={ca_path}",
        f"GIT_SSL_CAINFO={ca_path}",
        f"NODE_EXTRA_CA_CERTS={ca_path}",
        f"NPM_CONFIG_CAFILE={ca_path}",
        f"PIP_CERT={ca_path}",
        f"CARGO_HTTP_CAINFO={ca_path}",
    ]


def generate_state_env_vars(
    ca_dir: str,
    log_dir: str,
    proxy_pid: str,
    action_path: str,
    mode: str,
    policy_file: str,
    proxy_port: str,
) -> list[str]:
    """Generate NFW state environment variable lines.

    These variables allow the teardown script to locate resources
    created during setup.

    Args:
        ca_dir: Path to the CA certificate directory.
        log_dir: Path to the connection log directory.
        proxy_pid: PID of the running mitmproxy process.
        action_path: Path to the native-proxy action directory.
        mode: Enforcement mode ('monitor' or 'enforce').
        policy_file: Path to the network policy YAML file.
        proxy_port: Proxy listening port.

    Returns:
        List of KEY=value strings for NFW_ prefixed state variables.
    """
    return [
        f"NFW_CA_DIR={ca_dir}",
        f"NFW_LOG_DIR={log_dir}",
        f"NFW_PROXY_PID={proxy_pid}",
        f"NFW_ACTION_PATH={action_path}",
        f"NFW_MODE={mode}",
        f"NFW_POLICY_FILE={policy_file}",
        f"NFW_PROXY_PORT={proxy_port}",
    ]


def determine_exit_code(
    mode: str, blocked_count: int, pipeline_exit_code: int = 0
) -> int:
    """Determine the process exit code based on mode and blocked connections.

    Args:
        mode: Enforcement mode ('monitor' or 'enforce').
        blocked_count: Number of blocked connections.
        pipeline_exit_code: Exit code from the user's pipeline (default 0).

    Returns:
        1 if mode is 'enforce' and blocked_count > 0,
        otherwise pipeline_exit_code.
    """
    if mode == "enforce" and blocked_count > 0:
        return 1
    return pipeline_exit_code


def generate_transparent_state_vars(transparent: bool) -> list[str]:
    """Generate NFW_TRANSPARENT state variable.

    Args:
        transparent: Whether transparent proxy mode is enabled.

    Returns:
        List containing a single entry: "NFW_TRANSPARENT=true" or "NFW_TRANSPARENT=false".
    """
    value = "true" if transparent else "false"
    return [f"NFW_TRANSPARENT={value}"]
