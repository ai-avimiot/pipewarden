"""Container-mode pipelines run without the privileges that would bypass the proxy.

Asserted against entrypoint.sh source: the docker/act invocations are written inline.
"""

import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRYPOINT = os.path.join(REPO_ROOT, "container", "entrypoint.sh")


def _commands() -> list[str]:
    """Every shell command in the entrypoint with backslash continuations joined."""
    with open(ENTRYPOINT, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh.read().replace("\\\n", " ").splitlines()]


def _docker_run(name_var: str) -> str:
    marker = f'--name "${{{name_var}}}"'
    matches = [c for c in _commands() if c.startswith("docker run") and marker in c]
    assert len(matches) == 1, f"expected one docker run for {name_var}, got {matches}"
    return matches[0]


def test_pipeline_container_drops_raw_and_admin_caps() -> None:
    block = _docker_run("PIPELINE_CONTAINER")
    assert "--security-opt no-new-privileges" in block
    assert "--cap-drop NET_RAW" in block
    assert "--cap-drop NET_ADMIN" in block
    assert "--cap-add" not in block


def test_pipeline_container_keeps_default_caps_for_apt() -> None:
    block = _docker_run("PIPELINE_CONTAINER")
    assert "--cap-drop ALL" not in block
    assert "--privileged" not in block


def test_netns_holder_has_no_new_privileges() -> None:
    block = _docker_run("NETNS_CONTAINER")
    assert "--security-opt no-new-privileges" in block
    assert "--cap-add" not in block


def test_act_job_containers_drop_net_raw_and_get_no_docker_socket() -> None:
    commands = _commands()
    opts = " ".join(c for c in commands if c.startswith('CONTAINER_OPTS="${CONTAINER_OPTS}'))
    assert "--cap-drop=NET_RAW" in opts
    assert "NET_ADMIN" not in opts
    act = [c for c in commands if c.startswith("act push")]
    assert len(act) == 1
    assert "--container-daemon-socket - " in act[0]
