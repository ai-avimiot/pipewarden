#!/bin/bash
# entrypoint.sh — PipeWarden orchestrator
#
# Two execution modes:
#   1. Workflow mode (INPUT_WORKFLOW_FILE): injects an init step into the
#      workflow YAML, then runs it via nektos/act on the monitored network.
#      All GitHub Actions (uses: steps) work natively.
#   2. Command mode (INPUT_PIPELINE_CMD): runs a shell command directly
#      in an ubuntu:22.04 container on the monitored network.
#
# Architecture: transparent proxy. The proxy container (172.30.0.2) acts as
# the default gateway. All outbound TCP traffic (ports 80/443) is routed
# through the proxy at the network level — no HTTP_PROXY env vars needed.
set -euo pipefail

# ---------------------------------------------------------------------------
# Inputs (from GitHub Action environment or manual invocation)
# ---------------------------------------------------------------------------
PIPELINE_CMD="${INPUT_PIPELINE_CMD:-}"
WORKFLOW_FILE="${INPUT_WORKFLOW_FILE:-}"
POLICY_FILE="${INPUT_POLICY_FILE:-network-policy.yml}"
MODE="${INPUT_MODE:-enforce}"
FAIL_ON_BLOCK="${INPUT_FAIL_ON_BLOCK:-true}"

# Discovery mode: if policy file is absent, monitor all traffic and block nothing.
# The proxy addon handles a missing /policy.yml gracefully (empty rules, monitor mode).
POLICY_FILE_EXISTS=false
if [ -f "${POLICY_FILE}" ]; then
    POLICY_FILE_EXISTS=true
else
    echo "Note: policy file '${POLICY_FILE}' not found — running in discovery mode (monitor all, block nothing)"
fi
RUNNER_IMAGE="${PIPEWARDEN_RUNNER_IMAGE:-${NFW_RUNNER_IMAGE:-catthehacker/ubuntu:act-22.04}}"
POST_COMMENT="${INPUT_POST_COMMENT:-false}"
GH_TOKEN="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

# Determine execution mode: workflow file (act) or pipeline command (direct)
USE_ACT=false
if [ -n "${WORKFLOW_FILE}" ]; then
    USE_ACT=true
    echo "::group::Prepare workflow for act"
    # Copy pre-cached actions to writable location
    ACT_CACHE="/tmp/act-cache"
    cp -r /opt/act-cache "${ACT_CACHE}" 2>/dev/null || mkdir -p "${ACT_CACHE}"
    MODIFIED_WORKFLOW="/tmp/nfw-workflow.yml"
    python3 scripts/workflow_injector.py "${WORKFLOW_FILE}" --output "${MODIFIED_WORKFLOW}"
    echo "::endgroup::"
elif [ -z "${PIPELINE_CMD}" ]; then
    echo "Error: Either INPUT_PIPELINE_CMD or INPUT_WORKFLOW_FILE is required" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NETWORK_NAME="cicd-monitor-net"
PROXY_CONTAINER="cicd-proxy"
PIPELINE_CONTAINER="cicd-pipeline"
NETNS_CONTAINER="cicd-pipeline-netns"
CA_DIR="/tmp/ca"
LOG_DIR="/tmp/monitor-logs"
REPORT_DIR="/tmp/report"

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit (trap)
# ---------------------------------------------------------------------------
cleanup() {
    echo "::group::Cleanup"
    echo "Cleaning up containers and network..."
    docker rm -f "${PROXY_CONTAINER}" 2>/dev/null || true
    docker rm -f "${PIPELINE_CONTAINER}" 2>/dev/null || true
    docker rm -f "${NETNS_CONTAINER}" 2>/dev/null || true
    docker network rm "${NETWORK_NAME}" 2>/dev/null || true
    echo "Cleanup complete."
    echo "::endgroup::"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Setup: CA cert + Docker network + proxy image pull (parallelized)
# ---------------------------------------------------------------------------
echo "::group::Setup (CA + network + proxy pull)"

# These three operations are independent — run them in parallel
python3 scripts/generate_ca.py --out "${CA_DIR}" &
PID_CA=$!

# --internal: the only way off this network is through the dual-homed proxy, so
# a workload that rewrites its own default route reaches nothing.
docker network create --internal --subnet=172.30.0.0/16 "${NETWORK_NAME}" &
PID_NET=$!

PROXY_IMAGE="${PIPEWARDEN_PROXY_IMAGE:-${NFW_PROXY_IMAGE:-}}"
if [ -n "${PROXY_IMAGE}" ]; then
    # A locally built image (CI testing a PR) has no registry to pull from.
    { docker image inspect "${PROXY_IMAGE}" > /dev/null 2>&1 || docker pull "${PROXY_IMAGE}"; } &
    PID_PULL=$!
fi

# Pre-pull runner image for act (in parallel)
if [ "${USE_ACT}" = "true" ]; then
    docker pull "${RUNNER_IMAGE}" &
    PID_RUNNER=$!
fi

# Wait for all background jobs
wait ${PID_CA}
wait ${PID_NET}
if [ -n "${PROXY_IMAGE}" ]; then
    wait ${PID_PULL}
else
    PROXY_IMAGE="pipewarden-proxy"
    docker build -t "${PROXY_IMAGE}" -f proxy/Dockerfile .
fi
if [ "${USE_ACT}" = "true" ]; then
    wait ${PID_RUNNER}
fi

echo "::endgroup::"

# ---------------------------------------------------------------------------
# 2. Start proxy container (acts as gateway)
# ---------------------------------------------------------------------------
echo "::group::Start proxy"

PROXY_IP="172.30.0.2"

# Created on the default bridge (its egress), then attached to the monitored
# network as the gateway.
PROXY_RUN_ARGS=(
    --name "${PROXY_CONTAINER}"
    --network bridge
    --cap-add NET_ADMIN
    --sysctl net.ipv4.ip_forward=1
    -v "${CA_DIR}:/ca"
    -e MODE="${MODE}"
)
if [ "${POLICY_FILE_EXISTS}" = "true" ]; then
    PROXY_RUN_ARGS+=(-v "$(realpath "${POLICY_FILE}"):/policy.yml")
fi
docker create "${PROXY_RUN_ARGS[@]}" "${PROXY_IMAGE}" > /dev/null
docker network connect --ip "${PROXY_IP}" "${NETWORK_NAME}" "${PROXY_CONTAINER}"
docker start "${PROXY_CONTAINER}" > /dev/null

# Wait for mitmproxy to be listening on port 8080 (fast readiness check)
echo "Waiting for proxy to be ready..."
for i in $(seq 1 60); do
    CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' "${PROXY_CONTAINER}" 2>/dev/null || echo "unknown")
    if [ "${CONTAINER_STATUS}" = "exited" ] || [ "${CONTAINER_STATUS}" = "dead" ]; then
        echo "ERROR: Proxy container has stopped. Logs:"
        docker logs "${PROXY_CONTAINER}" 2>&1 | tail -20
        exit 1
    fi
    # Check if mitmproxy is actually listening on port 8080
    if docker exec "${PROXY_CONTAINER}" bash -c "cat /proc/net/tcp 2>/dev/null | grep -q ':1F90'" 2>/dev/null; then
        echo "Proxy container is ready"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "Warning: Proxy may not be fully ready after 20s"
    fi
    sleep 0.3
done
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 3. Run pipeline (act for workflow files, direct container for commands)
# ---------------------------------------------------------------------------
echo "::group::Run pipeline"
set +e

WORKSPACE_DIR="${GITHUB_WORKSPACE:-$(pwd)}"

if [ "${USE_ACT}" = "true" ]; then
    # --- Act mode: run workflow natively via nektos/act ---
    CONTAINER_OPTS="--dns ${PROXY_IP}"
    CONTAINER_OPTS="${CONTAINER_OPTS} -v ${CA_DIR}/ca.pem:/ca/ca.pem:ro"

    # act creates the job containers itself, so route each one through the
    # proxy from outside as it starts: the job then needs neither NET_ADMIN
    # nor iproute2 (which it could not install before it has a route).
    PROXY_ID="$(docker inspect -f '{{.Id}}' "${PROXY_CONTAINER}")"
    docker events --filter type=container --filter event=start --format '{{.ID}}' |
        while read -r cid; do
            [ "${cid}" = "${PROXY_ID}" ] && continue
            nets="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${cid}" 2>/dev/null || true)"
            case " ${nets} " in *" ${NETWORK_NAME} "*) ;; *) continue ;; esac
            docker run --rm --network "container:${cid}" --cap-add NET_ADMIN \
                --entrypoint ip "${PROXY_IMAGE}" route replace default via "${PROXY_IP}" \
                || echo "Warning: could not route container ${cid:0:12} through the proxy"
        done &
    ROUTER_PID=$!
    sleep 1  # let the event stream subscribe before act starts containers

    act push \
        -W "${MODIFIED_WORKFLOW}" \
        --network "${NETWORK_NAME}" \
        --container-options "${CONTAINER_OPTS}" \
        -b \
        -C "${WORKSPACE_DIR}" \
        --action-cache-path "${ACT_CACHE}" \
        --action-offline-mode \
        --pull=false \
        --no-cache-server \
        --env PROXY_GATEWAY="${PROXY_IP}" \
        --env SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
        --env REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        --env CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        --env NODE_EXTRA_CA_CERTS=/ca/ca.pem \
        --env PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
        --env GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
        --env NPM_CONFIG_CAFILE=/etc/ssl/certs/ca-certificates.crt \
        --env CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt \
        --env CI=true \
        -P ubuntu-latest="${RUNNER_IMAGE}" \
        -P ubuntu-22.04="${RUNNER_IMAGE}" \
        -P ubuntu-24.04="${RUNNER_IMAGE}" \
        --rm
    PIPELINE_EXIT=$?
    kill "${ROUTER_PID}" 2>/dev/null || true
else
    # --- Pipeline-command mode: run directly in a container ---
    PIPELINE_IP="172.30.0.3"

    # The route through the proxy is set from outside, in a namespace the
    # pipeline then joins: the pipeline itself never gets NET_ADMIN to undo it.
    docker run -d --name "${NETNS_CONTAINER}" \
        --network "${NETWORK_NAME}" \
        --ip "${PIPELINE_IP}" \
        --dns "${PROXY_IP}" \
        --entrypoint sleep "${PROXY_IMAGE}" infinity > /dev/null
    docker run --rm --network "container:${NETNS_CONTAINER}" --cap-add NET_ADMIN \
        --entrypoint ip "${PROXY_IMAGE}" route replace default via "${PROXY_IP}"

    # Every TLS connection is intercepted, so the per-run CA is the only root needed.
    docker run --name "${PIPELINE_CONTAINER}" \
        --network "container:${NETNS_CONTAINER}" \
        -v "${WORKSPACE_DIR}:/workspace" \
        -v "${CA_DIR}/ca.pem:/ca/ca.pem:ro" \
        -w /workspace \
        -e CI=true \
        -e SSL_CERT_FILE=/ca/ca.pem \
        -e CURL_CA_BUNDLE=/ca/ca.pem \
        -e REQUESTS_CA_BUNDLE=/ca/ca.pem \
        -e NODE_EXTRA_CA_CERTS=/ca/ca.pem \
        -e NPM_CONFIG_CAFILE=/ca/ca.pem \
        -e PIP_CERT=/ca/ca.pem \
        -e GIT_SSL_CAINFO=/ca/ca.pem \
        ubuntu:22.04 \
        bash -c "${PIPELINE_CMD}"
    PIPELINE_EXIT=$?
fi

set -e
echo "Pipeline exited with code ${PIPELINE_EXIT}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 4. Collect logs from proxy container
# ---------------------------------------------------------------------------
echo "::group::Collect logs"
mkdir -p "${LOG_DIR}"
docker cp "${PROXY_CONTAINER}:/var/log/connections.jsonl" "${LOG_DIR}/connections.jsonl" 2>/dev/null || {
    echo "Warning: could not copy connection log; creating empty log."
    echo -n "" > "${LOG_DIR}/connections.jsonl"
}
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 5. Generate report
# ---------------------------------------------------------------------------
echo "::group::Generate report"
REPORT_CMD_ARGS=(--input "${LOG_DIR}/connections.jsonl" --output "${REPORT_DIR}")
if [ "${POLICY_FILE_EXISTS}" = "true" ]; then
    REPORT_CMD_ARGS+=(--policy "${POLICY_FILE}")
fi
python3 scripts/generate_report.py "${REPORT_CMD_ARGS[@]}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 6. Write Job Summary (visible in GitHub Actions UI)
# ---------------------------------------------------------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "${REPORT_DIR}/summary.md" ]; then
    if [ -d "$(dirname "${GITHUB_STEP_SUMMARY}")" ]; then
        cat "${REPORT_DIR}/summary.md" >> "${GITHUB_STEP_SUMMARY}"
    else
        echo "Warning: GITHUB_STEP_SUMMARY path not accessible, skipping job summary"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Post GitHub comment with report (optional)
# ---------------------------------------------------------------------------
if [ "${POST_COMMENT}" = "true" ] && [ -f "${REPORT_DIR}/summary.md" ]; then
    echo "::group::Post GitHub comment"
    if [ -z "${GH_TOKEN}" ]; then
        echo "Warning: post-comment is enabled but no GitHub token available; skipping comment."
    elif [ -z "${GITHUB_REPOSITORY:-}" ]; then
        echo "Warning: GITHUB_REPOSITORY not set; skipping comment."
    else
        RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-}"
        # Pass the token via the environment, not argv — a token on the command
        # line is readable in the process table by any other process.
        GH_TOKEN="${GH_TOKEN}" python3 scripts/post_github_comment.py \
            --report "${REPORT_DIR}/summary.md" \
            --repo "${GITHUB_REPOSITORY}" \
            --event-path "${GITHUB_EVENT_PATH:-}" \
            --run-url "${RUN_URL}" \
            || echo "Warning: Failed to post GitHub comment."
    fi
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 8. Set outputs and determine exit code
# ---------------------------------------------------------------------------
BLOCKED_COUNT=$(python3 scripts/count_blocked.py "${REPORT_DIR}/report.json")

if [ -n "${GITHUB_OUTPUT:-}" ] && [ -d "$(dirname "${GITHUB_OUTPUT}")" ]; then
    echo "report-path=${REPORT_DIR}" >> "${GITHUB_OUTPUT}"
    echo "blocked-count=${BLOCKED_COUNT}" >> "${GITHUB_OUTPUT}"
    if [ "${MODE}" = "enforce" ] && [ "${BLOCKED_COUNT}" -gt 0 ]; then
        echo "status=fail" >> "${GITHUB_OUTPUT}"
    else
        echo "status=pass" >> "${GITHUB_OUTPUT}"
    fi
    # Emit generated policy path when running in discovery mode (no policy file)
    GENERATED_POLICY="${REPORT_DIR}/network-policy.yml"
    if [ -f "${GENERATED_POLICY}" ]; then
        echo "generated-policy-path=${GENERATED_POLICY}" >> "${GITHUB_OUTPUT}"
        echo "NFW: Generated network-policy.yml written to ${GENERATED_POLICY}"
    else
        echo "generated-policy-path=" >> "${GITHUB_OUTPUT}"
    fi
fi

# Exit code: enforce mode fails on blocked traffic (unless fail-on-block is
# opted out), monitor mode passes through the pipeline exit.
if [ "${MODE}" = "enforce" ] && [ "${BLOCKED_COUNT}" -gt 0 ]; then
    if [ "${FAIL_ON_BLOCK}" = "false" ]; then
        echo "::warning::PipeWarden: blocked ${BLOCKED_COUNT} connection(s) in enforce mode; fail-on-block is false, so the pipeline exit code is preserved. The traffic was still blocked."
    else
        echo "::error::PipeWarden: blocked ${BLOCKED_COUNT} connection(s) in enforce mode — stopping the pipeline. Set fail-on-block: false to block the traffic but let the job continue, or use monitor mode to only observe."
        exit 1
    fi
fi
exit "${PIPELINE_EXIT}"
