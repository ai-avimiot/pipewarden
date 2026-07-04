#!/bin/bash
# setup.sh — PipeWarden native proxy setup for GitHub Actions runners.
#
# Installs mitmproxy, generates a CA certificate, starts mitmdump as a
# background process under a dedicated user, optionally starts a Python DNS
# interceptor, and configures iptables for transparent interception.
set -euo pipefail

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
# Raw policy-file input. Empty ("") means auto-resolve (common + per-pipeline).
POLICY_FILE_INPUT="${INPUT_POLICY_FILE:-}"
MODE="${INPUT_MODE:-enforce}"
PROXY_PORT="${INPUT_PROXY_PORT:-8080}"

# Validate proxy-port
if ! [[ "${PROXY_PORT}" =~ ^[0-9]+$ ]] || [ "${PROXY_PORT}" -lt 1 ] || [ "${PROXY_PORT}" -gt 65535 ]; then
    echo "ERROR: proxy-port must be a number between 1 and 65535, got '${PROXY_PORT}'" >&2
    exit 1
fi

ENABLE_DNS="${INPUT_DNS:-true}"
ACTION_PATH="${INPUT_ACTION_PATH:-.}"
ENABLE_TRANSPARENT="${INPUT_TRANSPARENT:-true}"
FAIL_FAST="${INPUT_FAIL_FAST:-false}"
GH_TOKEN_INPUT="${INPUT_GITHUB_TOKEN:-}"

CA_DIR="/tmp/nfw-ca"
LOG_DIR="/tmp/monitor-logs"
PID_FILE="/tmp/nfw-proxy.pid"

ACTION_PATH="$(realpath "${ACTION_PATH}")"
PROJECT_ROOT="$(dirname "${ACTION_PATH}")"

# ---------------------------------------------------------------------------
# 0. Resolve effective policy
#    - explicit policy-file input wins
#    - else merge .github/pipewarden/common.network-policy.yml +
#      .github/pipewarden/<workflow>.network-policy.yml
#    - else repo-root network-policy.yml
#    - else discovery (monitor all, generate a policy)
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Resolve policy"
EFFECTIVE_POLICY_OUT="/tmp/pipewarden-effective-policy.yml"
POLICY_FILE="$(python3 "${PROJECT_ROOT}/scripts/resolve_policy.py" \
    --explicit "${POLICY_FILE_INPUT}" \
    --mode "${MODE}" \
    --out "${EFFECTIVE_POLICY_OUT}" 2>/tmp/pw-resolve.log)"
cat /tmp/pw-resolve.log || true
# Per-pipeline policy path (for the report's "commit this" tip).
PIPELINE_POLICY_PATH="$(python3 -c "import os, sys; sys.path.insert(0, '${PROJECT_ROOT}'); from scripts.resolve_policy import workflow_stem, pipeline_policy_name, PIPEWARDEN_DIR; s = workflow_stem(os.environ.get('GITHUB_WORKFLOW_REF', '')); print(os.path.join(PIPEWARDEN_DIR, pipeline_policy_name(s)) if s else os.path.join(PIPEWARDEN_DIR, 'network-policy.yml'))" 2>/dev/null || echo "")"
echo "Effective policy: ${POLICY_FILE:-<discovery mode>}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 1. Install mitmproxy (the proven proxy engine)
# ---------------------------------------------------------------------------
# Pin the version so a compromised or breaking PyPI release can't be pulled
# into the runner at job time. Keep this in lockstep with the proxy container
# base image (proxy/Dockerfile: mitmproxy/mitmproxy:<version>). Overridable via
# the mitmproxy-version input for testing against a newer release.
MITMPROXY_VERSION="${INPUT_MITMPROXY_VERSION:-12.2.3}"
echo "::group::PipeWarden: Install proxy"
if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    if [ -x /usr/local/bin/mitmdump ]; then
        echo "mitmproxy already installed, skipping"
    else
        echo "Installing mitmproxy==${MITMPROXY_VERSION}..."
        # sudo strips the environment, so the wheel cache restored by the JS
        # action (PIP_CACHE_DIR, see action/src/main.js) is forwarded
        # explicitly. Unset means no cache was restored — plain install.
        if [ -n "${PIP_CACHE_DIR:-}" ]; then
            # pip refuses (silently disables) a cache dir not owned by the
            # current user, so ownership must follow whoever touches it:
            # root during the sudo install, the runner user afterwards so
            # the post-step can archive it for the cache save.
            sudo chown -R 0:0 "${PIP_CACHE_DIR}" 2>/dev/null || true
            sudo PIP_CACHE_DIR="${PIP_CACHE_DIR}" pip install --quiet --break-system-packages --ignore-installed typing_extensions "mitmproxy==${MITMPROXY_VERSION}"
            sudo chown -R "$(id -u)":"$(id -g)" "${PIP_CACHE_DIR}" 2>/dev/null || true
        else
            sudo pip install --quiet --break-system-packages --ignore-installed typing_extensions "mitmproxy==${MITMPROXY_VERSION}"
        fi
    fi
else
    if command -v mitmdump &>/dev/null; then
        echo "mitmdump already on PATH, skipping"
    else
        pip install --quiet "mitmproxy==${MITMPROXY_VERSION}"
    fi
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 2. Generate CA certificate
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Generate CA certificate"
python3 "${PROJECT_ROOT}/scripts/generate_ca.py" --out "${CA_DIR}"
chmod 600 "${CA_DIR}/ca-key.pem"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 3. Install CA into system trust store
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Install CA into trust store"
sudo cp "${CA_DIR}/ca.pem" /usr/local/share/ca-certificates/nfw-ca.crt
sudo update-ca-certificates > /dev/null 2>&1 || echo "Warning: update-ca-certificates failed"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 4. Configure transparent mode user (if needed)
# ---------------------------------------------------------------------------
if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Configure transparent mode"
    if ! id -u pipewardenuser &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin pipewardenuser
        echo "Created pipewardenuser"
    fi

    sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 5. Capture upstream DNS before we take over
# ---------------------------------------------------------------------------
UPSTREAM_DNS=""
if [ "${ENABLE_DNS}" = "true" ]; then
    if command -v resolvectl &>/dev/null; then
        UPSTREAM_DNS=$(resolvectl status 2>/dev/null | grep -oP 'DNS Servers: \K.*' | head -1 || true)
    fi
    if [ -z "${UPSTREAM_DNS}" ]; then
        UPSTREAM_DNS=$(grep -oP 'nameserver \K[0-9.]+' /etc/resolv.conf 2>/dev/null | grep -v '127.0.0' | head -2 | tr '\n' ',' || true)
    fi
    if [ -z "${UPSTREAM_DNS}" ]; then
        UPSTREAM_DNS="8.8.8.8,1.1.1.1"
    fi
    UPSTREAM_DNS="${UPSTREAM_DNS%,}"

    # Stop systemd-resolved to free port 53
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo "Stopping systemd-resolved..."
        sudo systemctl stop systemd-resolved
    fi
fi

# ---------------------------------------------------------------------------
# 6. Start proxy (Go binary handles proxy + DNS in one process)
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Start proxy"
mkdir -p "${LOG_DIR}"

if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    # Transparent mode: run mitmproxy as pipewardenuser
    RUNNER_GROUP="$(id -gn)"
    sudo usermod -aG "${RUNNER_GROUP}" pipewardenuser 2>/dev/null || true

    # Ensure log dir is writable
    sudo chgrp "${RUNNER_GROUP}" "${LOG_DIR}"
    sudo chmod 770 "${LOG_DIR}"
    touch "${LOG_DIR}/connections.jsonl"
    sudo chgrp "${RUNNER_GROUP}" "${LOG_DIR}/connections.jsonl"
    sudo chmod 660 "${LOG_DIR}/connections.jsonl"

    # Create mitmproxy config dir
    sudo mkdir -p /home/pipewardenuser/.mitmproxy
    sudo cp "${CA_DIR}/ca-key.pem" "${CA_DIR}/ca.pem" /home/pipewardenuser/.mitmproxy/
    cat "${CA_DIR}/ca-key.pem" "${CA_DIR}/ca.pem" \
        | sudo tee /home/pipewardenuser/.mitmproxy/mitmproxy-ca.pem > /dev/null
    sudo chown -R pipewardenuser:pipewardenuser /home/pipewardenuser/.mitmproxy

    # Ensure addon.py and policy are readable
    sudo chmod -R o+rX "${PROJECT_ROOT}/proxy" 2>/dev/null || true
    sudo chmod o+r "$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" 2>/dev/null || true
    CURRENT_DIR="${PROJECT_ROOT}"
    while [ "${CURRENT_DIR}" != "/" ]; do
        sudo chmod o+rx "${CURRENT_DIR}" 2>/dev/null || true
        CURRENT_DIR="$(dirname "${CURRENT_DIR}")"
    done

    MITMDUMP_PATH="$(command -v mitmdump)"
    nohup sudo -u pipewardenuser \
        env POLICY_FILE="$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" \
            MODE="${MODE}" \
            LOG_PATH="${LOG_DIR}/connections.jsonl" \
        "${MITMDUMP_PATH}" \
        --mode transparent \
        --listen-host 0.0.0.0 \
        --listen-port "${PROXY_PORT}" \
        --ssl-insecure \
        --showhost \
        -s "${PROJECT_ROOT}/proxy/addon.py" \
        --set confdir="/home/pipewardenuser/.mitmproxy" \
        > "${LOG_DIR}/proxy.log" 2>&1 &
else
    # Non-transparent mode
    mkdir -p ~/.mitmproxy
    cat "${CA_DIR}/ca-key.pem" "${CA_DIR}/ca.pem" > ~/.mitmproxy/mitmproxy-ca.pem

    POLICY_FILE="$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" \
    MODE="${MODE}" \
    LOG_PATH="${LOG_DIR}/connections.jsonl" \
    nohup mitmdump \
        --mode regular \
        --listen-host 127.0.0.1 \
        --listen-port "${PROXY_PORT}" \
        --ssl-insecure \
        --showhost \
        -s "${PROJECT_ROOT}/proxy/addon.py" \
        --set confdir="$HOME/.mitmproxy" \
        > "${LOG_DIR}/proxy.log" 2>&1 &
fi

PROXY_PID=$!
echo "${PROXY_PID}" > "${PID_FILE}"
echo "Proxy started with PID ${PROXY_PID}"

# Readiness check
echo "Waiting for proxy to be ready..."
for i in $(seq 1 15); do
    if nc -z 127.0.0.1 "${PROXY_PORT}" 2>/dev/null; then
        echo "Proxy is ready (port ${PROXY_PORT} open)"
        break
    fi
    if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
        echo "ERROR: Proxy process died. Log output:"
        cat "${LOG_DIR}/proxy.log" 2>/dev/null || true
        exit 1
    fi
    if [ "$i" -eq 15 ]; then
        echo "ERROR: Proxy failed to start after 15s. Log output:"
        cat "${LOG_DIR}/proxy.log" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 7. Iptables rules (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Configure iptables rules"
    sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 443 -j REDIRECT --to-port "${PROXY_PORT}"
    sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 80 -j REDIRECT --to-port "${PROXY_PORT}"
    sudo iptables -A OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: " --log-uid
    echo "iptables rules configured"
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 8. Start DNS server (runs as root for port 53)
# ---------------------------------------------------------------------------
DNS_PID=""
if [ "${ENABLE_DNS}" = "true" ]; then
    echo "::group::PipeWarden: Start DNS server"

    # Start Python DNS server as root (port 53 requires root)
    nohup sudo \
        UPSTREAM_DNS="${UPSTREAM_DNS}" \
        DNS_LISTEN_ADDR="127.0.0.53" \
        DNS_LISTEN_PORT="53" \
        POLICY_FILE="$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" \
        MODE="${MODE}" \
        LOG_PATH="${LOG_DIR}/connections.jsonl" \
        DNS_IP_MAP_PATH="${LOG_DIR}/dns_ip_map.json" \
        python3 "${PROJECT_ROOT}/proxy/dns_server.py" \
        > "${LOG_DIR}/dns.log" 2>&1 &
    DNS_PID=$!

    echo "nameserver 127.0.0.53" | sudo tee /etc/resolv.conf > /dev/null

    # Readiness check for DNS
    sleep 0.5
    for i in $(seq 1 5); do
        if nslookup example.com 127.0.0.53 &>/dev/null; then
            echo "DNS server is ready"
            break
        fi
        if [ "$i" -eq 5 ]; then
            echo "WARNING: DNS server may not be ready"
        fi
        sleep 0.5
    done
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 8b. Fail-fast watcher (enforce mode): cancel the run on first blocked conn
# ---------------------------------------------------------------------------
FAILFAST_PID=""
if [ "${FAIL_FAST}" = "true" ] && [ "${MODE}" = "enforce" ]; then
    echo "::group::PipeWarden: Fail-fast watcher"
    if [ -n "${GH_TOKEN_INPUT}" ] && [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
        nohup env \
            GH_TOKEN="${GH_TOKEN_INPUT}" \
            GITHUB_REPOSITORY="${GITHUB_REPOSITORY}" \
            GITHUB_RUN_ID="${GITHUB_RUN_ID}" \
            LOG_PATH="${LOG_DIR}/connections.jsonl" \
            python3 "${PROJECT_ROOT}/scripts/fail_fast_watcher.py" \
            > "${LOG_DIR}/failfast.log" 2>&1 &
        FAILFAST_PID=$!
        echo "Fail-fast enabled — will cancel the run on the first blocked connection (watcher PID ${FAILFAST_PID})."
    else
        echo "::warning::fail-fast requested but no github-token / run context available — falling back to fail-at-teardown."
    fi
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 9. Export environment variables to GITHUB_ENV
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Export environment variables"

CA_PATH="${CA_DIR}/ca.pem"

if [ -n "${GITHUB_ENV:-}" ]; then
    if [ "${ENABLE_TRANSPARENT}" != "true" ]; then
        echo "HTTP_PROXY=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "HTTPS_PROXY=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "http_proxy=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "https_proxy=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
    fi

    # CA trust
    echo "SSL_CERT_FILE=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "REQUESTS_CA_BUNDLE=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "CURL_CA_BUNDLE=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "GIT_SSL_CAINFO=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "NODE_EXTRA_CA_CERTS=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "NPM_CONFIG_CAFILE=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "PIP_CERT=${CA_PATH}" >> "${GITHUB_ENV}"
    echo "CARGO_HTTP_CAINFO=${CA_PATH}" >> "${GITHUB_ENV}"

    # State vars for teardown
    echo "NFW_CA_DIR=${CA_DIR}" >> "${GITHUB_ENV}"
    echo "NFW_LOG_DIR=${LOG_DIR}" >> "${GITHUB_ENV}"
    echo "NFW_PROXY_PID=${PROXY_PID}" >> "${GITHUB_ENV}"
    echo "NFW_ACTION_PATH=${ACTION_PATH}" >> "${GITHUB_ENV}"
    echo "NFW_MODE=${MODE}" >> "${GITHUB_ENV}"
    echo "NFW_POLICY_FILE=$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" >> "${GITHUB_ENV}"
    echo "NFW_PIPELINE_POLICY=${PIPELINE_POLICY_PATH}" >> "${GITHUB_ENV}"
    echo "NFW_PROXY_PORT=${PROXY_PORT}" >> "${GITHUB_ENV}"
    if [ -n "${FAILFAST_PID}" ]; then
        echo "NFW_FAILFAST_PID=${FAILFAST_PID}" >> "${GITHUB_ENV}"
    fi
    echo "NFW_TRANSPARENT=${ENABLE_TRANSPARENT}" >> "${GITHUB_ENV}"
    echo "NFW_DNS_ENABLED=${ENABLE_DNS}" >> "${GITHUB_ENV}"
    if [ -n "${DNS_PID}" ]; then
        echo "NFW_DNS_PID=${DNS_PID}" >> "${GITHUB_ENV}"
    fi
fi

echo "::endgroup::"

# ---------------------------------------------------------------------------
# 10. Status
# ---------------------------------------------------------------------------
if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    echo "::warning::PipeWarden: ALL HTTP/HTTPS traffic intercepted via iptables transparent proxy. DNS: ${ENABLE_DNS}. Mode: ${MODE}."
else
    echo "::warning::PipeWarden: HTTP/HTTPS routed via proxy env vars. DNS: ${ENABLE_DNS}. Mode: ${MODE}."
fi
