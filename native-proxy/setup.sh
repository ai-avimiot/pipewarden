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
# Enforce mode: fail the job when a connection was blocked (default), unless the
# caller opts out to block-but-continue. Consumed by teardown.
FAIL_ON_BLOCK="${INPUT_FAIL_ON_BLOCK:-true}"
PROXY_PORT="${INPUT_PROXY_PORT:-8080}"

# Validate proxy-port
if ! [[ "${PROXY_PORT}" =~ ^[0-9]+$ ]] || [ "${PROXY_PORT}" -lt 1 ] || [ "${PROXY_PORT}" -gt 65535 ]; then
    echo "ERROR: proxy-port must be a number between 1 and 65535, got '${PROXY_PORT}'" >&2
    exit 1
fi

ENABLE_DNS="${INPUT_DNS:-true}"
ACTION_PATH="${INPUT_ACTION_PATH:-.}"
ENABLE_TRANSPARENT="${INPUT_TRANSPARENT:-true}"
# TLS interception (the MITM). When false, no CA is generated or trusted and
# no proxy runs, so certificate-pinned and mutual-TLS clients work unchanged —
# at the cost of body/path/query inspection and upstream-cert verification.
# Interception cannot happen without the proxy, so disabling it also forces
# transparent mode off: the iptables redirect would point at a proxy that
# isn't there. DNS enforcement and conntrack logging are independent and stay.
ENABLE_TLS_INTERCEPT="${INPUT_TLS_INTERCEPT:-true}"
if [ "${ENABLE_TLS_INTERCEPT}" != "true" ]; then
    if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
        echo "PipeWarden: tls-intercept=false — running without MITM; DNS enforcement + connection logging only."
    fi
    ENABLE_TRANSPARENT="false"
fi
# Connection attribution: which client — and which process — made each request.
#   off      nothing recorded
#   client   the User-Agent inside the decrypted request (free, no privileges)
#   process  additionally runs a root helper that joins the kernel socket table
#            and audit connect() records, naming the actual process
# An action input rather than a policy key: it decides whether a privileged
# process runs on the runner, which is infrastructure, not allowlist policy.
ATTRIBUTION_MODE="${INPUT_ATTRIBUTION:-client}"
case "${ATTRIBUTION_MODE}" in
    off|client|process) ;;
    *)
        echo "ERROR: attribution must be one of off, client, process — got '${ATTRIBUTION_MODE}'" >&2
        exit 1
        ;;
esac
# Recording a command line can republish a token that was passed as an
# argument, so it is opt-in and scrubbed against both the job's watched values
# and the generic credential patterns before it is written anywhere.
ATTRIBUTION_CMDLINE="${INPUT_ATTRIBUTION_CMDLINE:-false}"
# client mode reads the User-Agent out of a decrypted request, which only
# exists when the proxy terminates TLS. Without interception the helper is the
# only source left, so plain client mode has nothing to report.
if [ "${ENABLE_TLS_INTERCEPT}" != "true" ] && [ "${ATTRIBUTION_MODE}" = "client" ]; then
    echo "PipeWarden: attribution=client needs TLS interception to read a User-Agent — no attribution will be recorded (use attribution: process)."
fi
FAIL_FAST="${INPUT_FAIL_FAST:-false}"
GH_TOKEN_INPUT="${INPUT_GITHUB_TOKEN:-}"
# Startup canary: true (fail setup if the intercept records nothing),
# warn (log a warning and continue), false (skip the canary).
CANARY="${INPUT_CANARY:-true}"

CA_DIR="/tmp/nfw-ca"
LOG_DIR="/tmp/monitor-logs"
PID_FILE="/tmp/nfw-proxy.pid"
# Watched secret values for payload scanning, 0600 and owned by the proxy user.
# Removed by the rollback trap and by teardown.sh.
WATCH_SECRETS_FILE="/tmp/nfw-watch-secrets.json"
# Attribution helper: a root-owned daemon answering "which process owns this
# socket". Separate from the proxy because /proc/<pid>/fd is readable only by
# the process owner or root, and the proxy deliberately does not run as root.
ATTRIBUTION_SOCKET="/tmp/nfw-attribution.sock"
ATTRIBUTION_EVENTS="/tmp/nfw-attribution-events.jsonl"
ATTRIBUTION_PID_FILE="/tmp/nfw-attribution.pid"

ACTION_PATH="$(realpath "${ACTION_PATH}")"
PROJECT_ROOT="$(dirname "${ACTION_PATH}")"

# ---------------------------------------------------------------------------
# Rollback on failure
# ---------------------------------------------------------------------------
# A partial setup must never leave the runner broken: stopping systemd-resolved
# without a replacement DNS server (or leaving iptables rules pointing at a
# dead proxy) wedges every subsequent step of the job. Any non-zero exit rolls
# back the network changes made so far.
RESOLVED_STOPPED="false"
IPTABLES_INSTALLED="false"
FORWARD_LOG_INSTALLED="false"
IP6TABLES_INSTALLED="false"
BLINDSPOT_IPV6="false"
BLINDSPOT_DOCKER="false"
RESOLV_CONF_BACKUP="/tmp/nfw-resolv.conf.bak"

rollback_on_failure() {
    local rc=$?
    [ "${rc}" -eq 0 ] && return 0
    echo "::error::PipeWarden setup failed (exit ${rc}) — rolling back network changes"
    if [ "${IPTABLES_INSTALLED}" = "true" ]; then
        sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 443 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || true
        sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 80 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || true
        sudo iptables -D OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: " --log-uid 2>/dev/null || true
        # Enforce-mode protocol blocks (no-ops if they were never added).
        sudo iptables -D OUTPUT -p udp --dport 443 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
        sudo iptables -D OUTPUT -p tcp --dport 853 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with tcp-reset 2>/dev/null || true
        sudo iptables -D OUTPUT -p udp --dport 853 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
    fi
    if [ "${FORWARD_LOG_INSTALLED}" = "true" ]; then
        sudo iptables -D FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-FWD: " 2>/dev/null || true
    fi
    if [ "${IP6TABLES_INSTALLED}" = "true" ]; then
        sudo ip6tables -D OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN6: " --log-uid 2>/dev/null || true
        sudo ip6tables -D OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser -m multiport --dports 80,443,853 -j REJECT --reject-with tcp-reset 2>/dev/null || true
        sudo ip6tables -D OUTPUT -p udp -m owner ! --uid-owner pipewardenuser -m multiport --dports 443,853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
    fi
    sudo pkill -f "proxy/dns_server.py" 2>/dev/null || true
    sudo pkill -f "mitmdump" 2>/dev/null || true
    # SIGTERM rather than SIGKILL: the helper deletes its audit rule on the way
    # out, and a rule left installed outlives the job that added it.
    if [ -f "${ATTRIBUTION_PID_FILE}" ]; then
        sudo kill -TERM "$(cat "${ATTRIBUTION_PID_FILE}")" 2>/dev/null || true
        sleep 1
        sudo pkill -f "attribution_helper.py" 2>/dev/null || true
        sudo rm -f "${ATTRIBUTION_PID_FILE}" 2>/dev/null || true
    fi
    sudo rm -f "${ATTRIBUTION_SOCKET}" 2>/dev/null || true
    # Secret values must not outlive the proxy that needed them.
    sudo rm -f "${WATCH_SECRETS_FILE}" 2>/dev/null || true
    if [ "${RESOLVED_STOPPED}" = "true" ]; then
        if [ -f "${RESOLV_CONF_BACKUP}" ]; then
            sudo cp "${RESOLV_CONF_BACKUP}" /etc/resolv.conf 2>/dev/null || true
        fi
        sudo systemctl start systemd-resolved 2>/dev/null || true
    fi
    echo "Rollback complete — runner DNS and firewall restored"
}
trap rollback_on_failure EXIT

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
if [ "${ENABLE_TLS_INTERCEPT}" != "true" ]; then
    echo "TLS interception disabled — skipping proxy install (no MITM will run)."
elif [ "${ENABLE_TRANSPARENT}" = "true" ]; then
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
# 2 + 3. Generate and trust the per-job CA — only when intercepting.
# ---------------------------------------------------------------------------
# The CA exists solely to sign the forged leaf certificates the proxy presents.
# With no proxy, generating a key and writing it into the system trust store
# would be pure attack surface for no benefit — so both are skipped, and a
# pinned client sees the real certificate chain exactly as it expects.
if [ "${ENABLE_TLS_INTERCEPT}" = "true" ]; then
    echo "::group::PipeWarden: Generate CA certificate"
    python3 "${PROJECT_ROOT}/scripts/generate_ca.py" --out "${CA_DIR}"
    chmod 600 "${CA_DIR}/ca-key.pem"
    echo "::endgroup::"

    echo "::group::PipeWarden: Install CA into trust store"
    sudo cp "${CA_DIR}/ca.pem" /usr/local/share/ca-certificates/nfw-ca.crt
    sudo update-ca-certificates > /dev/null 2>&1 || echo "Warning: update-ca-certificates failed"
    echo "::endgroup::"
fi

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
    # systemd-resolved is stopped later, in step 8, immediately before the
    # replacement DNS server starts — never before the proxy is confirmed up.
    # Stopping it here turned a failed proxy start into a runner with no
    # resolver at all (job wedged until GitHub cancelled it).
fi

# ---------------------------------------------------------------------------
# 6. Start proxy (Go binary handles proxy + DNS in one process)
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Start proxy"
mkdir -p "${LOG_DIR}"
PROXY_PID=""

# Hand the watched secret values to the proxy. sudo strips the environment and
# the `env` below passes only a few variables, so without this the env-secrets
# detector resolves an empty watchlist and silently detects nothing. A file
# rather than argv: /proc/<pid>/cmdline is world-readable.
#
# Written before the mode branch because the attribution helper needs the same
# watchlist to scrub command lines, and it starts before the proxy does.
#
# Remove any leftover first: a job cancelled before teardown leaves the file
# owned by pipewardenuser, the writer (running as the runner user) then can't
# replace it, and chowning the leftover would hand the proxy the PREVIOUS job's
# secrets. The writer creates it O_EXCL, so a fresh path is a precondition, and
# on any failure the path is scrubbed rather than half-trusted.
WATCH_SECRETS_WRITTEN="false"
sudo rm -f "${WATCH_SECRETS_FILE}" 2>/dev/null || true
if python3 "${PROJECT_ROOT}/scripts/write_watch_secrets.py" \
    "${POLICY_FILE}" "${WATCH_SECRETS_FILE}"; then
    WATCH_SECRETS_WRITTEN="true"
else
    echo "Warning: could not materialise watched secrets — env-secrets detection will be inactive this run"
    sudo rm -f "${WATCH_SECRETS_FILE}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 5b. Attribution helper (process mode only)
# ---------------------------------------------------------------------------
# Started before the proxy on purpose: the addon stops querying a helper that
# refuses several connections in a row, and the startup canary generates
# traffic immediately. A helper that came up late would be written off before
# it ever answered.
#
# Runs as root because /proc/<pid>/fd is readable only by the process owner or
# root, and build steps run as the runner user while the proxy runs as
# pipewardenuser. The privilege lives in this one small process rather than
# being handed to mitmproxy.
if [ "${ATTRIBUTION_MODE}" = "process" ]; then
    sudo rm -f "${ATTRIBUTION_SOCKET}" "${ATTRIBUTION_EVENTS}" 2>/dev/null || true

    # Whoever the proxy runs as needs to reach the socket; nobody else does.
    if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
        ATTRIBUTION_GROUP="pipewardenuser"
    else
        ATTRIBUTION_GROUP="$(id -gn)"
    fi

    ATTRIBUTION_ARGS=(
        --socket "${ATTRIBUTION_SOCKET}"
        --events "${ATTRIBUTION_EVENTS}"
        --group "${ATTRIBUTION_GROUP}"
        --policy "$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")"
    )
    # The proxy's own upstream connections are not the build's traffic;
    # attributing every request to mitmdump would be worse than nothing. Only
    # transparent mode can express that as a uid, though — there the proxy runs
    # as pipewardenuser, while explicit-proxy mode runs it as the runner user,
    # the very user the build steps use. Passing the runner's own uid here would
    # discard the whole job's traffic instead of the proxy's.
    if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
        ATTRIBUTION_ARGS+=(--ignore-user "pipewardenuser")
    elif [ "${ENABLE_TLS_INTERCEPT}" = "true" ]; then
        echo "PipeWarden: transparent=false runs the proxy as $(id -un), the same user as the build —"
        echo "  connect() records cannot be told apart, so audit-tier attribution is off; socket lookups still work."
        ATTRIBUTION_ARGS+=(--no-audit)
    fi
    if [ "${ATTRIBUTION_CMDLINE}" = "true" ] && [ "${WATCH_SECRETS_WRITTEN}" = "true" ]; then
        ATTRIBUTION_ARGS+=(--include-cmdline --secrets "${WATCH_SECRETS_FILE}")
    elif [ "${ATTRIBUTION_CMDLINE}" = "true" ]; then
        # Without the watchlist the redactor loses the job's own secret values
        # and keeps only the generic patterns. Recording argv anyway would
        # publish exactly the token the watchlist exists to catch.
        echo "Warning: attribution-cmdline=true but no watched-secrets file — command lines will NOT be recorded."
    fi

    nohup sudo python3 "${PROJECT_ROOT}/scripts/attribution_helper.py" \
        "${ATTRIBUTION_ARGS[@]}" \
        > "${LOG_DIR}/attribution.log" 2>&1 &
    echo "$!" > "${ATTRIBUTION_PID_FILE}"

    # Wait for the socket rather than assume it: a helper that failed to open
    # netlink should degrade to client-only attribution here, not surface as a
    # slow timeout on every request for the rest of the job.
    ATTRIBUTION_READY="false"
    for _ in $(seq 1 25); do
        if [ -S "${ATTRIBUTION_SOCKET}" ]; then
            ATTRIBUTION_READY="true"
            break
        fi
        sleep 0.2
    done

    if [ "${ATTRIBUTION_READY}" = "true" ]; then
        echo "Attribution helper ready (${ATTRIBUTION_SOCKET})"
    else
        echo "::warning::PipeWarden: attribution helper did not start — falling back to client attribution"
        [ -s "${LOG_DIR}/attribution.log" ] && cat "${LOG_DIR}/attribution.log"
        sudo pkill -f "attribution_helper.py" 2>/dev/null || true
        sudo rm -f "${ATTRIBUTION_PID_FILE}" 2>/dev/null || true
        # Attribution is diagnostics. Losing it must not fail the job or take
        # egress control down with it.
        ATTRIBUTION_MODE="client"
    fi
fi

# The addon reads these; process mode without a socket downgrades itself.
export ATTRIBUTION_MODE
if [ "${ATTRIBUTION_MODE}" = "process" ]; then
    export ATTRIBUTION_SOCKET
else
    ATTRIBUTION_SOCKET=""
    export ATTRIBUTION_SOCKET
fi

if [ "${ENABLE_TLS_INTERCEPT}" != "true" ]; then
    # No MITM: nothing to launch. The connection log is still created so the
    # DNS server and conntrack merge have somewhere to write, and so teardown
    # and the report generator find the file they expect.
    touch "${LOG_DIR}/connections.jsonl"
    echo "No proxy started (tls-intercept=false)."
    echo "::endgroup::"
elif [ "${ENABLE_TRANSPARENT}" = "true" ]; then
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

    # Ensure addon.py and the policy package it imports are readable.
    # addon.py does `from policy.matcher import ...` — if policy/ is not
    # readable by pipewardenuser the addon fails to load and mitmproxy
    # records nothing.
    sudo chmod -R o+rX "${PROJECT_ROOT}/proxy" 2>/dev/null || true
    sudo chmod -R o+rX "${PROJECT_ROOT}/policy" 2>/dev/null || true
    sudo chmod o+r "$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" 2>/dev/null || true
    CURRENT_DIR="${PROJECT_ROOT}"
    while [ "${CURRENT_DIR}" != "/" ]; do
        sudo chmod o+rx "${CURRENT_DIR}" 2>/dev/null || true
        CURRENT_DIR="$(dirname "${CURRENT_DIR}")"
    done

    if [ "${WATCH_SECRETS_WRITTEN}" = "true" ]; then
        sudo chown pipewardenuser "${WATCH_SECRETS_FILE}" 2>/dev/null || true
    fi

    MITMDUMP_PATH="$(command -v mitmdump)"
    nohup sudo -u pipewardenuser \
        env POLICY_FILE="$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" \
            MODE="${MODE}" \
            LOG_PATH="${LOG_DIR}/connections.jsonl" \
            EXFIL_SECRETS_FILE="${WATCH_SECRETS_FILE}" \
            ATTRIBUTION_MODE="${ATTRIBUTION_MODE}" \
            ATTRIBUTION_SOCKET="${ATTRIBUTION_SOCKET}" \
        "${MITMDUMP_PATH}" \
        --mode transparent \
        --listen-host 0.0.0.0 \
        --listen-port "${PROXY_PORT}" \
        --ssl-insecure \
        --showhost \
        -s "${PROJECT_ROOT}/proxy/addon.py" \
        --set confdir="/home/pipewardenuser/.mitmproxy" \
        > "${LOG_DIR}/proxy.log" 2>&1 &
    PROXY_PID=$!
    echo "${PROXY_PID}" > "${PID_FILE}"
    echo "Proxy started with PID ${PROXY_PID}"
else
    # Non-transparent mode
    mkdir -p ~/.mitmproxy
    cat "${CA_DIR}/ca-key.pem" "${CA_DIR}/ca.pem" > ~/.mitmproxy/mitmproxy-ca.pem

    POLICY_FILE="$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" \
    MODE="${MODE}" \
    LOG_PATH="${LOG_DIR}/connections.jsonl" \
    ATTRIBUTION_MODE="${ATTRIBUTION_MODE}" \
    ATTRIBUTION_SOCKET="${ATTRIBUTION_SOCKET}" \
    nohup mitmdump \
        --mode regular \
        --listen-host 127.0.0.1 \
        --listen-port "${PROXY_PORT}" \
        --ssl-insecure \
        --showhost \
        -s "${PROJECT_ROOT}/proxy/addon.py" \
        --set confdir="$HOME/.mitmproxy" \
        > "${LOG_DIR}/proxy.log" 2>&1 &
    PROXY_PID=$!
    echo "${PROXY_PID}" > "${PID_FILE}"
    echo "Proxy started with PID ${PROXY_PID}"
fi

# Readiness check. Skipped when no proxy was started (tls-intercept=false):
# there is no port to poll and no process whose absence would be an error.
if [ -n "${PROXY_PID}" ]; then

# Readiness check.
# Liveness uses ps, not `kill -0`: in transparent mode the tracked PID is a
# root-owned sudo wrapper, and `kill -0` from the runner user races sudo's
# uid switch — for the first few milliseconds the process is signalable,
# then EPERM, which reads as "process died" while mitmdump is fine. The
# sleep also comes before the liveness verdict so the proxy gets at least
# one second of grace before being declared dead.
dump_proxy_log() {
    if [ -s "${LOG_DIR}/proxy.log" ]; then
        cat "${LOG_DIR}/proxy.log"
    else
        echo "(proxy.log is empty)"
    fi
}

echo "Waiting for proxy to be ready..."
PROXY_READY="false"
# Poll the port at 0.2s so startup latency (typically ~1s) isn't rounded up
# to a whole second; still bounded to ~20s (100 * 0.2s). Liveness is checked
# each iteration so a dead proxy fails fast rather than waiting out the budget.
for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 "${PROXY_PORT}" 2>/dev/null; then
        echo "Proxy is ready (port ${PROXY_PORT} open)"
        PROXY_READY="true"
        break
    fi
    if ! ps -p "${PROXY_PID}" > /dev/null 2>&1; then
        PROXY_EXIT=0
        wait "${PROXY_PID}" 2>/dev/null || PROXY_EXIT=$?
        echo "ERROR: Proxy process exited during startup (exit code ${PROXY_EXIT}). Log output:"
        dump_proxy_log
        exit 1
    fi
    sleep 0.2
done
if [ "${PROXY_READY}" != "true" ]; then
    echo "ERROR: Proxy failed to open port ${PROXY_PORT} after 20s. Log output:"
    dump_proxy_log
    exit 1
fi

# The port check alone is not proof of life: mitmproxy briefly opens the
# port and then exits when the addon script fails to load. A proxy without
# the addon would record and enforce nothing, so treat both cases as fatal.
# Poll for up to ~1.5s: fail the instant an addon error surfaces, otherwise
# accept once the process has stayed up a few polls (no fixed full-second wait).
STABLE_POLLS=0
for _ in $(seq 1 15); do
    if grep -qiE "error in script|ScriptError" "${LOG_DIR}/proxy.log" 2>/dev/null; then
        echo "ERROR: Proxy engine reported an addon script error — connections would not be logged or enforced. Log output:"
        dump_proxy_log
        exit 1
    fi
    if ! ps -p "${PROXY_PID}" > /dev/null 2>&1; then
        echo "ERROR: Proxy exited right after opening its port (usually an addon load failure). Log output:"
        dump_proxy_log
        exit 1
    fi
    STABLE_POLLS=$((STABLE_POLLS + 1))
    [ "${STABLE_POLLS}" -ge 3 ] && break
    sleep 0.1
done
echo "::endgroup::"
fi  # end readiness (proxy started)

# ---------------------------------------------------------------------------
# 7. Iptables rules (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${ENABLE_TLS_INTERCEPT}" != "true" ]; then
    # No proxy to redirect into, so no REDIRECT and no proxy-user exemption —
    # but conntrack logging still gives connection-level visibility (dst IP,
    # port, uid) for every NEW outbound flow. This is the harden-runner-style
    # posture: see who was contacted, without reading what was sent. DNS-layer
    # enforcement is added separately in section 8.
    echo "::group::PipeWarden: Configure connection logging (no interception)"
    if sudo iptables -A OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: " --log-uid 2>/dev/null; then
        IPTABLES_INSTALLED="true"
        echo "Connection logging enabled (no TLS interception)."
    else
        echo "::warning::could not add connection log rule — outbound connections will not be logged this run."
    fi
    if command -v ip6tables &>/dev/null; then
        sudo ip6tables -A OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN6: " --log-uid 2>/dev/null \
            && IP6TABLES_INSTALLED="true" || true
    fi
    echo "::endgroup::"
elif [ "${ENABLE_TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Configure iptables rules"
    sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 443 -j REDIRECT --to-port "${PROXY_PORT}"
    sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 80 -j REDIRECT --to-port "${PROXY_PORT}"
    sudo iptables -A OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: " --log-uid
    IPTABLES_INSTALLED="true"

    # Enforce mode: close the protocol-level bypasses of the TCP 80/443 proxy.
    # These are NOT redirected into the proxy (it speaks TCP HTTP/HTTPS), so
    # the only safe enforce action is to reject them, which also forces clients
    # to fall back to the interceptable TCP path:
    #   - QUIC / HTTP-3 over UDP 443 (browsers, google/cloudflare SDKs, and
    #     increasingly package managers negotiate this automatically whenever
    #     UDP 443 is open, sailing straight past a TCP-only proxy)
    #   - DNS-over-TLS / DNS-over-QUIC on 853 (bypasses the DNS interceptor)
    # Monitor mode leaves them alone (nothing is ever blocked in monitor).
    if [ "${MODE}" = "enforce" ]; then
        sudo iptables -A OUTPUT -p udp --dport 443 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with icmp-port-unreachable
        sudo iptables -A OUTPUT -p tcp --dport 853 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with tcp-reset
        sudo iptables -A OUTPUT -p udp --dport 853 -m owner ! --uid-owner pipewardenuser -j REJECT --reject-with icmp-port-unreachable
        echo "Enforce: blocked QUIC (udp/443) and DoT/DoQ (853) to force interceptable TCP"
    fi

    # Visibility for the known interception blind spots. Log-only (never
    # blocks), so it is safe to add unconditionally where the tooling exists:
    #   - FORWARD: egress from Docker containers a job launches traverses
    #     FORWARD, not OUTPUT, so it is otherwise invisible. Logging it means
    #     container traffic at least shows up as IP metadata in the report.
    #   - ip6tables: IPv6 egress bypasses the IPv4-only rules entirely. A LOG
    #     rule makes it visible; enforce mode additionally rejects uninspected
    #     IPv6 web/DoT below (fail-closed) since the proxy is IPv4-only.
    sudo iptables -A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-FWD: " 2>/dev/null \
        && FORWARD_LOG_INSTALLED="true" || echo "Note: could not add FORWARD log rule (container egress will be invisible)"

    if command -v ip6tables &>/dev/null; then
        if sudo ip6tables -A OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN6: " --log-uid 2>/dev/null; then
            IP6TABLES_INSTALLED="true"
            if [ "${MODE}" = "enforce" ]; then
                # Proxy is IPv4-only, so uninspected IPv6 web/DoT is fail-closed.
                sudo ip6tables -A OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser -m multiport --dports 80,443,853 -j REJECT --reject-with tcp-reset 2>/dev/null || true
                sudo ip6tables -A OUTPUT -p udp -m owner ! --uid-owner pipewardenuser -m multiport --dports 443,853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
                echo "Enforce: rejected uninspected IPv6 web/DoT (proxy is IPv4-only)"
            fi
        fi
    fi

    echo "iptables rules configured"
    echo "::endgroup::"

    # ---------------------------------------------------------------------
    # 7a. Interception blind-spot detection — make the gaps loud, not silent
    # ---------------------------------------------------------------------
    # These are recorded to GITHUB_ENV so teardown surfaces them in health.json
    # and the job summary. IPv6 and container egress are only partially covered
    # (logged, and rejected in enforce), and a user relying on enforce should
    # know that up front rather than discover it in an incident.
    BLINDSPOT_IPV6="false"
    BLINDSPOT_DOCKER="false"
    if ip -6 route show default 2>/dev/null | grep -q .; then
        BLINDSPOT_IPV6="true"
        if [ "${MODE}" = "enforce" ]; then
            echo "::warning::PipeWarden: this runner has IPv6 egress. The proxy is IPv4-only; IPv6 HTTP/HTTPS/DoT is logged and rejected in enforce mode, but never TLS-inspected."
        else
            echo "::warning::PipeWarden: this runner has IPv6 egress. The proxy is IPv4-only; IPv6 HTTP/HTTPS is logged but NOT inspected (monitor mode blocks nothing)."
        fi
    fi
    if ip -o link show type bridge 2>/dev/null | grep -qiE 'docker0|br-'; then
        BLINDSPOT_DOCKER="true"
        echo "::warning::PipeWarden: a Docker bridge is present. Egress from containers a job launches traverses FORWARD, not OUTPUT — it is logged as IP metadata but NOT TLS-inspected or policy-enforced."
    fi
fi

# ---------------------------------------------------------------------------
# 8. Start DNS server (runs as root for port 53)
# ---------------------------------------------------------------------------
DNS_PID=""
if [ "${ENABLE_DNS}" = "true" ]; then
    echo "::group::PipeWarden: Start DNS server"

    # DNS takeover happens only now, with the proxy confirmed up, and as one
    # transactional unit: back up resolv.conf, stop systemd-resolved, start
    # the replacement server. Any failure from here on rolls back via the
    # EXIT trap so the runner is never left without a resolver.
    sudo cp -L /etc/resolv.conf "${RESOLV_CONF_BACKUP}" 2>/dev/null || true
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo "Stopping systemd-resolved..."
        sudo systemctl stop systemd-resolved
        RESOLVED_STOPPED="true"
    fi

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

    # Readiness check for DNS. Fatal on failure: a runner whose only
    # resolver is a dead DNS server cannot finish the job anyway, so fail
    # here while the EXIT trap can still restore systemd-resolved.
    #
    # "Ready" means the server answered, not that it said yes. dns_server.py
    # short-circuits this name (READINESS_PROBE_NAME) ahead of policy
    # evaluation and returns NXDOMAIN, so the check reports on the server
    # rather than on the user's allowlist. Probing a real domain instead
    # conflated the two: under enforce, the policy NXDOMAINs it and setup
    # died claiming the DNS server never started.
    DNS_PROBE_NAME="readiness.pipewarden.invalid"
    DNS_READY="false"
    for _ in $(seq 1 25); do
        # dig exits 0 whenever it got a reply — NXDOMAIN included — and 9 when
        # the server did not answer, which is exactly the distinction needed.
        if command -v dig &>/dev/null; then
            if dig +time=2 +tries=1 @127.0.0.53 "${DNS_PROBE_NAME}" &>/dev/null; then
                echo "DNS server is ready"
                DNS_READY="true"
                break
            fi
        else
            # nslookup returns non-zero for NXDOMAIN too, so its exit code
            # cannot be used; separate "answered" from "unreachable" by output.
            NS_OUT="$(nslookup "${DNS_PROBE_NAME}" 127.0.0.53 2>&1 || true)"
            if ! printf '%s' "${NS_OUT}" | grep -qiE \
                'connection refused|no servers could be reached|timed out|no response'; then
                echo "DNS server is ready"
                DNS_READY="true"
                break
            fi
        fi
        sleep 0.2
    done
    if [ "${DNS_READY}" != "true" ]; then
        echo "ERROR: DNS server did not become ready. Log output:"
        cat "${LOG_DIR}/dns.log" 2>/dev/null || true
        exit 1
    fi
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 8a. Startup canary — prove the intercept actually records traffic
# ---------------------------------------------------------------------------
# A proxy that is up but not capturing (addon failure, iptables rules not
# matching, dead DNS) renders a report identical to a clean run. Make one
# real request and require it to appear in the connection log before
# declaring setup healthy. Runs before the fail-fast watcher on purpose: a
# canary blocked by an enforce policy still proves logging works, and must
# not cancel the run.
if [ "${ENABLE_TLS_INTERCEPT}" != "true" ]; then
    # The canary proves the PROXY leg records traffic. With no proxy there is
    # no such leg to prove — conntrack logging is verified separately at
    # teardown — so running it would always fail. Skip, don't weaken.
    echo "Startup canary skipped (tls-intercept=false — no proxy leg to verify)."
elif [ "${CANARY}" != "false" ]; then
    echo "::group::PipeWarden: Startup canary"
    CANARY_HOST="api.github.com"
    if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
        # Resolve the canary IP against the upstream resolver directly and pin
        # it with --resolve: an enforce policy may NXDOMAIN the canary host at
        # the DNS leg, and the point here is to exercise the proxy leg. The
        # SNI still carries the hostname, so the proxy logs (and may block)
        # it either way — a blocked canary entry passes the check too.
        CANARY_IP=""
        if [ -n "${UPSTREAM_DNS}" ] && command -v dig &>/dev/null; then
            CANARY_IP="$(dig +short +time=3 +tries=1 @"${UPSTREAM_DNS%%,*}" A "${CANARY_HOST}" 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
        fi
        if [ -n "${CANARY_IP}" ]; then
            curl --silent --show-error --max-time 15 --output /dev/null \
                --resolve "${CANARY_HOST}:443:${CANARY_IP}" "https://${CANARY_HOST}/" \
                || echo "Canary request failed (not fatal by itself — checking the connection log)"
        else
            curl --silent --show-error --max-time 15 --output /dev/null "https://${CANARY_HOST}/" \
                || echo "Canary request failed (not fatal by itself — checking the connection log)"
        fi
    else
        curl --silent --show-error --max-time 15 --output /dev/null \
            --proxy "http://127.0.0.1:${PROXY_PORT}" "https://${CANARY_HOST}/" \
            || echo "Canary request failed (not fatal by itself — checking the connection log)"
    fi
    # Poll for the canary entry (the proxy writes it a beat after the request
    # returns) instead of a flat 1s wait — break as soon as it lands.
    CANARY_SEEN="false"
    for _ in $(seq 1 10); do
        if grep "\"host\": \"${CANARY_HOST}\"" "${LOG_DIR}/connections.jsonl" 2>/dev/null | grep -q '"protocol": "https"'; then
            CANARY_SEEN="true"
            break
        fi
        sleep 0.1
    done
    if [ "${CANARY_SEEN}" = "true" ]; then
        echo "Canary OK — ${CANARY_HOST} was recorded by the proxy leg"
        # Drop startup noise (including the canary itself) so the report and
        # enforce-mode blocked counts reflect only the job's own traffic.
        # Truncation (not re-creation) keeps ownership and permissions.
        : > "${LOG_DIR}/connections.jsonl"
    else
        echo "Canary request to ${CANARY_HOST} was NOT recorded by the proxy leg."
        echo "The intercept is not capturing traffic — the job would run unmonitored."
        echo "Proxy log tail:"
        tail -n 50 "${LOG_DIR}/proxy.log" 2>/dev/null || true
        if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
            echo "iptables nat OUTPUT counters (packets column shows whether the REDIRECT matched):"
            sudo iptables -t nat -L OUTPUT -v -n 2>/dev/null || true
        fi
        if [ "${CANARY}" = "warn" ]; then
            echo "::warning::PipeWarden startup canary failed — the proxy leg is not recording traffic (canary: warn, continuing)."
        else
            echo "::error::PipeWarden startup canary failed — the proxy leg is not recording traffic. Set canary: warn to continue without this guarantee."
            exit 1
        fi
    fi
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
    # Env-var proxy mode: non-transparent but still intercepting. When
    # interception is off there is no proxy to point at, so these must not be
    # exported — otherwise every client would try to reach a dead port.
    if [ "${ENABLE_TRANSPARENT}" != "true" ] && [ "${ENABLE_TLS_INTERCEPT}" = "true" ]; then
        echo "HTTP_PROXY=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "HTTPS_PROXY=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "http_proxy=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
        echo "https_proxy=http://127.0.0.1:${PROXY_PORT}" >> "${GITHUB_ENV}"
    fi

    # CA trust — only when intercepting. With no forged certs, pointing clients
    # at a CA that signed nothing would at best do nothing and at worst make a
    # pinned client that reads these vars distrust the real chain.
    if [ "${ENABLE_TLS_INTERCEPT}" = "true" ]; then
        echo "SSL_CERT_FILE=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "REQUESTS_CA_BUNDLE=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "CURL_CA_BUNDLE=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "GIT_SSL_CAINFO=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "NODE_EXTRA_CA_CERTS=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "NPM_CONFIG_CAFILE=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "PIP_CERT=${CA_PATH}" >> "${GITHUB_ENV}"
        echo "CARGO_HTTP_CAINFO=${CA_PATH}" >> "${GITHUB_ENV}"
    fi

    # State vars for teardown
    echo "NFW_CA_DIR=${CA_DIR}" >> "${GITHUB_ENV}"
    echo "NFW_LOG_DIR=${LOG_DIR}" >> "${GITHUB_ENV}"
    echo "NFW_PROXY_PID=${PROXY_PID}" >> "${GITHUB_ENV}"
    echo "NFW_ACTION_PATH=${ACTION_PATH}" >> "${GITHUB_ENV}"
    echo "NFW_MODE=${MODE}" >> "${GITHUB_ENV}"
    echo "NFW_FAIL_ON_BLOCK=${FAIL_ON_BLOCK}" >> "${GITHUB_ENV}"
    echo "NFW_POLICY_FILE=$(realpath "${POLICY_FILE}" 2>/dev/null || echo "${POLICY_FILE}")" >> "${GITHUB_ENV}"
    echo "NFW_PIPELINE_POLICY=${PIPELINE_POLICY_PATH}" >> "${GITHUB_ENV}"
    # Teardown's cleanup reads this; without it the removal only works while
    # the path happens to match teardown's hardcoded default.
    echo "NFW_WATCH_SECRETS_FILE=${WATCH_SECRETS_FILE}" >> "${GITHUB_ENV}"
    echo "NFW_PROXY_PORT=${PROXY_PORT}" >> "${GITHUB_ENV}"
    # Reflects what is actually running, not what was asked for: a helper that
    # failed to start has already downgraded this to client.
    echo "NFW_ATTRIBUTION_MODE=${ATTRIBUTION_MODE}" >> "${GITHUB_ENV}"
    echo "NFW_ATTRIBUTION_SOCKET=${ATTRIBUTION_SOCKET}" >> "${GITHUB_ENV}"
    echo "NFW_ATTRIBUTION_EVENTS=${ATTRIBUTION_EVENTS}" >> "${GITHUB_ENV}"
    echo "NFW_ATTRIBUTION_PID_FILE=${ATTRIBUTION_PID_FILE}" >> "${GITHUB_ENV}"
    if [ -n "${FAILFAST_PID}" ]; then
        echo "NFW_FAILFAST_PID=${FAILFAST_PID}" >> "${GITHUB_ENV}"
    fi
    echo "NFW_TRANSPARENT=${ENABLE_TRANSPARENT}" >> "${GITHUB_ENV}"
    echo "NFW_TLS_INTERCEPT=${ENABLE_TLS_INTERCEPT}" >> "${GITHUB_ENV}"
    # Whether a conntrack LOG rule is live and needs flushing + parsing at
    # teardown. True in transparent mode and in intercept-off logging mode;
    # decoupled from TRANSPARENT so the intercept-off path is handled too.
    echo "NFW_CONN_LOGGING=${IPTABLES_INSTALLED}" >> "${GITHUB_ENV}"
    echo "NFW_DNS_ENABLED=${ENABLE_DNS}" >> "${GITHUB_ENV}"
    if [ -n "${DNS_PID}" ]; then
        echo "NFW_DNS_PID=${DNS_PID}" >> "${GITHUB_ENV}"
    fi
    # Which hardening rules were installed (so teardown removes exactly those)
    # and which interception blind spots this runner exposes (so teardown
    # surfaces them in health.json).
    echo "NFW_FORWARD_LOG=${FORWARD_LOG_INSTALLED}" >> "${GITHUB_ENV}"
    echo "NFW_IP6TABLES=${IP6TABLES_INSTALLED}" >> "${GITHUB_ENV}"
    echo "NFW_BLINDSPOT_IPV6=${BLINDSPOT_IPV6}" >> "${GITHUB_ENV}"
    echo "NFW_BLINDSPOT_DOCKER=${BLINDSPOT_DOCKER}" >> "${GITHUB_ENV}"
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

# Setup finished — disarm the failure rollback.
trap - EXIT
