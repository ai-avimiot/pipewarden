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
FAIL_FAST="${INPUT_FAIL_FAST:-false}"
GH_TOKEN_INPUT="${INPUT_GITHUB_TOKEN:-}"
# Startup canary: true (fail setup if the intercept records nothing),
# warn (log a warning and continue), false (skip the canary).
CANARY="${INPUT_CANARY:-true}"

CA_DIR="/tmp/nfw-ca"
LOG_DIR="/tmp/monitor-logs"
PID_FILE="/tmp/nfw-proxy.pid"

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

# ---------------------------------------------------------------------------
# 7. Iptables rules (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${ENABLE_TRANSPARENT}" = "true" ]; then
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
    DNS_READY="false"
    for _ in $(seq 1 25); do
        if nslookup example.com 127.0.0.53 &>/dev/null; then
            echo "DNS server is ready"
            DNS_READY="true"
            break
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
if [ "${CANARY}" != "false" ]; then
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
    echo "NFW_FAIL_ON_BLOCK=${FAIL_ON_BLOCK}" >> "${GITHUB_ENV}"
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
