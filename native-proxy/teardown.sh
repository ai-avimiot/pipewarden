#!/bin/bash
# teardown.sh — Native proxy firewall teardown for GitHub Actions runners.
#
# Stops the mitmproxy background process and DNS server, generates
# reports from the connection log, writes the GitHub Job Summary,
# and cleans up.
set -euo pipefail

# ---------------------------------------------------------------------------
# Read state from environment variables set by setup.sh
# ---------------------------------------------------------------------------
PROXY_PID="${NFW_PROXY_PID:-}"
DNS_PID="${NFW_DNS_PID:-}"
DNS_ENABLED="${NFW_DNS_ENABLED:-false}"
LOG_DIR="${NFW_LOG_DIR:-/tmp/monitor-logs}"
CA_DIR="${NFW_CA_DIR:-/tmp/nfw-ca}"
MODE="${NFW_MODE:-monitor}"
POLICY_FILE="${NFW_POLICY_FILE:-}"
ACTION_PATH="${NFW_ACTION_PATH:-${INPUT_ACTION_PATH:-.}}"
TRANSPARENT="${NFW_TRANSPARENT:-false}"

# The project root is one level up from native-proxy/
PROJECT_ROOT="$(dirname "${ACTION_PATH}")"
REPORT_DIR="/tmp/report"

# ---------------------------------------------------------------------------
# 0. Capture intercept health while the processes are still (maybe) alive
# ---------------------------------------------------------------------------
# Recorded before anything is stopped so the report can distinguish "clean
# run with no traffic" from "the intercept died and monitored nothing".
PROXY_ALIVE_AT_TEARDOWN="no"
if pgrep -f "mitmdump" > /dev/null 2>&1; then
    PROXY_ALIVE_AT_TEARDOWN="yes"
fi
DNS_ALIVE_AT_TEARDOWN="disabled"
if [ "${DNS_ENABLED}" = "true" ]; then
    DNS_ALIVE_AT_TEARDOWN="no"
    if pgrep -f "dns_server.py" > /dev/null 2>&1; then
        DNS_ALIVE_AT_TEARDOWN="yes"
    fi
fi

# ---------------------------------------------------------------------------
# 0.5. Stop fail-fast watcher (if running)
# ---------------------------------------------------------------------------
if [ -n "${NFW_FAILFAST_PID:-}" ] && kill -0 "${NFW_FAILFAST_PID}" 2>/dev/null; then
    kill -TERM "${NFW_FAILFAST_PID}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 1. Stop proxy process
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Stop proxy"
# In transparent mode the tracked PID is a root-owned sudo wrapper: liveness
# must use ps (kill -0 gets EPERM and reads as "already exited") and the
# signal must be sent with sudo (an unprivileged kill fails silently).
proxy_kill() {
    if [ "${TRANSPARENT}" = "true" ]; then
        sudo kill "$@" 2>/dev/null
    else
        kill "$@" 2>/dev/null
    fi
}
if [ -n "${PROXY_PID}" ] && ps -p "${PROXY_PID}" > /dev/null 2>&1; then
    echo "Stopping proxy (PID ${PROXY_PID})..."
    proxy_kill -TERM "${PROXY_PID}" || true

    for i in $(seq 1 10); do
        if ! ps -p "${PROXY_PID}" > /dev/null 2>&1; then
            echo "Proxy stopped gracefully"
            break
        fi
        if [ "$i" -eq 10 ]; then
            echo "Proxy did not stop gracefully, sending SIGKILL"
            proxy_kill -9 "${PROXY_PID}" || true
        fi
        sleep 0.5
    done
else
    echo "Warning: Proxy PID not found or already exited"
fi
# The sudo wrapper's mitmdump child can outlive the wrapper.
if [ "${TRANSPARENT}" = "true" ]; then
    sudo pkill -f "mitmdump" 2>/dev/null || true
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 1.5. Flush iptables rules (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Remove iptables rules"
    PROXY_PORT="${NFW_PROXY_PORT:-8080}"
    sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 443 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || \
    sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner mitmproxyuser --dport 443 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || echo "Warning: Failed to delete NAT rule for port 443"
    sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner pipewardenuser --dport 80 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || \
    sudo iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner mitmproxyuser --dport 80 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null || echo "Warning: Failed to delete NAT rule for port 80"
    sudo iptables -D OUTPUT -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: " --log-uid 2>/dev/null || echo "Warning: Failed to delete LOG rule"
    echo "iptables rules removed"
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 2. Stop DNS server and restore system DNS
# ---------------------------------------------------------------------------
if [ "${DNS_ENABLED}" = "true" ]; then
    echo "::group::PipeWarden: Stop DNS server"

    # Kill any remaining DNS processes that didn't exit with the parent.
    sudo pkill -f "dns_server.py" 2>/dev/null || true

    # Restore systemd-resolved
    if command -v systemctl &>/dev/null; then
        echo "Restoring systemd-resolved..."
        sudo systemctl start systemd-resolved 2>/dev/null || true
        # Wait for it to be ready
        sleep 0.5
    fi

    echo "DNS server stopped, system DNS restored"
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 3. Ensure connection log exists
# ---------------------------------------------------------------------------
CONN_LOG="${LOG_DIR}/connections.jsonl"
if [ ! -f "${CONN_LOG}" ]; then
    echo "Warning: Connection log not found, creating empty log"
    mkdir -p "${LOG_DIR}"
    touch "${CONN_LOG}"
fi

# ---------------------------------------------------------------------------
# 3.5. Parse iptables connection logs (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Parse iptables connection logs"
    python3 -c "
import sys, json, os
sys.path.insert(0, '${PROJECT_ROOT}/native-proxy')
from log_parser import parse_nfw_log_file, merge_iptables_entries

# Parse syslog for NFW-CONN entries
syslog_path = '/var/log/syslog'
if not os.path.isfile(syslog_path):
    syslog_path = '/var/log/kern.log'

ipt_entries = parse_nfw_log_file(syslog_path)
print(f'Parsed {len(ipt_entries)} iptables log entries')

# Read existing JSONL entries
conn_log = '${LOG_DIR}/connections.jsonl'
existing = []
try:
    with open(conn_log, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                existing.append(json.loads(line))
except (FileNotFoundError, json.JSONDecodeError):
    pass

# Merge and write back
merged = merge_iptables_entries(ipt_entries, existing)
new_entries = merged[len(existing):]
if new_entries:
    with open(conn_log, 'a') as f:
        for entry in new_entries:
            ce = {
                'timestamp': entry.get('timestamp', ''),
                'protocol': entry.get('protocol', 'tcp').lower(),
                'host': entry.get('dst_ip', ''),
                'port': entry.get('dst_port', 0),
                'path': '',
                'method': 'iptables-log',
                'status': 'logged',
                'bytes_transferred': 0,
            }
            f.write(json.dumps(ce) + '\n')
    print(f'Appended {len(new_entries)} new iptables entries to connection log')
else:
    print('No new iptables entries to merge')
" || echo "Warning: Failed to parse iptables logs"
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 4. Generate report
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Generate report"
REPORT_ARGS="--input ${CONN_LOG} --output ${REPORT_DIR} --mode ${MODE:-monitor}"
if [ -n "${NFW_PIPELINE_POLICY:-}" ]; then
    REPORT_ARGS="${REPORT_ARGS} --commit-path ${NFW_PIPELINE_POLICY}"
fi
if [ -n "${POLICY_FILE}" ] && [ -f "${POLICY_FILE}" ]; then
    REPORT_ARGS="${REPORT_ARGS} --policy ${POLICY_FILE}"
fi
python3 "${PROJECT_ROOT}/scripts/generate_report.py" ${REPORT_ARGS} || {
    echo "Warning: Report generation failed"
}
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 4.5. Intercept health — make silent breakage distinguishable from a clean run
# ---------------------------------------------------------------------------
# "Total connections: 0" must never read the same for "nothing happened" and
# "the intercept was broken". Writes health.json into the report artifact and
# appends a health section to summary.md (which step 5 puts in the Job
# Summary), plus ::warning:: annotations for anything unhealthy.
echo "::group::PipeWarden: Intercept health"
mkdir -p "${REPORT_DIR}"
PW_PROXY_ALIVE="${PROXY_ALIVE_AT_TEARDOWN}" \
PW_DNS_ALIVE="${DNS_ALIVE_AT_TEARDOWN}" \
PW_TRANSPARENT="${TRANSPARENT}" \
PW_CONN_LOG="${CONN_LOG}" \
PW_REPORT_DIR="${REPORT_DIR}" \
python3 - <<'PYEOF' || echo "Warning: health check failed"
import json
import os

proxy_leg = ipt = dns = 0
try:
    with open(os.environ["PW_CONN_LOG"]) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("method") == "iptables-log":
                ipt += 1
            elif e.get("protocol") == "dns":
                dns += 1
            elif e.get("protocol") in ("http", "https", "tcp"):
                proxy_leg += 1
except OSError:
    pass

proxy_alive = os.environ.get("PW_PROXY_ALIVE", "unknown")
dns_alive = os.environ.get("PW_DNS_ALIVE", "unknown")
transparent = os.environ.get("PW_TRANSPARENT", "") == "true"

warnings = []
if proxy_alive == "no":
    warnings.append(
        "the proxy process was not running at teardown — part of the job may "
        "have gone unmonitored"
    )
if transparent and proxy_leg == 0 and (ipt > 0 or dns > 0):
    warnings.append(
        "the transparent proxy leg recorded ZERO flows while other legs saw "
        "traffic — HTTP/HTTPS content metadata was NOT captured; this report "
        "is DNS/iptables metadata only"
    )
if dns_alive == "no":
    warnings.append("the PipeWarden DNS server was not running at teardown")

health = {
    "proxy_alive_at_teardown": proxy_alive,
    "dns_server_alive_at_teardown": dns_alive,
    "proxy_leg_entries": proxy_leg,
    "dns_entries": dns,
    "iptables_only_entries": ipt,
    "warnings": warnings,
}
with open(os.path.join(os.environ["PW_REPORT_DIR"], "health.json"), "w") as fh:
    json.dump(health, fh, indent=2)

lines = ["", "### Intercept health", ""]
if warnings:
    for w in warnings:
        lines.append(f"> ⚠️ **{w}**")
        lines.append(">")
else:
    lines.append("✅ All intercept legs healthy.")
lines += [
    "",
    "| Check | Value |",
    "| --- | --- |",
    f"| Proxy process alive at teardown | {proxy_alive} |",
    f"| DNS server alive at teardown | {dns_alive} |",
    f"| Proxy-leg entries (HTTP/HTTPS/TCP) | {proxy_leg} |",
    f"| DNS entries | {dns} |",
    f"| iptables-only entries | {ipt} |",
    "",
]
summary_md = os.path.join(os.environ["PW_REPORT_DIR"], "summary.md")
try:
    with open(summary_md, "a") as fh:
        fh.write("\n".join(lines))
except OSError:
    pass

for w in warnings:
    print(f"::warning title=PipeWarden health::{w}")
print(
    f"Health: proxy_leg={proxy_leg} dns={dns} iptables={ipt} "
    f"proxy_alive={proxy_alive} dns_alive={dns_alive}"
)
PYEOF
if [ "${TRANSPARENT}" = "true" ] && [ -f "${REPORT_DIR}/health.json" ] \
    && grep -q '"proxy_leg_entries": 0' "${REPORT_DIR}/health.json"; then
    echo "Proxy log tail (for diagnosing the zero-flow proxy leg):"
    tail -n 40 "${LOG_DIR}/proxy.log" 2>/dev/null || echo "(no proxy.log)"
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 5. Write Job Summary
# ---------------------------------------------------------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "${REPORT_DIR}/summary.md" ]; then
    if [ -d "$(dirname "${GITHUB_STEP_SUMMARY}")" ]; then
        cat "${REPORT_DIR}/summary.md" >> "${GITHUB_STEP_SUMMARY}"
    else
        echo "Warning: GITHUB_STEP_SUMMARY path not accessible"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Set outputs and compute blocked count
# ---------------------------------------------------------------------------
BLOCKED_COUNT=0
if [ -f "${REPORT_DIR}/report.json" ]; then
    BLOCKED_COUNT=$(python3 "${PROJECT_ROOT}/scripts/count_blocked.py" "${REPORT_DIR}/report.json")
fi

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
        echo "PipeWarden: Generated network-policy.yml written to ${GENERATED_POLICY}"
    else
        echo "generated-policy-path=" >> "${GITHUB_OUTPUT}"
    fi
    # Emit SARIF path for GitHub Security tab integration
    SARIF_FILE="${REPORT_DIR}/pipewarden.sarif"
    if [ -f "${SARIF_FILE}" ]; then
        echo "sarif-path=${SARIF_FILE}" >> "${GITHUB_OUTPUT}"
    else
        echo "sarif-path=" >> "${GITHUB_OUTPUT}"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Cleanup
# ---------------------------------------------------------------------------
echo "::group::PipeWarden: Cleanup"

# Remove CA certificate and private key
rm -rf "${CA_DIR}"
sudo rm -f /usr/local/share/ca-certificates/nfw-ca.crt
sudo update-ca-certificates > /dev/null 2>&1 || true

# Unset proxy env vars for subsequent steps
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "HTTP_PROXY=" >> "${GITHUB_ENV}"
    echo "HTTPS_PROXY=" >> "${GITHUB_ENV}"
    echo "http_proxy=" >> "${GITHUB_ENV}"
    echo "https_proxy=" >> "${GITHUB_ENV}"
fi

echo "Cleanup complete"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 7.5. Remove proxy user (transparent mode only)
# ---------------------------------------------------------------------------
if [ "${TRANSPARENT}" = "true" ]; then
    echo "::group::PipeWarden: Remove proxy user"
    sudo userdel pipewardenuser 2>/dev/null || true
    sudo userdel mitmproxyuser 2>/dev/null || true
    sudo rm -rf /home/mitmproxyuser /home/pipewardenuser 2>/dev/null || true
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 8. Exit code
# ---------------------------------------------------------------------------
if [ "${MODE}" = "enforce" ] && [ "${BLOCKED_COUNT}" -gt 0 ]; then
    echo "PipeWarden: Blocked ${BLOCKED_COUNT} connections in enforce mode — failing workflow"
    exit 1
fi
