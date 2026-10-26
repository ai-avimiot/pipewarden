#!/bin/bash
# Proxy container entrypoint for transparent mode.
# Starts DNS resolver + mitmproxy, sets up iptables for transparent interception.

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.send_redirects=0 2>/dev/null || true

# Combine CA key+cert into mitmproxy format
mkdir -p /root/.mitmproxy
if [ -f /ca/ca-key.pem ] && [ -f /ca/ca.pem ]; then
    cat /ca/ca-key.pem /ca/ca.pem > /root/.mitmproxy/mitmproxy-ca.pem
fi

# ---------------------------------------------------------------------------
# Start DNS resolver in background
# ---------------------------------------------------------------------------
echo "[proxy] Starting DNS resolver..."
DNS_SUPPRESS_AAAA=true python3 /dns_server.py &
DNS_PID=$!
sleep 0.5

# Verify DNS server started. Fatal: without it the pipeline either resolves
# nothing or, worse, someone else's resolver answers unlogged.
if ! kill -0 $DNS_PID 2>/dev/null; then
    echo "[proxy] ERROR: DNS server failed to start" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# iptables: redirect traffic to mitmproxy and DNS server
# ---------------------------------------------------------------------------
# No -i: the proxy may be dual-homed (monitored network + egress network), and
# PREROUTING only sees traffic arriving from other hosts. Failures are fatal —
# a proxy that cannot intercept must not keep routing.
set -e
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53

# Anything else the pipeline sends is forwarded, so it is at least logged (as
# in native mode, non-HTTP ports are metadata only). Masquerade so replies
# return when the monitored network is --internal.
iptables -A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-FWD: " || true
EGRESS_IF="$(ip -4 route show default | awk '{print $5; exit}')"
iptables -t nat -A POSTROUTING -o "${EGRESS_IF}" -j MASQUERADE
set +e

# ---------------------------------------------------------------------------
# Start mitmproxy in transparent mode
# ---------------------------------------------------------------------------
exec mitmdump \
    --mode transparent \
    --listen-port 8080 \
    --ssl-insecure \
    --showhost \
    -s /addon.py \
    --set confdir=/root/.mitmproxy
