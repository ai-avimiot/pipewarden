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
python3 /dns_server.py &
DNS_PID=$!
sleep 0.5

# Verify DNS server started
if ! kill -0 $DNS_PID 2>/dev/null; then
    echo "[proxy] WARNING: DNS server failed to start"
fi

# ---------------------------------------------------------------------------
# iptables: redirect traffic to mitmproxy and DNS server
# ---------------------------------------------------------------------------

# Redirect incoming HTTP/HTTPS traffic to mitmproxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true

# Redirect incoming DNS traffic (UDP) to our DNS resolver
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || true

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
