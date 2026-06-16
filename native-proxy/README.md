# Native Proxy Firewall

Lightweight network monitoring for GitHub Actions workflows. Runs mitmproxy directly on the runner — no Docker containers needed.

By default, the native proxy uses **transparent mode**: iptables redirects all outbound HTTP/HTTPS traffic through mitmproxy, catching even tools that ignore `HTTP_PROXY` env vars (Node.js `https.get()`, Go `net/http`, etc.). Combined with DNS interception, this gives near-complete visibility into your CI pipeline's network activity.

## Quick Start

Add the setup and teardown steps around your existing workflow steps:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          policy-file: network-policy.yml
          mode: monitor

      # Your normal workflow steps — unchanged
      - uses: actions/setup-node@v6
        with:
          node-version: '20'
      - run: npm install
      - run: npm test

      - name: PipeWarden Teardown
        if: always()
        id: nfw
        uses: ai-avimiot/pipewarden/native-proxy/action-teardown@v1
        # Generates the report AND uploads it as the `network-report` artifact.
        # Disable with `upload-artifact: false`, or rename via `artifact-name:`.
```

> The `if: always()` on teardown is important — it ensures reports are generated (and uploaded) even if your build fails.

## With pip caching (~1-3s setup)

```yaml
      - uses: actions/cache@v5
        with:
          path: /root/.cache/pip  # sudo pip (transparent mode) caches here
          key: nfw-pip-${{ runner.os }}

      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          policy-file: network-policy.yml
```

## Inputs (Setup)

| Input | Default | Description |
|-------|---------|-------------|
| `policy-file` | `""` (auto) | Path to a network policy YAML. Empty auto-resolves `.github/pipewarden/common.network-policy.yml` + `<workflow>.network-policy.yml`, falling back to repo-root `network-policy.yml`, then discovery |
| `mode` | `monitor` | `monitor` (log only) or `enforce` (block + fail) |
| `proxy-port` | `8080` | Port for the proxy to listen on |
| `dns` | `true` | Enable DNS interception (intercepts all DNS queries via PipeWarden DNS server) |
| `transparent` | `true` | Enable iptables transparent proxy. Set to `false` for env-var-only mode |

## Outputs (Teardown)

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report directory |
| `blocked-count` | Number of blocked/would-block connections |
| `status` | `pass` or `fail` |

## How It Works

### Transparent Mode (default)

```
┌──────────────────────────────────────────────────────────┐
│  GitHub Actions Runner (ubuntu-latest)                    │
│                                                           │
│  setup.sh:                                                │
│    sudo pip install mitmproxy (system-wide)               │
│    generate CA cert → system trust store                  │
│    create mitmproxyuser (dedicated proxy user)            │
│    start mitmdump --mode transparent :8080 (as proxyuser) │
│    iptables NAT: redirect :80/:443 → :8080                │
│    iptables LOG: log all new outbound connections          │
│    stop systemd-resolved, start dns_server.py :53         │
│    export HTTP_PROXY, CA trust vars → GITHUB_ENV          │
│                                                           │
│  Your workflow steps:                                     │
│    npm install ──┐                                        │
│    pip install ──┤                                        │
│    curl/wget  ──┤── iptables ──► mitmdump ──► policy ──► web │
│    node https ──┤   (transparent redirect)                │
│    go net/http ─┘                                         │
│    DNS queries ─► dns_server.py ─► log + forward          │
│    SSH/other   ─► iptables LOG ─► syslog                  │
│                       │                                   │
│                       ▼                                   │
│              connections.jsonl                             │
│                                                           │
│  teardown.sh:                                             │
│    flush iptables rules                                   │
│    stop mitmdump + dns_server.py                          │
│    parse syslog NFW-CONN entries → merge into log         │
│    restore systemd-resolved                               │
│    generate report → Job Summary                          │
│    cleanup CA + proxy user + env vars                     │
└──────────────────────────────────────────────────────────┘
```

The key technique: mitmproxy runs as `mitmproxyuser`, and iptables rules use `-m owner ! --uid-owner mitmproxyuser` to only redirect traffic from other users. This avoids infinite redirect loops — the proxy's own outbound traffic goes directly to the internet.

### Env-var-only Mode (transparent: false)

Set `transparent: 'false'` to disable iptables and rely solely on `HTTP_PROXY`/`HTTPS_PROXY` env vars. This is the legacy behavior — simpler but tools that ignore proxy env vars will bypass monitoring.

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          policy-file: network-policy.yml
          transparent: 'false'
```

## Network Policy Format

Same YAML format as the container-based mode:

```yaml
version: "1"
mode: monitor

rules:
  - name: "npm registry"
    allow:
      domains:
        - "registry.npmjs.org"
        - "*.npmjs.org"
      ports: [443]
      protocols: [https]

  - name: "GitHub"
    allow:
      domains:
        - "*.github.com"
        - "*.githubusercontent.com"
      ports: [443]
      protocols: [https]
```

Add `appears: sometimes` to a rule (sibling of `name`/`allow`) for destinations that aren't contacted every run (cache-dependent or conditional steps) so they aren't reported as unused when not seen. Default is `appears: always`. Report-only — it does not change what traffic is allowed.

## Environment Variables

The setup step exports these to `GITHUB_ENV` so all subsequent steps use the proxy:

**Proxy routing:**
- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` → `http://127.0.0.1:8080`

**CA trust (for TLS interception):**
- `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`
- `NODE_EXTRA_CA_CERTS`, `NPM_CONFIG_CAFILE`, `PIP_CERT`, `CARGO_HTTP_CAINFO`

**Internal state (used by teardown):**
- `NFW_CA_DIR`, `NFW_LOG_DIR`, `NFW_PROXY_PID`, `NFW_ACTION_PATH`, `NFW_MODE`, `NFW_POLICY_FILE`, `NFW_PROXY_PORT`
- `NFW_TRANSPARENT` — whether iptables rules were configured
- `NFW_DNS_ENABLED`, `NFW_DNS_PID`, `NFW_ORIGINAL_RESOLV_SAVED` (when DNS interception is enabled)

## Traffic Coverage

### Transparent mode (default)

| Traffic type | Captured by | Details |
|-------------|-------------|---------|
| HTTP/HTTPS (ports 80/443) | iptables → mitmproxy | Full request/response inspection, TLS interception |
| DNS queries | dns_server.py | All lookups logged, enforce mode returns NXDOMAIN for blocked domains |
| Other TCP (SSH, custom ports) | iptables LOG | Connection metadata only (src/dst IP, port, protocol, UID) |
| UDP (non-DNS) | Not captured | — |

### Env-var-only mode (transparent: false)

| Traffic type | Captured by | Details |
|-------------|-------------|---------|
| HTTP/HTTPS from proxy-aware tools | HTTP_PROXY env vars → mitmproxy | curl, wget, npm, pip, cargo, go, git |
| HTTP/HTTPS from proxy-unaware tools | Not captured | Node.js `https.get()`, Go `net/http` default client |
| DNS queries | dns_server.py (if dns: true) | All lookups logged |
| Other TCP/UDP | Not captured | — |

## Native vs Container-Based Mode

| Aspect | Native Proxy (transparent) | Native Proxy (env-var-only) | Container Mode |
|--------|---------------------------|----------------------------|----------------|
| Proxy runs in | Background process | Background process | Docker container |
| Traffic routing | iptables transparent proxy | HTTP_PROXY env vars | iptables transparent proxy |
| HTTP/HTTPS coverage | All tools | Proxy-aware tools only | All tools |
| DNS interception | Yes | Yes | Yes |
| Non-HTTP visibility | iptables LOG (metadata) | No | iptables (full) |
| Docker required | No | No | Yes (3 images) |
| Setup time | ~3-5s | ~1-3s | ~58s |
| Workflow execution | Native GitHub Actions | Native GitHub Actions | Re-run via act |

## Limitations

- **No raw TCP/UDP interception**: iptables LOG rules capture connection metadata (IP, port, protocol) for non-HTTP traffic, but the actual data is not inspected. Only HTTP/HTTPS traffic goes through mitmproxy for full inspection.
- **UDP traffic not monitored**: Non-DNS UDP connections are not captured by iptables LOG rules (which only match TCP NEW connections).
- **DNS interception requires systemd-resolved**: The DNS feature stops `systemd-resolved` and takes over port 53. On runners without `systemd-resolved`, DNS interception is skipped gracefully. Set `dns: false` to disable.
- **Transparent mode requires sudo**: iptables rules and the dedicated proxy user require root access. GitHub Actions runners have this by default.

For full traffic coverage including raw TCP data inspection, use the container-based mode.
