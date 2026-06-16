# Design plan: network visibility for containerized build steps

**Status:** proposal (not yet implemented) · **Scope:** `native-proxy` mode · **Driver:**
builds that run Docker themselves (AWS CDK Lambda bundling, `docker build`/`docker run`
in a job step)

> **Current state (2026-06):** the blind spot described below is **confirmed empirically**
> and reproducible — see the runnable demo
> [`container-scenario-native.yml`](https://github.com/ai-avimiot/pipewarden-demo/blob/main/.github/workflows/container-scenario-native.yml)
> + [`container-bundling/bundle.sh`](https://github.com/ai-avimiot/pipewarden-demo/blob/main/container-bundling/bundle.sh)
> in `ai-avimiot/pipewarden-demo`. **None of the tiers below are implemented yet** —
> `native-proxy` (as of v1.0.4) still only covers host egress. The unrelated artifact
> work in v1.0.3/v1.0.4 (the action now auto-uploads its report) is *not* part of this
> plan. Next step remains the **Tier 0 + Tier 1** spike.

## 1. Problem

`native-proxy` mode hooks only the host `OUTPUT` chain
(`native-proxy/iptables_rules.py`):

```
nat    OUTPUT  -p tcp --dport 443/80 -j REDIRECT --to-port 8080   # redirect to mitmproxy
filter OUTPUT  -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-CONN: "   # log the rest
```

The `OUTPUT` chain only sees packets originating in the **host** network namespace.
When a step runs `docker run` / `docker build`, the container is in its own netns on a
bridge (`docker0` or a user-defined `br-*`). Its packets go
`PREROUTING → FORWARD → POSTROUTING` — they never reach `OUTPUT`. Consequences:

- **Not redirected** to mitmproxy → no HTTP/TLS inspection.
- **Not logged** → not even an IP/port metadata line.
- **DNS lost** → Docker rewrites any `127.0.0.0/8` nameserver (PipeWarden's DNS on
  `127.0.0.53`) to a public resolver for bridge containers, and loopback is per-netns
  anyway, so container lookups bypass `proxy/dns_server.py`.

### Why this matters for AWS CDK

CDK shells out to Docker for asset bundling:

| Construct | Docker use | Egress |
|---|---|---|
| `NodejsFunction` | esbuild locally **or** Docker container | npm / esbuild image pull |
| `PythonFunction` (`aws-lambda-python-alpha`) | **always** Docker | `pip install` → PyPI |
| `DockerImageAsset` / `DockerImageFunction` | `docker build` | base image + package pulls |

All of this is currently invisible. The existing **container mode**
(`container/entrypoint.sh`) does not help: it only captures containers it attaches to
`cicd-monitor-net`; a `docker run` a build step launches itself lands on the default
bridge, off that network.

### Empirically observed (GitHub-hosted runner, monitor mode)

Confirmed with the demo workflow (a host `curl` next to a `docker run … pip install`):

- **Host egress is captured** — `curl https://httpbin.org/ip` shows up with full
  connection detail and TLS SNI.
- **Container HTTPS connections are NOT captured** — the in-container `pip install`'s
  downloads from `pypi.org` and `files.pythonhosted.org` are entirely absent from the
  report (no connection record, no SNI).
- **Container DNS is inconsistent / mostly bypassed** — Docker rewrites loopback
  resolvers, so most container lookups go to a public resolver over the bridge and are
  not seen. (Some unrelated host-side lookups still appear, so don't rely on DNS-only
  entries as proof of container visibility.)
- **Image pulls by the Docker daemon** (e.g. `docker pull`) happen in the host netns and
  *may* be captured; the demo pre-pulls before monitoring to keep the focus on the
  container's own egress.

Net: today a compromised dependency pulled during in-container bundling would leave
**no connection trace** in the report.

## 2. Constraints

1. **We don't own the containers** — CDK chooses the image, mounts, and `docker run`
   args. PipeWarden can't assume it edits them.
2. **No assumed CA trust inside them** — the CA lives in the host trust store and is
   exported to host steps; neither reaches a fresh container. Naive
   "redirect 443 → mitmproxy" inside a container = TLS handshake failures = broken
   builds.

These force a **tiered** approach: safe visibility first, opt-in decryption second.

## 3. Tiered design

### Tier 0 — Detect & warn (ship first, trivial)
At setup detect Docker/bridges (`ip -o link show type bridge`, `docker0`/`br-*`,
`docker info`). If present, emit a job-summary warning that container egress (e.g. CDK
Lambda bundling) is not captured. Closes the **silent** blind spot immediately.

### Tier 1 — Metadata + DNS visibility (recommended default; no CA, no breakage)
Capture *destinations* without decrypting:

- **FORWARD conntrack logging** per bridge:
  `filter FORWARD -i docker0 -m conntrack --ctstate NEW -j LOG --log-prefix "NFW-FWD-CONN: "`
  → feeds existing `log_parser.py` → per-destination IP/port/bytes for container egress.
- **Container DNS interception** on the bridge:
  `nat PREROUTING -i docker0 -p udp --dport 53 -j REDIRECT --to-port 53` (+ tcp 53)
  catches the lookup regardless of the rewritten target. Needs `dns_server.py` bound to
  the bridge gateway IP or `0.0.0.0` (already env-configurable via `DNS_LISTEN_ADDR`).
- **IP→domain correlation** already exists (`dns_ip_map.json` in
  `scripts/generate_report.py`).
- *(optional)* **SNI sniffing** on 443 to recover hostnames when DNS is cached/bypassed
  (passive ClientHello parse, or mitmproxy TLS-passthrough logging SNI only).

Outcome: "CDK pulled `public.ecr.aws`, bundling fetched `registry.npmjs.org` /
`pypi.org` / `files.pythonhosted.org`" — visible, **zero build breakage, no CA**.

### Tier 2 — Full MITM of container traffic (opt-in deep inspection)
- `nat PREROUTING -i docker0 -p tcp --dport 80/443 -j REDIRECT --to-port 8080`
  (mitmproxy already binds `0.0.0.0`).
- Solve CA trust via a **`docker` CLI shim** earlier on `PATH` than real Docker. Because
  CDK invokes `docker` from `PATH`, the shim transparently injects into
  `docker run`/`docker build`:
  - `-v <ca.pem>:/pipewarden-ca.pem:ro` and
    `-e NODE_EXTRA_CA_CERTS / PIP_CERT / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / GIT_SSL_CAINFO / CARGO_HTTP_CAINFO`;
  - for `docker build`: CA as a BuildKit secret / `update-ca-certificates` layer.
- **Safety net:** mitmproxy falls back to TLS passthrough (Tier-1 SNI-only) on
  handshake/cert failure, so un-cooperating tools degrade to metadata, not crashes.

### Tier 3 — Enforcement for containers (after monitor is trusted)
DNS-driven **ipset + `DOCKER-USER`** egress firewall: `dns_server.py` populates an ipset
with IPs for allowed domains and returns `NXDOMAIN` for blocked ones; `DOCKER-USER`
default-drops bridge egress except to the allowlist ipset. Use `DOCKER-USER` specifically
— Docker traverses it before its own rules and never flushes it. Document the
**direct-IP-bypass** limitation.

## 4. CDK-specific playbook
- **Cheapest win:** `NodejsFunction` with `bundling: { forceDockerBundling: false }`
  bundles locally → egress flows through existing host `OUTPUT` rules. No PipeWarden
  change needed.
- **`PythonFunction` / forced Docker bundling:** Tier 1 (visibility) or Tier 2 (+CA via
  `bundling.environment` or the docker shim).
- **`DockerImageAsset` / `docker build`:** Tier 1 FORWARD logging captures pulls; Tier 2
  needs CA as a build secret.

## 5. Work items
| File | Change |
|---|---|
| `native-proxy/iptables_rules.py` | `generate_forward_log_rules(bridges)`, `generate_bridge_dns_rules(bridges)`, optional `generate_bridge_redirect_rules`, + flush counterparts; bridge auto-detection |
| `native-proxy/setup.sh` | detect Docker/bridges; apply bridge rules; bind DNS to gateway/`0.0.0.0`; Tier-0 warning |
| `proxy/dns_server.py` | reachable bind addr; ipset population (Tier 3) |
| `native-proxy/log_parser.py` | parse `NFW-FWD-CONN`; tag `source: container\|host` |
| `scripts/generate_report.py` | surface container-origin destinations distinctly |
| *(new)* `native-proxy/docker-shim` | Tier 2 CA/proxy injection wrapper |
| `tests/` | extend `test_iptables_rules.py`, `test_log_parser.py`; add bridge + shim tests |

## 6. Risks — de-risk with a spike before building
- On **GitHub-hosted runners**, confirm bridge naming and that `REDIRECT` from a bridge
  to host mitmproxy works ([mitmproxy #7889](https://github.com/mitmproxy/mitmproxy/issues/7889)
  documents a REDIRECT-by-container-IP quirk; TPROXY may be needed).
- Rule ordering vs Docker's own `PREROUTING`/`DOCKER` chains; don't shadow them or break
  container↔container traffic.
- Binding `0.0.0.0:53` vs Docker embedded DNS / leftover `systemd-resolved`.
- conntrack LOG volume on chatty builds.

## 7. Sequencing
Spike → **Tier 0 + Tier 1** as the first shippable release (this *is* the
"improve visibility" goal, safely) → Tier 2 (docker shim) → Tier 3 (enforce).

## References
- Runnable repro: [pipewarden-demo container-scenario](https://github.com/ai-avimiot/pipewarden-demo/blob/main/.github/workflows/container-scenario-native.yml)
- mitmproxy: [transparent proxying](https://docs.mitmproxy.org/stable/howto/transparent/),
  [docker bridge issue #7889](https://github.com/mitmproxy/mitmproxy/issues/7889)
- [Transparent squid proxy for Docker](https://jpetazzo.github.io/2014/06/17/transparent-squid-proxy-docker/)
- CDK: [NodejsFunction](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_lambda_nodejs.NodejsFunction.html),
  [PythonFunction docker-in-docker #12940](https://github.com/aws/aws-cdk/issues/12940)
- [Domain-based egress filtering with iptables + dnsmasq](https://craftcoders.app/building-a-simple-domain-name-based-firewall-for-egress-filtering/index.html)
- [Docker firewall & DNS / DOCKER-USER](https://medium.com/nosebit-engineering/docker-firewall-and-dns-1a7ccfc21be)
