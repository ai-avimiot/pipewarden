# Avimiot Pipewarden

[![Tests](https://github.com/ai-avimiot/pipewarden/actions/workflows/test.yml/badge.svg)](https://github.com/ai-avimiot/pipewarden/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Avimiot Pipewarden — see every outbound connection your CI pipeline makes. Block the ones it shouldn't.**

Part of [AI Avimiot](https://github.com/ai-avimiot).

Your build pipeline makes dozens of network calls you never see — package registries, CDNs, telemetry endpoints, post-install scripts phoning home. A compromised dependency can exfiltrate your secrets during `npm install` and you'd never know.

PipeWarden is the missing security layer between dependency scanning and production. It monitors **actual network behavior at build time** — the blind spot that static analysis, SCA, and provenance tools can't cover.

## Table of contents

- [What PipeWarden catches that other tools don't](#what-pipewarden-catches-that-other-tools-dont)
- [What PipeWarden is (and isn't)](#what-pipewarden-is-and-isnt)
- [Key benefits](#key-benefits)
- [Quick start](#quick-start)
  - [60-second install](#60-second-install)
  - [1. Discover — see what your pipeline talks to](#1-discover--see-what-your-pipeline-talks-to)
  - [2. Review — tune the generated policy](#2-review--tune-the-generated-policy)
  - [3. Enforce — block unauthorized traffic](#3-enforce--block-unauthorized-traffic)
- [How it works](#how-it-works)
- [Report output](#report-output)
  - [GitHub Security tab integration](#github-security-tab-integration)
- [Compliance](#compliance)
- [OWASP CI/CD Top 10 coverage](#owasp-cicd-top-10-coverage)
- [Modes](#modes)
- [Configuration reference](#configuration-reference)
- [Container mode](#container-mode)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## What PipeWarden catches that other tools don't

| Threat | SCA (Snyk, Dependabot) | Provenance (Sigstore, SLSA) | **PipeWarden** |
|--------|:-----:|:-----:|:-----:|
| Compromised package phones home during install | | | :white_check_mark: **Blocked** |
| Build step exfiltrates `GITHUB_TOKEN` to attacker server | | | :white_check_mark: **Blocked** |
| Dependency downloads second-stage payload | | | :white_check_mark: **Blocked** |
| Cryptominer injected via post-install script | | | :white_check_mark: **Blocked** |
| DNS exfiltration of secrets during build | | | :white_check_mark: **Blocked** |
| Artifact tampering after build | | :white_check_mark: Detected | |

> :rotating_light: **Every major CI/CD supply chain attack** — SolarWinds, Codecov, event-stream, xz-utils, tj-actions/changed-files — involved unauthorized network activity that PipeWarden would have detected.

## What PipeWarden is (and isn't)

**PipeWarden is a build-time network firewall.** It answers: *"What network connections did my build actually make, and were they all expected?"*

| PipeWarden is | PipeWarden is not |
|--------|-----------|
| Runtime network monitoring during CI/CD builds | A dependency scanner (use Snyk, Socket, Dependabot) |
| An allowlist-based egress firewall for pipelines | A SAST/DAST tool (use CodeQL, Semgrep) |
| A network audit trail for compliance (SOC 2, PCI DSS, NIS2) | A container image scanner (use Trivy, Grype) |
| A supply chain attack detector for zero-days SCA can't find | A production runtime security tool |

PipeWarden **complements** your existing security stack — it covers the layer between "scan dependencies" and "verify the artifact."

## Key benefits

- **Your data stays in GitHub** — no SaaS dashboard, no third-party accounts, no data leaving your runner. Reports go to Job Summary, artifacts, and optionally the GitHub Security tab via SARIF
- **No kernel access required** — unlike eBPF-based tools, PipeWarden works on any GitHub-hosted runner out of the box. No privileged containers, no agent installs
- **Deep inspection** — transparent proxy sees full HTTP/HTTPS request/response content, TLS certificate chains, and DNS queries. Not just destination IPs
- **Drop-in setup** — one step. Teardown is automatic, even if your job fails
- **Policy as code** — define allowed destinations in a simple YAML file. Monitor first, enforce when ready

## Quick start

### 60-second install

The simplest setup is a single action — teardown happens automatically when your job ends, even on failure:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: ai-avimiot/pipewarden/native-proxy/action@v1
        with:
          mode: monitor   # discover first; switch to enforce once stable

      # --- your normal workflow, unchanged ---
      - uses: actions/setup-node@v6
        with:
          node-version: '20'
      - run: npm install
      - run: npm test
```

That's it. The report lands in your job summary, in `/tmp/report/`, and is uploaded automatically as a **`network-report`** build artifact — no extra steps. (The upload happens in the action's teardown, which runs at job end even on failure.)

> Don't want the artifact, or want to rename it? Use `upload-artifact: false` or `artifact-name: my-report` on the action. You do **not** need your own `actions/upload-artifact` step — and adding one for `/tmp/report/` won't work with the single-step action, because the report is generated in the teardown post-step that runs *after* your job's steps.

**Versioning.** `@v1` tracks the latest 1.x.y (fixes + features, no breaking changes); `@latest` follows the newest release across all majors; breaking changes ship as a new major (`v2`). For production, pin to an exact release (`@v1.0.7`) or a commit SHA — PipeWarden is a supply-chain tool, so treat a mutable tag as a moving dependency. See [VERSIONING.md](VERSIONING.md).

### 1. Discover — see what your pipeline talks to

The default action above runs in **monitor** mode and writes a policy file you can commit. After the run completes you'll find:

- **Job Summary** — full connection report with destinations, TLS info, and IP ownership
- **Build artifacts** — `network-report` contains `report.json`, `summary.md`, and an auto-generated `network-policy.yml`
- **Artifact: `pipewarden-generated-network-policy`** — the ready-to-commit policy file (also uploaded automatically)

If you need manual control of teardown (for example to gate other steps on the report), use the two-step variant. The teardown step also uploads the `network-report` artifact automatically:

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          mode: monitor

      # --- your normal workflow steps, unchanged ---

      - name: PipeWarden Teardown
        if: always()
        uses: ai-avimiot/pipewarden/native-proxy/action-teardown@v1
        # uploads the `network-report` artifact (disable with upload-artifact: false)
```

### 2. Review — tune the generated policy

Download `network-policy.yml` from the build artifacts. It allows everything your build contacted. Review it, remove anything unexpected, and commit it to your repo:

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

**Sometimes-used destinations.** Some allowed destinations aren't contacted on every run — e.g. a package cache that's only hit on a cache miss, or a conditional/matrix-only step. Mark those rules `appears: sometimes` so they aren't reported as "unused (candidate for removal)" when a run doesn't touch them (the default is `appears: always`). This is **report-only** — it doesn't change what traffic is allowed:

```yaml
  - name: "pip cache mirror"
    appears: sometimes        # always (default) | sometimes
    allow:
      domains:
        - "*.pythonhosted.org"
      ports: [443]
      protocols: [https]
```

### Where policies live (auto-resolution)

Leave `policy-file` unset and PipeWarden resolves the policy automatically, **merging two files** so a shared baseline and per-pipeline rules are both applied:

```
.github/pipewarden/
  common.network-policy.yml      # shared baseline (GitHub, DNS, …) — you maintain this
  ci.network-policy.yml          # rules for ci.yml — PipeWarden auto-generates this
  release.network-policy.yml     # rules for release.yml
```

- **Both are watched:** the effective allowlist is the **union** of `common.network-policy.yml` and the per-workflow `<workflow>.network-policy.yml` (named after the workflow *file*, e.g. `ci.yml` → `ci.network-policy.yml`). Per-pipeline rules override same-named common rules.
- **PipeWarden auto-generates the per-pipeline file**, not the common one. In monitor/discovery the report tells you to download the generated `network-policy.yml` and commit it to `.github/pipewarden/<workflow>.network-policy.yml`.
- **Fallback:** if no `.github/pipewarden/` files exist, a repo-root `network-policy.yml` is used; if nothing exists, the run is discovery (monitor all, generate a policy).
- Setting `policy-file:` explicitly bypasses auto-resolution and uses exactly that file.

### 3. Enforce — block unauthorized traffic

Once the policy is stable, just point PipeWarden at it. Enforce is the default — connections outside the allowlist are blocked and the workflow fails:

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          policy-file: network-policy.yml
```

Reports appear in the GitHub Job Summary and as downloadable artifacts.

## How it works

PipeWarden runs mitmproxy as a transparent proxy directly on the GitHub Actions runner. iptables redirects all outbound HTTP/HTTPS traffic through the proxy — no `HTTP_PROXY` env vars needed, so even tools that ignore proxy settings are captured.

```
┌──────────────────────────────────────────────────────────────┐
│  GitHub Actions Runner                                       │
│                                                              │
│  Your workflow steps:                                        │
│    npm install ──┐                                           │
│    pip install ──┤── iptables ──► mitmproxy ──► policy ──► web
│    curl / wget ──┤   (transparent redirect)                  │
│    node https  ──┤                                           │
│    go net/http ──┘                                           │
│                                                              │
│    DNS queries ───► PipeWarden DNS server ──► log + forward  │
│    Other TCP   ───► iptables LOG ──────────► metadata logged │
│                                                              │
│  Output: connections.jsonl → report → Job Summary            │
└──────────────────────────────────────────────────────────────┘
```

## Report output

PipeWarden generates detailed reports for every run:

| File | Format | Contents |
|------|--------|----------|
| `report.json` | JSON | Full machine-readable report with all connection details |
| `summary.txt` | Text | Human-readable summary for CI logs |
| `summary.md` | Markdown | GitHub Job Summary with tables and collapsible sections |
| `pipewarden.sarif` | SARIF 2.1.0 | Findings for GitHub Security tab (blocked connections, cert warnings) |

Each report includes:

- **Per-destination breakdown** — domain, port, protocol, request count, bytes transferred
- **TLS certificate info** — issuer CA, validity, warnings for untrusted/self-signed certs
- **IP enrichment** — ASN owner, country, reverse DNS (via Team Cymru)
- **DNS query log** — every domain lookup with resolved IPs
- **Policy analysis** — which rules matched, which are unused, suggested allowlist YAML for unmatched destinations

### GitHub Security tab integration

Upload the SARIF report to surface blocked connections as code scanning alerts. This needs the **two-step** variant: the SARIF is written by teardown, so the `upload-sarif` step must come *after* an explicit teardown (with the single-step action the SARIF is created in a post-step that runs after the whole job, so a mid-job upload would find nothing):

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          mode: monitor

      # --- your normal workflow steps ---

      - name: PipeWarden Teardown
        if: always()
        uses: ai-avimiot/pipewarden/native-proxy/action-teardown@v1

      - name: Upload to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: /tmp/report/pipewarden.sarif
          category: pipewarden
```

This needs `permissions: security-events: write` on the job. Findings appear under **Security > Code scanning** with severity levels, persist across runs, and integrate with GitHub's alert management.

## Compliance

PipeWarden generates the kind of continuous, immutable audit trail that compliance frameworks require:

| Framework | What PipeWarden provides |
|-----------|------------------|
| **SOC 2** | Network activity logs for build process audit trail |
| **PCI DSS 4.0** | Continuous monitoring evidence (CI/CD is now explicitly in-scope) |
| **NIST 800-53** | Satisfies AU (Audit), SC (Comms Protection), SI (System Integrity) controls |
| **EU NIS2** | Supply chain security measures with audit capability |

## OWASP CI/CD Top 10 coverage

PipeWarden directly addresses 5 of the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/):

| Risk | How PipeWarden helps |
|------|--------------|
| **SEC-3:** Dependency Chain Abuse | Detects unexpected outbound connections during package install |
| **SEC-4:** Poisoned Pipeline Execution | Blocks anomalous network calls from compromised workflow steps |
| **SEC-6:** Insufficient Credential Hygiene | Detects secret exfiltration to unauthorized endpoints |
| **SEC-8:** Ungoverned 3rd Party Services | Enforces allowlist of approved network destinations |
| **SEC-10:** Insufficient Logging/Visibility | Complete network-level audit trail for every build |

## Modes

### Monitor (default)

Logs all connections. Traffic outside the allowlist is flagged as `would_block` but still allowed through. Use this to discover what your pipeline connects to before writing a strict policy.

### Enforce

Blocks connections outside the allowlist. HTTP/HTTPS requests get `403`. DNS queries for blocked domains get `NXDOMAIN`. By default the workflow fails at **teardown** if any connections were blocked.

**Fail fast.** A blocked request usually breaks the command that made it, but some tools swallow the error and keep going. Set `fail-fast: true` (enforce only) to **cancel the whole run the moment the first blocked connection is seen**, instead of waiting for teardown. It needs a token with `actions: write`:

```yaml
      - uses: ai-avimiot/pipewarden/native-proxy/action@v1
        with:
          mode: enforce
          fail-fast: true
          github-token: ${{ github.token }}
    # and at the job level:
    # permissions:
    #   actions: write
```

Without a token it logs a warning and falls back to fail-at-teardown.

> **Tip:** the auto-generated policy adds **wildcard hint comments** (e.g. `# consider "*.npmjs.org"`) when it sees several sibling subdomains — review and apply them by hand. It never suggests wildcards for multi-tenant suffixes like `s3.amazonaws.com`.

## Configuration reference

### Inputs (setup)

| Input | Default | Description |
|-------|---------|-------------|
| `policy-file` | `""` (auto) | Path to a network policy YAML; empty auto-resolves `.github/pipewarden/` (see [above](#where-policies-live-auto-resolution)) |
| `mode` | `enforce` | `enforce` (block + fail) or `monitor` (log only) |
| `proxy-port` | `8080` | Port for the proxy to listen on |
| `dns` | `true` | Enable DNS interception |
| `transparent` | `true` | Enable iptables transparent proxy |
| `fail-fast` | `false` | Enforce only: cancel the run on the first blocked connection (needs `github-token` + `actions: write`) |
| `github-token` | `""` | Token used to cancel the run when `fail-fast` triggers |
| `upload-artifact` | `true` | Upload the report as a build artifact at teardown |
| `artifact-name` | `network-report` | Name of the uploaded report artifact |

### Outputs (teardown)

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report directory |
| `blocked-count` | Number of blocked/would-block connections |
| `status` | `pass` or `fail` |

## Container mode

For full raw TCP data inspection, PipeWarden can also run your workflow inside an isolated Docker network. See [`examples/container-mode-workflow.yml`](examples/container-mode-workflow.yml) and the [detailed docs](native-proxy/README.md).

| | Native Proxy (recommended) | Container Mode |
|--|---------------------------|----------------|
| Setup time | ~3-5s (cached) | ~58s |
| Docker required | No | Yes |
| Traffic coverage | HTTP/HTTPS + DNS + TCP metadata | All TCP + DNS |
| Workflow changes | Add 1 step | Wrapper workflow |

## Development

```bash
git clone https://github.com/ai-avimiot/pipewarden.git
cd pipewarden
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/requirements.txt
pytest
```

Test suite includes property-based tests via [Hypothesis](https://hypothesis.readthedocs.io/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues should be reported via [GitHub Security Advisories](https://github.com/ai-avimiot/pipewarden/security/advisories/new) — see [SECURITY.md](SECURITY.md).

## License

MIT
