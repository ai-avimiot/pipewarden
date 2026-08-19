# Avimiot Pipewarden

[![Tests](https://github.com/ai-avimiot/pipewarden/actions/workflows/test.yml/badge.svg)](https://github.com/ai-avimiot/pipewarden/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Avimiot Pipewarden — see every outbound connection your CI pipeline makes, and what leaves with it. Block both.**

Part of [AI Avimiot](https://github.com/ai-avimiot).

Your build pipeline makes dozens of network calls you never see — package registries, CDNs, telemetry endpoints, post-install scripts phoning home. A compromised dependency can exfiltrate your secrets during `npm install` and you'd never know.

PipeWarden is the missing security layer between dependency scanning and production. It monitors **actual network behavior at build time** — the blind spot that static analysis, SCA, and provenance tools can't cover.

It works at two levels. An **allowlist** decides which destinations your build may reach. And because PipeWarden terminates TLS on the runner, it can also read the **request itself** — so a secret sent to a destination you already allow is caught too, which no destination-based check can see.

## Table of contents

- [What PipeWarden catches that other tools don't](#what-pipewarden-catches-that-other-tools-dont)
- [What PipeWarden is (and isn't)](#what-pipewarden-is-and-isnt)
- [What PipeWarden supports](#what-pipewarden-supports)
  - [Where PipeWarden fits](#where-pipewarden-fits)
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
- [Exfiltration detection](#exfiltration-detection)
- [Known blind spots](#known-blind-spots)
- [Certificate pinning and mTLS](#certificate-pinning-and-mtls)
- [Migrating to v2.0](docs/migrating-to-v2.md)
- [Deploy and credentialed jobs](#deploy-and-credentialed-jobs)
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
| …to a server your policy already allows | | | :white_check_mark: **Blocked** with [exfiltration detection](#exfiltration-detection) |
| Dependency downloads second-stage payload | | | :white_check_mark: **Blocked** |
| Cryptominer injected via post-install script | | | :white_check_mark: **Blocked** |
| DNS exfiltration of secrets during build | | | :white_check_mark: **Blocked** |
| Artifact tampering after build | | :white_check_mark: Detected | |

> :rotating_light: **Supply-chain compromises routinely show up as build-time network activity.** The Codecov bash-uploader compromise sent CI environment variables — including credentials — to an attacker-controlled host during customers' builds. The tj-actions/changed-files compromise fetched its payload from a remote URL mid-workflow. Both are the kind of egress PipeWarden is built to surface.
>
> Not every incident is: backdoors that activate in the shipped artifact rather than the pipeline (xz-utils) leave no build-time trace for a network control to catch. PipeWarden covers the build's egress — pair it with dependency scanning and artifact provenance for the rest.

## What PipeWarden is (and isn't)

**PipeWarden is a build-time network firewall.** It answers: *"What network connections did my build actually make, and were they all expected?"*

| PipeWarden is | PipeWarden is not |
|--------|-----------|
| Runtime network monitoring during CI/CD builds | A dependency scanner (use Snyk, Socket, Dependabot) |
| An allowlist-based egress firewall for pipelines | A SAST/DAST tool (use CodeQL, Semgrep) |
| A network audit trail for compliance (SOC 2, PCI DSS, NIS2) | A container image scanner (use Trivy, Grype) |
| A supply chain attack detector for zero-days SCA can't find | A production runtime security tool |

PipeWarden **complements** your existing security stack — it covers the layer between "scan dependencies" and "verify the artifact."

## What PipeWarden supports

Stated plainly, so you can tell before adopting whether it fits.

| | Supported |
| --- | --- |
| Domain / port / protocol allowlisting | ✅ |
| **Request-path rules** (`paths: ["/simple/*"]`) | ✅ |
| **Request body & query-string scanning** for secrets | ✅ opt-in ([exfiltration detection](#exfiltration-detection)) |
| Request header scanning | ✅ opt-in (`scan_headers`) |
| DNS interception & enforcement | ✅ |
| TLS certificate-chain verification | ✅ |
| Non-HTTP TCP/UDP connection logging | ✅ metadata only |
| Runs with no TLS interception (pinning / mTLS) | ✅ ([`tls-intercept: false`](#certificate-pinning-and-mtls)) |
| GitHub-hosted Linux runners | ✅ |
| Container mode | ✅ ([container mode](#container-mode)) |
| **Client attribution** — which tool made a request | ✅ ([who made the connection](#who-made-the-connection)) |
| **Process attribution** — which process opened a connection | ✅ opt-in (`attribution: process`) |
| **File-integrity monitoring** | ❌ out of scope |
| Windows / macOS runners | ❌ Linux only |
| Self-hosted runners / ARC | ❌ not supported today |
| Per-host TLS exclusion (`tls-passthrough`) | ⏳ planned |
| Curated known-malicious blocklist | ❌ deliberately not — see below |

**No threat feed, by design.** PipeWarden ships no blocklist of known-bad domains and fetches nothing at build time. Allowlisting is the model: in enforce mode everything not on your list is already blocked, including infrastructure no feed has heard of yet. A bundled list would also go stale, and a stale list is worse than none — it implies a coverage guarantee nobody is maintaining.

### Where PipeWarden fits

There are two workable architectures for CI egress control, and the choice is a real trade rather than a ranking.

**Observation-based** tools watch DNS and connections without touching TLS. Nothing in your build can break because of them, and pinned or mTLS clients are unaffected — but the request contents are, by construction, unreadable.

**PipeWarden terminates TLS.** That is what makes request-path rules and payload scanning possible, and it is the reason a secret sent to an allowlisted host can be caught at all. The cost is real and worth stating up front: a CA is installed on the runner for the job, certificate-pinned clients will refuse it, mutual-TLS connections cannot be intercepted at all, and a proxy defect can break a build that an observation-based tool would have left alone. `tls-intercept: false` exists precisely so you can opt out of that trade without giving up allowlisting.

PipeWarden is also younger and has had far fewer eyes on it than established tools — which is not the same as having fewer holes. That is why it ships an [adversarial bypass suite](#known-blind-spots) that runs in CI and documents what it does *not* catch.

If you need file-integrity or process monitoring, Windows/macOS, or self-hosted and ARC coverage, PipeWarden does not do those today; [StepSecurity's harden-runner](https://github.com/step-security/harden-runner) is a well-established option in this space that does. The two are not mutually exclusive — running both is reasonable.

## Key benefits

- **Nothing leaves your infrastructure** — no SaaS dashboard, no accounts, no telemetry, and no data fetched at build time. PipeWarden makes no network calls of its own. Reports go to the Job Summary, artifacts, and optionally the GitHub Security tab via SARIF
- **Catches secrets leaving, not just bad destinations** — [exfiltration detection](#exfiltration-detection) reads request bodies and query strings, so a token sent to a host your policy *allows* is still blocked. Opt-in, and the secret value is never written to any report
- **Request-level policy** — rules match on paths, not only domains. TLS certificate chains are verified, and DNS queries are seen before anything connects
- **Names who made each connection** — [attribution](#who-made-the-connection) reports the client behind every request, and optionally the process itself, so a report says *what ran*, not only where it went
- **Works on a stock runner** — no kernel access, no privileged containers, no agent baked into an image
- **Honest about its limits** — an [adversarial bypass suite](#known-blind-spots) runs in CI and documents what PipeWarden does *not* catch, so the gaps are stated rather than discovered
- **Fits pinned and mTLS workflows** — [`tls-intercept: false`](#certificate-pinning-and-mtls) runs with no interception at all when your clients can't tolerate it
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

      - uses: ai-avimiot/pipewarden/native-proxy/action@v2
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

**Versioning.** `@v2` tracks the latest 2.x.y (fixes + features, no breaking changes); `@latest` follows the newest release across all majors; breaking changes ship as a new major. `@v1` still resolves to 1.4.1 and does not carry the 2.x work — upgrading the tag is all the move takes, see [Migrating to v2.0](docs/migrating-to-v2.md). For production, pin to an exact release (`@v2.1.0`) or a commit SHA — PipeWarden is a supply-chain tool, so treat a mutable tag as a moving dependency. See [VERSIONING.md](VERSIONING.md).

> **Pinning to a SHA:** annotated tags resolve to a *tag object* SHA that Actions cannot use in `uses:`. Always pin to the **commit** SHA: `git rev-list -n 1 vX.Y.Z` (or take the SHA shown next to the tag on the release page), not `git rev-parse vX.Y.Z`.

### 1. Discover — see what your pipeline talks to

The default action above runs in **monitor** mode and writes a policy file you can commit. After the run completes you'll find:

- **Job Summary** — full connection report with destinations, TLS info, and IP ownership
- **Build artifacts** — `network-report` contains `report.json`, `summary.md`, and an auto-generated `network-policy.yml`
- **Artifact: `pipewarden-generated-network-policy`** — the ready-to-commit policy file (also uploaded automatically)

If you need manual control of teardown (for example to gate other steps on the report), use the two-step variant. The teardown step also uploads the `network-report` artifact automatically:

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v2
        with:
          mode: monitor

      # --- your normal workflow steps, unchanged ---

      - name: PipeWarden Teardown
        if: always()
        uses: ai-avimiot/pipewarden/native-proxy/action-teardown@v2
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

> **Workflows with multiple jobs?** Each job runs on its own runner, so add the action to every job you want covered — they all auto-resolve the same per-workflow policy. For matrix jobs, aggregating reports, and the union vs. least-privilege tradeoff, see [docs/multi-job-workflows.md](docs/multi-job-workflows.md).

### 3. Enforce — block unauthorized traffic

Once the policy is stable, just point PipeWarden at it. Enforce is the default — connections outside the allowlist are blocked and the workflow fails:

```yaml
      - name: PipeWarden Setup
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v2
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

**The report is metadata-only by design.** A connection entry carries host, port, method, byte counts, TLS SNI and certificate-chain details — never request headers, bodies, or cookies. The URL path is recorded with its **query string redacted** (`/download?<redacted>`), because even though the proxy terminates TLS, query strings routinely carry credentials (presigned-URL signatures, `?access_token=`, API keys) and those must not land in an uploaded artifact. This is what makes it safe to run in jobs holding live cloud credentials (see [Deploy and credentialed jobs](#deploy-and-credentialed-jobs)). For exactly what `enforce` mode does and does not block, see the [enforcement boundary](SECURITY.md#enforcement-boundary-what-enforce-actually-covers) in SECURITY.md.

Every report also includes an **intercept health** section (`health.json` + a block in the Job Summary): whether the proxy and DNS server were still alive at teardown and how many entries each interception leg recorded. A broken intercept is reported as broken — it can no longer masquerade as a clean run with zero connections.

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
        uses: ai-avimiot/pipewarden/native-proxy/action-setup@v2
        with:
          mode: monitor

      # --- your normal workflow steps ---

      - name: PipeWarden Teardown
        if: always()
        uses: ai-avimiot/pipewarden/native-proxy/action-teardown@v2

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

Blocks connections outside the allowlist. HTTP/HTTPS requests get `403`. DNS queries for blocked domains get `NXDOMAIN`.

**Stopping the pipeline (default).** A blocked connection is a policy violation, so by default **the job fails** — the pipeline stops. This holds even when the build step that made the connection swallowed the error and kept going: the block is detected at teardown and the job is failed there (`::error::` in the log, exit code 1). This is true for all three entry points — the single-step action, the two-step `setup`/`teardown` actions, and container mode.

**Block but continue (`fail-on-block: false`).** If you want the traffic blocked at the network level but the job to keep running — e.g. a deploy where you'd rather ship than stop, while still recording every violation in the report — set `fail-on-block: false`. The connection is still blocked; the job logs a `::warning::` and continues.

```yaml
      - uses: ai-avimiot/pipewarden/native-proxy/action@v2
        with:
          mode: enforce
          fail-on-block: false   # block the traffic, but don't fail the job
```

**Just observe (audit).** To neither block nor fail — pure observation — use `mode: monitor` (the discovery mode above). Nothing is ever blocked; out-of-policy traffic is flagged `would_block` in the report.

| Goal | Setting |
| --- | --- |
| Block a violation **and stop the pipeline** (default) | `mode: enforce` |
| Block a violation but **let the job continue** | `mode: enforce` + `fail-on-block: false` |
| **Only observe** — never block, never fail | `mode: monitor` |

**Fail fast.** A blocked request usually breaks the command that made it, but some tools swallow the error and keep going. Set `fail-fast: true` (enforce only) to **cancel the whole run the moment the first blocked connection is seen**, instead of waiting for teardown. It needs a token with `actions: write`:

```yaml
      - uses: ai-avimiot/pipewarden/native-proxy/action@v2
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

## Exfiltration detection

An allowlist answers *where* traffic went. It cannot answer *what went with it*.

Consider the threat this README opens with — a build step sending your `GITHUB_TOKEN` to an attacker. If the attacker picks an unlisted host, the allowlist stops it. If they pick a host you already allow — a gist, a chat webhook, your own object store, a CI service in your policy — it is an ordinary `POST` and the allowlist says yes.

Because PipeWarden terminates TLS, it can read the request instead of only its destination. This is opt-in and requires policy `version: "2"` — see [Migrating to v2.0](docs/migrating-to-v2.md), and roll it out in `warn` before `block`:

```yaml
version: "2"
mode: enforce

exfiltration:
  mode: block                        # off (default) | warn | block
  detectors: [env-secrets, patterns]
  watch_env: [GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, NPM_TOKEN]

rules:
  - name: "Artifact store"
    allow_request_body: true         # this endpoint is *meant* to receive credentials
    allow:
      domains: ["uploads.example.com"]
      ports: [443]
      protocols: [https]
```

Bodies and query strings are scanned; headers are **not, by default**. A credential in an `Authorization:` header sent to an allowlisted host is almost always authentication — `gh`, `git`, artifact uploads — not exfiltration, and blocking it would break ordinary builds. Set `scan_headers: true` to include headers if your threat model wants them, and expect to pair it with `allow_request_body: true` on every credentialed destination.

| Detector | What it matches | Blocks? |
| --- | --- | --- |
| `env-secrets` | The literal values of the env vars in `watch_env`, including their base64, URL- and hex-encoded forms | Yes |
| `patterns` | Issuer-assigned credential shapes — `ghp_`, `github_pat_`, `AKIA`, `AIza`, `xox*`, PEM private keys, JWTs | Yes |
| `entropy` | High-entropy blobs | **No** — reported only |

`env-secrets` is the one that matters: matching against your *own* secret values answers "did a value from my secret store leave this runner" with no heuristics and effectively no false positives. `entropy` never blocks because it fires on checksums, cache keys and minified assets, and enforcing on it would break ordinary builds.

Values shorter than 12 characters are ignored — CI is full of short "secrets" (`true`, a port number) whose bytes appear in nearly every request.

### What the report records

**Never the secret.** `report.json` is uploaded as a build artifact, so a detector that logged what it matched would publish the credential more conveniently than the exfiltration attempt did. Findings carry the *source* — the env var name, or the pattern class — plus a count and a fingerprint keyed with a per-run salt, so repeats collapse within one report while remaining useless outside it.

### What this costs

The proxy holds your watched secret values in memory to compare against them. See [SECURITY.md](SECURITY.md#payload-scanning) for the full picture before enabling it.

## Who made the connection

An allowlist answers *where* traffic went. Payload scanning answers *what went with it*. This answers *who sent it* — the question every incident review asks first, and the one a destination log cannot address. Eight requests to `registry.npmjs.org` look identical whether npm made them or a postinstall script did.

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v2
  with:
    attribution: process       # default is 'client'
```

Three sources, in increasing cost and decreasing availability:

| Source | What it knows | Cost |
|--------|---------------|------|
| `user-agent` | The client's self-reported name, e.g. `npm/10.2.4` | Free. Readable **only because PipeWarden terminates TLS** — a tool that watches packets cannot see it |
| `proc` | The real process behind the socket: pid, binary path, parent | A small root helper on the runner |
| `audit` | `connect()` syscalls as they happen | The same helper, reading the kernel audit stream |

`proc` and `audit` are complementary rather than ranked. `proc` joins on the client's source port, so it is exact — but a process that exits before the lookup lands leaves no `/proc` entry. `audit` never misses a short-lived process, but carries only the destination, so two processes contacting the same host in the same moment are indistinguishable. The helper prefers the first and falls back to the second.

The report groups connections by actor, promoting whoever tripped a block or a payload finding:

```
Who made these connections (3 client(s)):
  postinstall.sh (curl/8.5.0) — 1x to 1 destination(s) [1 with secret findings, 1 blocked]
  npm — 2x to 1 destination(s)
  git/2.43.0 — 1x to 1 destination(s)
```

The first row is the point. The process is `postinstall.sh`, but it told the server it was `curl` — and a `User-Agent` that disagrees with the process behind it is exactly the discrepancy attribution exists to expose. A client that lies is still believed, so `user-agent` alone identifies **tools, not adversaries**.

### What it costs

`attribution: process` runs a small root-owned helper on the runner for the life of the job. It needs root because `/proc/<pid>/fd` is readable only by the process owner or root, and your build steps run as the runner user while the proxy deliberately does not run as root. The privilege lives in that one process rather than being handed to mitmproxy. The helper speaks the netlink audit protocol directly — no `auditd`, no `libaudit`, nothing installed from outside your allowlist — and deletes its audit rule on the way out, on both the success and failure paths.

Attribution is diagnostics. A helper that fails to start downgrades to `client` with a warning rather than failing the job, and the proxy stops querying one that stops answering. Losing attribution never affects whether traffic flows.

`attribution-cmdline: true` additionally records each process's command line. It is off by default and should stay off unless you need it: CI scripts routinely put tokens on argv, and while the recorded string is scrubbed against both your watched secret values and the built-in credential patterns, a redactor cannot recognise a bespoke internal credential format. For an unknown format the safe answer is not to collect the string at all.

With `tls-intercept: false` there is no decrypted request, so `client` mode has nothing to read — `process` is the only mode that reports anything, and it names the processes behind the conntrack rows that are then the whole connection log.

## Known blind spots

PipeWarden ships an [adversarial bypass suite](.github/workflows/bypass-suite.yml) that tries to evade its own interception on every relevant change and asserts the result. Cases marked `gap` are asserted to *stay* missing — if one starts being caught, the suite fails, because this section would then be wrong.

**Caught:** HTTPS to a raw IP with no DNS lookup (including DNS-over-HTTPS, which is indistinguishable from it), DNS-over-TLS on 853, QUIC/UDP on 443, raw TCP on non-standard ports, DNS queries, and plain DNS sent straight to an external resolver — visible through conntrack, and **rejected** outright in `enforce` with `dns: true` for every user except root.

**Not caught:**

| Blind spot | Why |
| --- | --- |
| Egress from a container started by a build step | Container traffic traverses the docker bridge and the `FORWARD` chain, never `OUTPUT`, so the redirect never applies. Use [container mode](#container-mode) for those workloads. |
| Egress from a process running as `pipewardenuser` | The redirect carries `! --uid-owner pipewardenuser` so the proxy does not intercept itself. Reaching it needs `sudo` — which a compromised build step on a GitHub-hosted runner already has. |
| Connections already established when PipeWarden starts | The redirect is a `nat` rule the kernel consults once per connection, and conntrack logging matches `--ctstate NEW`. A socket opened by an earlier step keeps flowing on its original path: not redirected, not inspected, not logged. Put the setup step first. |

The first two are properties of running on the same host as the workload, and neither is fixable without moving interception off the runner. The third is a matter of step order: run PipeWarden before anything that opens a long-lived connection.

## Certificate pinning and mTLS

PipeWarden inspects TLS by terminating it: it presents a certificate it forged for the requested host, signed by a per-job CA it installs into the runner's trust store (see [How it works](#how-it-works)). Two kinds of client refuse that certificate, correctly:

- **Certificate-pinned clients** validate the *real* site's key and reject anything else — including PipeWarden's forged leaf. That is pinning doing its job.
- **Mutual-TLS (client-certificate) clients** cannot be intercepted even in principle: completing the upstream handshake needs the client's private key, which the proxy does not have.

PipeWarden **detects pinning and tells you**. When a client rejects the forged certificate, the TLS handshake failure is recorded and the report names the host with the two fixes below — so the failure surfaces as *"pinned.example.com refused interception"* instead of an opaque handshake error inside your own build step.

**Fix one host — `tls-passthrough`** *(planned)*: tunnel a named host's TLS untouched (real cert to the client, client cert to the server) while everything else stays intercepted. The host is still visible as SNI/connection metadata and still subject to the DNS allowlist — degraded to connection-level enforcement, not disabled.

**Fix the whole workflow — `tls-intercept: false`**: run with no MITM at all. No CA is generated or trusted and no proxy starts, so pinned and mTLS clients see the genuine certificate chain and work unchanged. PipeWarden falls back to **DNS-layer enforcement plus conntrack connection logging** — the same posture harden-runner takes. You keep allowlist enforcement on domains and a record of what was contacted; you lose body/path/query inspection and upstream-certificate verification, because nothing is in the TLS path to provide them.

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v2
  with:
    mode: enforce
    tls-intercept: 'false'   # no MITM — pinned & mTLS clients unaffected
    dns: 'true'
```

## Deploy and credentialed jobs

PipeWarden is designed to be safe in jobs that hold live credentials (cloud deploys, OIDC token exchanges, package publishing):

- **TLS interception does not break signed traffic.** The proxy terminates TLS and re-encrypts upstream; request contents — including AWS SigV4 signatures, which sign headers and payload, not the TLS session — pass through unmodified. GitHub OIDC exchanges, `aws-actions/configure-aws-credentials`, and full `cdk deploy` runs work through the intercept with no changes.
- **Clients trust the intercept via the standard CA env vars.** Setup exports `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `NPM_CONFIG_CAFILE`, etc., and installs the ephemeral CA into the system trust store, so npm, pip, the AWS SDKs and curl all verify normally.
- **Nothing decrypted is persisted.** The report records connection metadata only (host/port/path/method/bytes/SNI/cert chain) — never headers, bodies, or cookies, and URL query strings are redacted before logging so signed-URL and token params don't leak. See [Report output](#report-output).
- **A broken intercept fails loudly, not silently.** The startup canary fails setup (rolling back all DNS and iptables changes so the runner keeps working) if the intercept records nothing, and the teardown health section flags a proxy or DNS server that died mid-job. For a deploy job where you'd rather proceed unmonitored than block the deploy, use `canary: warn`.

## Configuration reference

### Inputs (setup)

| Input | Default | Description |
|-------|---------|-------------|
| `policy-file` | `""` (auto) | Path to a network policy YAML; empty auto-resolves `.github/pipewarden/` (see [above](#where-policies-live-auto-resolution)) |
| `mode` | `enforce` | `enforce` (block + fail) or `monitor` (log only) |
| `fail-on-block` | `true` | Enforce only: fail the job when any connection was blocked (stops the pipeline). Set `false` to block the traffic but let the job continue. Ignored in monitor mode |
| `proxy-port` | `8080` | Port for the proxy to listen on |
| `dns` | `true` | Enable DNS interception. In `enforce`, also rejects plain DNS (TCP/UDP 53) addressed to anything other than the local interceptor, for every user except root |
| `transparent` | `true` | Enable iptables transparent proxy |
| `tls-intercept` | `true` | Terminate TLS for body/path/query inspection. Set `false` for [pinning/mTLS workflows](#certificate-pinning-and-mtls) — no MITM, DNS + connection logging only |
| `attribution` | `client` | Record who made each connection. `client` reads the `User-Agent` from the decrypted request; `process` also names the real process via a root helper; `off` records nothing. See [Who made the connection](#who-made-the-connection) |
| `attribution-cmdline` | `false` | `attribution: process` only: also record each process's command line, scrubbed against your watched secrets and the built-in credential patterns |
| `fail-fast` | `false` | Enforce only: cancel the run on the first blocked connection (needs `github-token` + `actions: write`) |
| `github-token` | `""` | Token used to cancel the run when `fail-fast` triggers |
| `cache` | `true` | Cache the proxy engine's pip wheels across runs (saves ~10-20s of setup); `false` to disable |
| `upload-artifact` | `true` | Upload the report as a build artifact at teardown |
| `artifact-name` | `network-report-<job id>` | Name of the uploaded report artifact (per-job default so two instrumented jobs in one workflow don't collide) |
| `canary` | `true` | Startup canary: after setup, make one HTTPS request and require it in the connection log. `true` fails setup (with full rollback of DNS/iptables changes) if the intercept records nothing; `warn` only annotates; `false` skips |

The `mode` input (via the `MODE` environment variable) takes precedence over the policy file's own `mode:` field; the file's value is used only when no input/env mode is set, falling back to `monitor`.

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
