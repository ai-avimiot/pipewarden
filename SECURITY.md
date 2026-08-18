# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
| ------- | --------- |
| Latest  | ✅        |
| Older   | ❌        |

## Verifying Released Images

PipeWarden publishes three images to GHCR, each signed with [cosign](https://github.com/sigstore/cosign) (keyless, via GitHub OIDC) and carrying GitHub-native build-provenance and SBOM attestations:

- `ghcr.io/ai-avimiot/pipewarden`
- `ghcr.io/ai-avimiot/pipewarden-proxy`
- `ghcr.io/ai-avimiot/pipewarden-runner`

### Requires cosign v3 or newer

> **Breaking change.** Since the `sigstore/cosign-installer` v4 upgrade, signatures are stored as **OCI 1.1 referring artifacts** rather than the legacy `sha256-<digest>.sig` tag. **cosign v2 cannot verify these images** — it fails with `no signatures found`. Install cosign v3+ (`brew install cosign`, or the [official releases](https://github.com/sigstore/cosign/releases)).
>
> Images published before that change still carry legacy `.sig` tags and remain verifiable with cosign v2.

### Verify the signature

```bash
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/ai-avimiot/pipewarden/\.github/workflows/build-image\.yml@refs/' \
  ghcr.io/ai-avimiot/pipewarden:latest
```

The identity regex asserts the image was built by this repository's `build-image.yml` workflow. To pin to an exact release, replace it with `--certificate-identity` and the full ref, e.g. `https://github.com/ai-avimiot/pipewarden/.github/workflows/build-image.yml@refs/tags/v1.0.8`.

Verify by digest rather than tag when you need immutability — a tag can be repointed:

```bash
cosign verify ... ghcr.io/ai-avimiot/pipewarden@sha256:<digest>
```

### Verify build provenance

Each image also carries a GitHub-native attestation, verifiable without cosign:

```bash
gh attestation verify oci://ghcr.io/ai-avimiot/pipewarden:latest --repo ai-avimiot/pipewarden
```

### Inspect the SBOM

An SPDX SBOM is attested alongside each image:

```bash
cosign verify-attestation --type https://spdx.dev/Document/v2.3 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/ai-avimiot/pipewarden/\.github/workflows/build-image\.yml@refs/' \
  ghcr.io/ai-avimiot/pipewarden:latest \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

## Enforcement boundary (what "enforce" actually covers)

`enforce` mode inspects and blocks at the application layer via mitmproxy, which is reached by redirecting **TCP ports 80 and 443, IPv4, in the host network namespace** into the proxy. Understand the edges before relying on it:

> **With `tls-intercept: false` this whole section does not apply.** No proxy runs and no CA is installed, so nothing below about TLS-terminated inspection holds. Enforcement is then DNS-layer only (a disallowed domain gets NXDOMAIN and never resolves), with connections logged as IP/port metadata via conntrack. Use it when the workflow certificate-pins or uses mutual TLS — see [Certificate pinning and mTLS](README.md#certificate-pinning-and-mtls).

A blocked connection fails the job by default (the pipeline stops); `fail-on-block: false` blocks the traffic but lets the job continue, and `monitor` mode only observes. See the README's Enforce section.

**Blocked / inspected**
- TCP HTTP on 80 and HTTPS on 443 (IPv4, host netns) — TLS-terminated, matched against policy, blocked when disallowed. This is the primary path and covers the overwhelming majority of CI egress.
- QUIC / HTTP-3 (UDP 443) and DNS-over-TLS/QUIC (853) — **rejected** in enforce mode so clients fall back to the interceptable TCP path (they are not proxy-inspected themselves).
- Plain DNS (TCP/UDP 53) to anything other than the local interceptor — **rejected** in enforce mode when `dns: true`, for every user except root. `resolv.conf` points at the interceptor, but that is a default rather than a control: a step addressing `8.8.8.8` directly resolved names that never appeared in the DNS log. Root is exempt because the interceptor itself forwards upstream on that port as root. Note what this does and does not change: resolving a name elsewhere never granted egress in the first place, because enforcement happens at connection time against the SNI, not at resolution time. This closes a **visibility** gap, not a bypass.
- IPv6 HTTP/HTTPS/DoT — **rejected** in enforce mode (the proxy is IPv4-only, so uninspected IPv6 egress is failed closed rather than allowed through).

**Logged but NOT blocked or TLS-inspected** (visible as IP/port metadata in the report; each raises a `::warning::` and a `health.json` flag so it is never silent)
- Traffic on non-standard TCP ports (e.g. 8443, git-over-SSH on 22, git:9418). It appears in the report but is not policy-enforced.
- Egress from **Docker containers a job launches** — it traverses the `FORWARD` chain, not `OUTPUT`, so it is logged as IP metadata but not TLS-inspected. Full container interception is tracked in `docs/container-visibility-plan.md`.
- IPv6 egress on a runner that has it (logged via `ip6tables`; inspected on neither mode, rejected in enforce).

**Not covered**
- Any code able to run as the `pipewardenuser` UID (e.g. `sudo -u pipewardenuser`, which passwordless-sudo runners allow) is exempt from the redirect by design and can reach 443 directly.
- **Connections already established when PipeWarden starts.** The redirect is a `nat` rule, which the kernel consults once per connection, and the conntrack logging matches `--ctstate NEW`. A socket opened by an earlier step — before the setup action ran — therefore keeps flowing on its original path: not redirected, not inspected, not logged. In the normal case PipeWarden is the first step and there is nothing open yet; the gap is real when it is placed after steps that start long-lived connections. Put it first.
- Full IPv6 and in-container TLS interception are roadmap items, not current guarantees.

If you run in `enforce` on a job holding live credentials, treat the metadata-only report and these boundaries as the contract. The report itself is metadata-only by construction: connection host/port/path/method/bytes/SNI/cert-chain, with **URL query strings redacted** before logging, and request/response headers and bodies never written to it.

## Payload scanning

Policy `version: "2"` adds opt-in [exfiltration detection](README.md#exfiltration-detection), which inspects request bodies and query strings — and, only with `scan_headers: true`, headers — for secret material. Headers are excluded by default because they are where legitimate authentication lives: an `Authorization:` credential sent to the host it belongs to is not exfiltration, and scanning it would block ordinary authenticated traffic to allowlisted destinations. It is **off unless you enable it**. If you do, understand what changes.

**The proxy holds your secret values in memory.** To recognise `GITHUB_TOKEN` leaving the runner, the proxy must know what `GITHUB_TOKEN` is. Values named in `watch_env` are read from the job environment at setup and handed to the proxy process, which keeps them in memory for the life of the job to compare against outbound traffic.

This makes the proxy a higher-value target than it was. Mitigations, in order of importance:

- **Values are never written to any artifact.** Findings record the env var *name* (or the pattern class), a count, and a fingerprint keyed with a random per-run salt. The salt is never persisted, so a fingerprint cannot be reversed by whoever reads `report.json`. A property test over arbitrary secret shapes asserts no watched value reaches a finding, and an end-to-end test asserts `connections.jsonl` contains the variable's name but never its value.
- **The handover is not on the command line.** Values reach the proxy through a file created with mode `0600` *before* any content is written and owned by `pipewardenuser` — not via `argv`, which is world-readable through `/proc/<pid>/cmdline` and would expose the secrets to every process on the runner in order to detect them leaving it.
- **The file does not outlive the job.** It is removed by the setup rollback trap on failure and by teardown on success, so later steps sharing the runner cannot read it.
- **Bodies are read, never retained.** Scanning happens in memory during the request; no request or response content is stored anywhere.

**What is scanned.** Up to `max_scan_bytes` (default 1 MiB) of each request. A secret placed past that offset inside a larger body is not seen — a real limit, stated rather than hidden. Rules carrying `allow_request_body: true` are skipped entirely.

**Detector confidence.** `env-secrets` and `patterns` can block; `entropy` never does, because it fires on checksums, cache keys and minified assets and enforcing on it would break ordinary builds.

If holding secret values in the proxy is not acceptable for your threat model, leave `exfiltration.mode` at `off` (the default) and PipeWarden behaves exactly as it did before — destination-based enforcement only, with no secret material anywhere in the process.

## Process attribution

[`attribution: process`](README.md#who-made-the-connection) runs a root-owned helper on the runner for the life of the job. The default, `attribution: client`, does not — it reads the `User-Agent` out of a request the proxy has already decrypted and needs no privileges at all.

**Why it needs root.** `/proc/<pid>/fd` is readable only by the process owner or root. Build steps run as the runner user, the proxy runs as `pipewardenuser`, and neither can enumerate the other's sockets. Rather than grant mitmproxy that privilege, the privilege lives in a separate process that does one thing: answer "which process owns this socket".

What that process can do, and what constrains it:

- **It answers, it never acts.** The helper serves one request type over a unix socket — a source port or destination in, a process description out. It cannot change policy, block traffic, or affect whether a connection is allowed.
- **The socket is not world-reachable.** Created `root:<proxy group>` mode `0660`, falling back to `0600` if the group cannot be resolved, so an arbitrary process on the runner cannot interrogate it.
- **No external dependencies.** The audit tier speaks the netlink audit protocol directly. Nothing is installed from outside your allowlist — no `auditd`, no `libaudit` — because a tool whose thesis is allowlisting should not need to fetch anything to work.
- **The audit rule does not outlive the job.** The helper deletes it on SIGTERM, and both the setup rollback trap and teardown stop the helper — a rule left installed would keep generating records for every later job on that runner. Teardown also kills any helper whose pid file was lost. If the helper had to switch the audit subsystem on, it switches it back off again: the machine-wide setting is part of what must not outlive the job, not just the rule.
- **An existing audit consumer is left alone.** Only one process at a time receives audit records, so claiming delivery would take it from whoever already holds it — `auditd`, on a self-hosted runner — and handing it back at teardown would silence that consumer for good. The helper checks first and declines the audit tier rather than displace a live owner, falling back to `/proc` lookups. A stale owner whose process is gone does not block the tier, because the kernel does not clear the setting when that process dies.
- **Its output is bounded.** Process names, binary paths and parent names are truncated and reduced to a conservative character set before being recorded, because an `argv[0]` is whatever the caller chose and it ends up in `report.json` and in Markdown posted to the job summary.
- **Explicit-proxy mode runs without the audit tier.** There the proxy runs as the runner user rather than `pipewardenuser`, so its own outbound connections are indistinguishable from the build's and cannot be filtered out by uid. Socket lookups still name processes; only the tier that catches short-lived ones is off. The mode actually in effect is recorded in `report.json`, so "nothing attributed" can be told apart from "attribution was not running".

**`attribution-cmdline` is the part to think about.** It is off by default. A command line is a place credentials genuinely appear — `curl -H "Authorization: Bearer ..."`, `npm publish --//registry:_authToken=...` — and `/proc/<pid>/cmdline` is world-readable, so those values are already exposed to every process on the runner. Recording them puts them in an uploaded artifact, which is a different and worse exposure.

What protects them: the string is scrubbed against your watched secret values *and* the same credential patterns the payload scanner uses, so a token nobody thought to add to `watch_env` is still removed. If the watched-secrets file could not be written, setup declines to record command lines at all rather than recording them with a weaker redactor. What does not protect them: a redactor cannot recognise a bespoke internal credential format. If your pipeline passes credentials in a shape no generic pattern matches, and you have not listed them in `watch_env`, leave this off.

**Failure is degradation, not enforcement loss.** A helper that cannot start downgrades attribution to `client` with a warning; the proxy stops querying one that stops answering. Attribution is reporting, and losing it never changes whether traffic flows.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Security Advisories](https://github.com/ai-avimiot/pipewarden/security/advisories/new) to privately report a vulnerability. This allows the issue to be triaged and fixed before public disclosure.

Please include the following in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected version(s)
- Any suggested mitigations, if known

## Response Timeline

- **Acknowledgment:** Within 5 business days of receiving your report
- **Triage and assessment:** Within 10 business days
- **Fix and disclosure:** Coordinated with the reporter; target within 90 days depending on severity and complexity

## Scope

The following are considered security issues for this project:

- Vulnerabilities that allow bypassing network policy enforcement
- Issues that expose or leak sensitive traffic data outside the intended scope
- Certificate or TLS handling flaws that could enable silent MITM interception beyond the tool's intended monitoring role
- Privilege escalation within Docker containers or the host system
- Injection vulnerabilities in policy files, configuration parsing, or CI/CD workflow generation
- Unintended disclosure of credentials or secrets captured during traffic monitoring

The following are **out of scope**:

- Security issues in third-party dependencies (report these upstream)
- The intentional MITM behavior of the proxy (this is the tool's core function)
- Issues that only affect development/test environments with no production impact
- Denial-of-service attacks requiring physical access or privileged host access
