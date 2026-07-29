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
