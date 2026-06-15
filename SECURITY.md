# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
| ------- | --------- |
| Latest  | ✅        |
| Older   | ❌        |

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
