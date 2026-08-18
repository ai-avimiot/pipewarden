# Migrating to PipeWarden v2.0

**Nothing is required.** v1 policies parse unchanged, every input keeps its meaning, and the defaults preserve v1 behaviour exactly. Upgrade the tag and your pipeline behaves as it did:

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v2
```

The major version marks a new policy schema and a new capability, not a break. This guide covers what changed and what you may want to opt into.

## What changed without asking you

### QUIC and UDP entries no longer disappear from reports

Connections were deduplicated by `(destination IP, port)` with no regard for transport, so a UDP entry to a host already recorded over TCP was discarded as a repeat.

That hid essentially all QUIC: an HTTP/3 client contacts a host over TCP/443 first, so every subsequent UDP/443 datagram to it looked like a duplicate. Enforce mode still *rejected* the traffic — those rules are independent — but monitor mode, the mode you run first to learn what your pipeline does, showed nothing.

**What you may notice:** monitor-mode reports can now contain more entries than before for the same pipeline. Those connections were always happening; they were being dropped from the report.

## What you can opt into

### Exfiltration detection (policy `version: "2"`)

An allowlist answers *where* traffic went, not *what went with it*. A token sent to a host your policy already allows is an ordinary request. Because PipeWarden terminates TLS, it can read the request itself.

Bump the version and add the block:

```yaml
version: "2"          # was "1"
mode: enforce

exfiltration:
  mode: block                        # off (default) | warn | block
  detectors: [env-secrets, patterns]
  watch_env: [GITHUB_TOKEN, NPM_TOKEN]

rules:
  - name: "Artifact store"
    allow_request_body: true         # opt this destination out of scanning
    allow:
      domains: ["uploads.example.com"]
      ports: [443]
      protocols: [https]
```

Read [SECURITY.md](../SECURITY.md#payload-scanning) first: enabling this means the proxy holds your watched secret values in memory for the life of the job.

**Roll it out in `warn` first.** Findings are recorded and nothing is blocked, so you learn whether any legitimate request in your pipeline carries a credential — uploading to an artifact store, authenticating to a private registry — before those requests start failing. Move to `block` once the report is clean or the exceptions carry `allow_request_body: true`.

### Running without TLS interception

New in v2.0: if your workflow certificate-pins or uses mutual TLS, those clients previously had no good option — they refuse the certificate PipeWarden presents, because that is exactly what pinning is for.

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v2
  with:
    mode: enforce
    tls-intercept: 'false'   # no MITM at all
    dns: 'true'
```

No CA is generated or installed and no proxy starts, so those clients see the genuine certificate chain and work unchanged. Enforcement falls back to the DNS layer, with connections logged via conntrack. You keep domain allowlisting and a record of what was contacted; you lose path rules, payload scanning and certificate verification, because nothing is in the TLS path to provide them.

PipeWarden also now **detects pinning and names it**: a client refusing the forged certificate is recorded, and the report lists the host with the available fixes rather than leaving you with an unexplained handshake error in your own build step.

### Naming who made each connection

New in v2.0. Your reports already say *where* traffic went; attribution says *who sent it*. This is on by default at its free tier — `attribution: client` reads the `User-Agent` out of requests PipeWarden has already decrypted, costs nothing and needs no privileges, so existing workflows gain a "who made these connections" section with no change on your part.

Nothing is required of you. If you want the process itself rather than its self-reported name:

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v2
  with:
    mode: enforce
    attribution: process     # names the actual process, not just the client
```

That starts a small root-owned helper on the runner, because `/proc/<pid>/fd` is readable only by the process owner or root. Read [Process attribution](../SECURITY.md#process-attribution) before enabling it — particularly if you are also considering `attribution-cmdline`, which records command lines and is off by default for good reason.

`attribution: off` restores exactly the v1.x behaviour: no attribution collected, nothing added to the report.

Note that `attribution: client` needs TLS interception to have anything to read. If you also set `tls-intercept: false`, there is no decrypted request and only `process` mode will report anything — setup says so rather than leaving you with an empty section.

### Version rules

| Policy | Behaviour |
| --- | --- |
| `version: "1"` | Parses exactly as before. Payload scanning off and unavailable. |
| `version: "2"` | Everything from v1, plus `exfiltration:` and `allow_request_body`. |

v2 keys in a v1 policy are **refused, not ignored**. A file that says `exfiltration: {mode: block}` under `version: "1"` fails to parse rather than running silently without the control — a security feature that quietly does nothing is worse than one that is absent, because you would believe you had it.

> **YAML note:** `mode: off` works. Bare `off` is a boolean in YAML 1.1, and PipeWarden maps it back to the word you typed. `"off"` and `'off'` work too.

## New in CI, not in your pipeline

The repository now runs an [adversarial bypass suite](../.github/workflows/bypass-suite.yml) that tries to evade PipeWarden's own interception and asserts each outcome, including the cases it deliberately does not catch. That produced the README's [Known blind spots](../README.md#known-blind-spots) section — the same information that was previously spread across `SECURITY.md` prose, now continuously checked rather than asserted once.

Nothing about this runs in your pipeline.

## What did not change

- Every action input and output keeps its name and meaning.
- Monitor mode still never blocks anything.
- The report is still metadata-only; query strings are still redacted.
- PipeWarden still makes no network calls of its own — no telemetry, no account, no policy service, no data fetched at build time.
