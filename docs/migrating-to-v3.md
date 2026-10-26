# Migrating to PipeWarden v3.0

v3.0 tightens several enforce-mode defaults. Each change closes a way for traffic to get past the firewall, so none of them can be switched off; where one affects you, the fix is a policy or workflow change, listed below. Change the tag once you have checked each section:

```yaml
- uses: ai-avimiot/pipewarden/native-proxy/action@v3   # was @v2
```

`@v2` stays on the 2.2.x line (2.2.2 adds only security fixes), so a pipeline that is not ready keeps working there. Most changes only bite in `enforce`; in `monitor` the same traffic is reported as `would_block`, so **run one monitor job on `@v3` first** and read its report.

| You use | Read |
| --- | --- |
| A policy with `version: "2"` | [Internal-address guard](#internal-address-guard-on-every-version-2-rule) |
| Container mode with `workflow-file` | [No Docker socket](#act-job-containers-get-no-docker-socket) |
| IPv6-only destinations, or `tls-intercept: false` / `transparent: false` | [AAAA answers](#aaaa-answers) |
| Native enforce on a self-hosted or custom runner kernel | [IPv6 rejects](#native-enforce-setup-fails-if-ip6tables-reject-rules-cannot-be-added) |
| Native enforce with steps that touch iptables or kill processes | [Teardown boundary check](#teardown-fails-enforce-jobs-when-the-boundary-was-not-intact) |
| Discovery-generated policies | [Generated policies](#discovery-generated-policies-do-not-pin-methods) |
| `.github/pipewarden/common.network-policy.yml` with a per-workflow file | [Policy merge](#policy-merge-refuses-mixed-versions-and-keeps-exfiltration) |

## Breaking changes

### Internal-address guard on every `version: "2"` rule

**Who is affected:** anyone whose policy already says `version: "2"` (for example because it adopted exfiltration detection on v2.x) and reaches an internal host by name. A `version: "1"` policy is not checked and behaves as before.

Under `version: "2"`, an allowed name only gets through if it resolves to a public address. If the upstream address is loopback, link-local, private (`10/8`, `172.16/12`, `192.168/16`), CGNAT, unique-local, reserved or a cloud metadata / platform endpoint (`169.254.169.254`, `fd00:ec2::254`, `168.63.129.16`, `192.0.0.192`):

- the request is blocked in enforce: `403` with `X-PipeWarden-Block-Reason: private-ip`, and the report entry carries a `block_reason` like `destination 10.20.0.7 is a private address not listed in allowed_ips of any rule matching 'artifacts.corp.example'`;
- in enforce the DNS interceptor answers `NXDOMAIN` for that name, refusing the whole answer if any `A` or `AAAA` record is internal;
- in monitor both are reported as `would_block` and allowed.

Typical cases: an artifact mirror or registry on a private network reached from a self-hosted runner, a service on `localhost` addressed by name, or a container-mode service on the Docker network.

**Fix:** list the internal addresses on the rule that reaches them:

```yaml
version: "2"
rules:
  - name: "internal artifact mirror"
    allow:
      domains: ["artifacts.corp.example"]
      ports: [443]
      protocols: [https]
      allowed_ips: ["10.20.0.0/16"]   # IPs or CIDRs inside the internal ranges above
```

An entry only exempts connections that match its own rule. A rule whose `domains` names the address itself (`"10.0.0.5"`, or `"localhost"` for loopback) needs no entry. Public addresses are refused in `allowed_ips`, since they need no exemption. Going back to `version: "1"` also removes the guard, but it removes exfiltration detection, `methods` and `access` with it.

With `transparent: false` (env-var proxy mode), plain-HTTP requests under a `version: "2"` policy are checked when the proxy connects upstream. The proxy then resolves the name itself (through the DNS interceptor when `dns: true`) and connects only to the address it checked, preferring IPv4. Those requests no longer fall back to other addresses or reuse upstream connections.

### act job containers get no Docker socket

**Who is affected:** container mode with `workflow-file` (act) whose steps run `docker` themselves (`run: docker build`, `docker compose`, `docker run`).

act used to bind-mount the host's Docker socket into each job container. A step holding that socket can start a container with `--network host` and leave the firewall, so v3 runs act with `--container-daemon-socket -`. The default runner image, `catthehacker/ubuntu:act-22.04`, **does** have the `docker` CLI, so those steps worked on v2.2.1 and now fail with "Cannot connect to the Docker daemon". `uses: docker://…` steps and Docker container actions are started by act itself and still work.

**Fix:** run workflows that build or run images in native mode (`native-proxy/action`). There, containers a step starts are logged as IP metadata via the `FORWARD` chain but not TLS-inspected (see [Known blind spots](../README.md#known-blind-spots)). Pipeline-command mode is not a way around this: its pipeline container has neither the socket nor the CLI.

Container mode also drops `NET_RAW` from act job containers and pipeline-command containers, and sets `no-new-privileges` on pipeline-command containers. Tools that open raw sockets (such as `ping` where it relies on `NET_RAW`) or rely on setuid binaries such as `sudo` fail there.

### AAAA answers

**Who is affected:** enforce jobs that reach a destination only over IPv6.

In enforce, when the IPv4-only proxy is in the path — native mode with the defaults (`transparent: true`, `tls-intercept: true`) and container mode — the DNS interceptor answers `AAAA` queries for allowed names with an empty answer (NOERROR, no records), for every policy version. Clients then use IPv4, which the proxy inspects; IPv6 web and DoT traffic was already rejected there. Blocked names still get `NXDOMAIN` for every query type.

With `tls-intercept: false` or `transparent: false` there is no IPv4-only proxy, so `AAAA` queries are forwarded upstream like `A` queries. Under `version: "2"` the answer is checked by the internal-address guard: an internal `AAAA` record makes the interceptor answer `NXDOMAIN` in enforce and report `would_block` in monitor. In monitor, `AAAA` queries are always forwarded.

**Fix:** none for HTTP/HTTPS. A destination that has no IPv4 address cannot be reached in enforce with the proxy in the path; use `tls-intercept: false` for that workflow, or `monitor`.

### Native enforce setup fails if ip6tables REJECT rules cannot be added

**Who is affected:** native enforce on a runner whose kernel lacks `ip6t_REJECT` (or `multiport`), which in practice means some self-hosted or custom images. GitHub-hosted Ubuntu runners have both.

Setup used to ignore a failure to add the IPv6 REJECT rules (for uninspected IPv6 web/DoT in transparent mode, and for IPv6 DNS/DoT with `tls-intercept: false`). That left IPv6 egress unenforced without saying so. v3 fails setup with `::error title=PipeWarden setup::could not add the ip6tables … REJECT rules`. Setup still continues without IPv6 rules when `ip6tables` itself is unavailable.

**Fix:** use a runner kernel with `ip6t_REJECT` and `xt_multiport` (for example `modprobe ip6t_REJECT` in the runner image), or run that job in `mode: monitor`.

### Teardown fails enforce jobs when the boundary was not intact

**Who is affected:** native enforce jobs whose steps delete or flush iptables rules, or stop the proxy or DNS interceptor (usually via `sudo`).

Before removing anything, teardown checks with `iptables -C` / `ip6tables -C` that the rules setup installed are still present, and that the processes are still running:

| Setup | Checked |
| --- | --- |
| Transparent proxy (default) | The 80/443 redirects, the `NFW-CONN` LOG rule, `NFW-FWD` if setup added it, `NFW-CONN6` with ip6tables, and the proxy process. In enforce also the UDP 443 and 853 rejects, the IPv6 web/DoT rejects (with ip6tables), and with `dns: true` the direct-DNS rejects |
| `tls-intercept: false` | The `NFW-CONN` LOG rule and `NFW-CONN6` with ip6tables. In enforce with `dns: true` also the DNS and DoT rejects, IPv6 ones included with ip6tables |
| `transparent: false`, or `tls-intercept: false` without iptables | Nothing; reported as `not checked` |
| Container mode | No boundary check |

Wherever rules are checked with `dns: true`, the DNS interceptor must also be running. The result is written to `health.json` (`boundary_intact`, `boundary_missing`) and the Job Summary. A broken boundary fails the job in enforce (both the single-step action and the two-step teardown), is a warning in enforce with `fail-on-block: false`, and a warning in monitor.

**Fix:** do not remove PipeWarden's rules or stop its processes mid-job. A step that needs to change the firewall belongs in a job without PipeWarden, or before its setup step.

### Discovery-generated policies do not pin methods

**Who is affected:** anyone expecting a discovery run to write `methods` or `access` into the generated `network-policy.yml`.

Generated policies are still `version: "1"` and allow every method. When every request seen for an HTTP(S) destination was `GET`, `HEAD` or `OPTIONS`, the rule gets a comment instead of a restriction:

```yaml
  - name: "files.pythonhosted.org"
    allow:
      domains: ["files.pythonhosted.org"]
      ports: [443]
      protocols: [https]
      # access: read-only  # only reads seen; needs version "2"
```

One run cannot show a write that only happens on a cache miss or a release, so a pinned method would break the next such run. **Fix:** none needed. To restrict methods, set the policy to `version: "2"` and uncomment the line after checking that the host never needs a write. Some clients `POST` while only reading: `npm install` / `npm ci` (the audit, unless `--no-audit` or `audit=false`) and `git clone` / `git fetch` over HTTPS (`git-upload-pack`).

### Policy merge refuses mixed versions and keeps exfiltration

**Who is affected:** auto-resolved policies, that is `.github/pipewarden/common.network-policy.yml` merged with `.github/pipewarden/<workflow>.network-policy.yml`.

- **Mixed versions are refused.** If the two files declare different `version` values, setup fails with `Cannot merge policies with different versions: … Set every file to version "2" (add allowed_ips to rules that must reach private addresses), or every file to version "1".` On v2.2.1 the merged file was always written as `version: "1"`. **Fix:** give both files the same version; if you choose `"2"`, check the [internal-address guard](#internal-address-guard-on-every-version-2-rule) for the common rules too.
- **`exfiltration:` and `allow_request_body` survive the merge.** v2.2.1 dropped both, so payload scanning was silently off on the auto-resolved path. The `exfiltration:` block is now taken whole from the last file that declares one (the per-workflow file over common); a per-workflow file without one keeps common's. Same-name rules are still replaced whole by the per-workflow file. **What you may notice:** a configured `exfiltration: {mode: block}` now blocks.
- Each file's `mode:` is still ignored; the action's `mode` input decides.

An explicit `policy-file:` input is used as is and is not merged.

## New features

- **`allowed_ips`** (policy `version: "2"`): per-rule exemption from the internal-address guard, for internal hosts a rule is meant to reach.
- **`methods` and `access`** (policy `version: "2"`): restrict a rule to HTTP methods, e.g. `access: read-only` for `GET`, `HEAD`, `OPTIONS`. A request with another method is blocked with `X-PipeWarden-Block-Reason: method`.
- **`scripts/policy_boundary.py`**: an offline check that every repo policy stays inside an org-wide boundary policy, for use as a required status check. See [Org boundary check](../README.md#org-boundary-check-scriptspolicy_boundarypy).
- **Hash-pinned native install**: the native proxy installs mitmproxy from `native-proxy/requirements-lock.txt` with `--require-hashes`. A non-default `mitmproxy-version` installs without hashes and logs a warning.
- **DNS-tunnel heuristic**: the report flags query names that carry random-looking encoded data, or many such names under one zone. Report only; it never blocks.
- **Actionable denials**: the `403` body names the host, port, method, path and reason, and for a plain policy miss suggests a ready-to-paste rule. The `X-PipeWarden-Block-Reason` header carries `policy-miss`, `private-ip`, `method`, `domain-fronting`, `cert-identity` or `exfil`. Security blocks never suggest widening the policy, and the report's suggested rules leave them out too.

## What did not change

- Every action input and output keeps its name and meaning.
- Monitor mode still never blocks anything.
- `version: "1"` policies parse as before and are not checked against internal addresses.
- The report is still metadata-only; query strings are still redacted.
- PipeWarden still makes no network calls of its own: no telemetry, no account, no policy service, no data fetched at build time.
