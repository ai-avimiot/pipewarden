# Multi-job workflows

How to cover every job in a workflow with PipeWarden, share one policy, and
consolidate the reports.

## The one thing to know first

**Each job runs on its own runner.** A GitHub workflow job is a fresh VM with its
own filesystem and its own network namespace. PipeWarden's proxy is set up *per
runner*, so:

- One proxy **cannot** see another job's traffic. There is no single proxy that
  spans the workflow — that's the GitHub execution model, not a PipeWarden limit.
- There is **no live shared state** between jobs. The only cross-job channels
  GitHub offers are **artifacts** and **job outputs**, so anything you want to
  share (e.g. a consolidated report) has to travel through one of those, after the
  fact.

Everything below follows from that.

## 1. Cover every job

Add the action to each job you want monitored. There's nothing workflow-global to
configure — a job is only covered if it runs the action:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ai-avimiot/pipewarden/native-proxy/action@v1
        with:
          mode: monitor
      - run: npm ci && npm test

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ai-avimiot/pipewarden/native-proxy/action@v1   # cover this job too
        with:
          mode: monitor
      - run: npm run e2e
```

## 2. Share one policy across all jobs

You already get this for free. [Auto-resolution](../README.md#where-policies-live-auto-resolution)
keys the policy on the **workflow file name**, not the job. Every job in `ci.yml`
resolves to the same effective allowlist:

```
.github/pipewarden/
  common.network-policy.yml    # shared baseline — applies to every job
  ci.network-policy.yml        # rules for ci.yml — applies to every job in ci.yml
```

So leaving `policy-file` unset in each job is enough — `build` and `e2e` above are
both governed by `common ∪ ci`.

### The tradeoff: union, not least-privilege

One per-workflow policy must be the **union** of every job's traffic. If `build`
talks to npm and `deploy` talks to AWS, the shared policy allows *both* in *both*
jobs — `build` is permitted to reach AWS even though it never should. That's
usually an acceptable trade for one file to maintain.

When you want tighter per-job scoping, set `policy-file:` explicitly on the jobs
that differ:

```yaml
  deploy:
    steps:
      - uses: ai-avimiot/pipewarden/native-proxy/action-setup@v1
        with:
          policy-file: .github/pipewarden/deploy.network-policy.yml   # tighter, deploy-only
```

This bypasses auto-resolution and uses exactly that file.

### `appears: sometimes` is what makes a shared policy quiet

Because one policy covers several jobs, **any single job legitimately won't touch
most of the rules** — the npm rules are dead weight in the deploy job, the AWS
rules are dead weight in the build job. Without help, every run would flag those as
`unused (candidate for removal)`.

Mark cross-job and conditional destinations `appears: sometimes` so they're not
reported as unused when a given job doesn't hit them (report-only — it does **not**
change what's allowed):

```yaml
  - name: "AWS (deploy job only)"
    appears: sometimes
    allow:
      domains: ["*.amazonaws.com"]
      ports: [443]
      protocols: [https]
```

This is exactly the multi-job / matrix case the `appears` field exists for.

## 3. Matrix jobs: give each leg a unique artifact name

The report artifact defaults to `network-report`. In a matrix (or any time more
than one job uploads), every leg would try to upload under the same name and
collide. Make the name unique per leg:

```yaml
  test:
    strategy:
      matrix:
        node: [18, 20, 22]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ai-avimiot/pipewarden/native-proxy/action@v1
        with:
          mode: monitor
          artifact-name: network-report-node${{ matrix.node }}
      - uses: actions/setup-node@v6
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci && npm test
```

Use `${{ github.job }}` for distinct (non-matrix) jobs, or the matrix value(s) for
matrix legs. Set `upload-artifact: false` on jobs whose report you don't need.

## 4. Consolidate the reports (optional)

There is no built-in workflow-level report — each job produces its own. To get a
single "what did the whole workflow talk to" view, add an aggregation job that
waits for the others, downloads every report artifact, and merges them:

```yaml
  pipewarden-report:
    needs: [build, e2e, test]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
        with:
          pattern: network-report-*      # all per-job/per-matrix reports
          path: reports/
      # merge reports/*/report.json into one view however you like, e.g.:
      - run: |
          find reports -name report.json -print
          # jq -s 'add' reports/*/report.json > merged-report.json   # adapt to your needs
      - uses: actions/upload-artifact@v7
        with:
          name: network-report-merged
          path: reports/
```

> Aggregation is a manual step today — PipeWarden does not yet ship a first-class
> "merge all job reports" action. The per-job reports are complete and
> machine-readable (`report.json`), so a small `jq`/script step is enough until
> that lands.

## Summary

| Goal | How |
|------|-----|
| Cover every job | Add the action to each job |
| One policy for all jobs | Leave `policy-file` unset — resolves per workflow file |
| Tighter per-job policy | Set `policy-file:` explicitly on that job |
| Quiet "unused" reports | Mark cross-job/conditional rules `appears: sometimes` |
| Matrix without collisions | Unique `artifact-name:` per leg |
| One combined report | Aggregation job: `needs:` all, download `network-report-*`, merge |
| Live shared state across jobs | Not possible — separate runners; use artifacts after the fact |
