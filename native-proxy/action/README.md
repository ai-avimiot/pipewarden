# Native Proxy Action (with Automatic Teardown)

This is a unified GitHub Action that sets up the PipeWarden native proxy and **automatically tears it down** via a post-action hook.

## How It Works

This action uses GitHub Actions' `post:` feature to guarantee cleanup:

1. **Main action** (`main.js`): Runs `setup.sh` to start the proxy
2. **Your workflow steps**: Run with network monitoring active
3. **Post-action** (`post.js`): Automatically runs `teardown.sh` at job end (even on failure)

The post-action is **guaranteed to run** via `post-if: always()`, so you never need a manual teardown step.

## Usage

```yaml
- name: "🔒 PipeWarden: Start network monitoring"
  uses: ./native-proxy/action
  with:
    policy-file: network-policy.yml
    mode: monitor
    dns: 'true'
    transparent: 'true'

# Your CI steps here
- name: Run tests
  run: npm test

# Post-action automatically runs here:
# - Stops proxy and DNS server
# - Generates report
# - Displays connection log and summary
# - Sets outputs (status, blocked-count, report-path)
# - Uploads the report as the `network-report` artifact (no extra step needed)
```

## Inputs

- `policy-file`: Path to network-policy.yml (default: `network-policy.yml`)
- `mode`: `monitor` (log only) or `enforce` (block unauthorized traffic) (default: `monitor`)
- `proxy-port`: Port for mitmproxy (default: `8080`)
- `dns`: Enable DNS interception (default: `true`)
- `transparent`: Enable iptables transparent proxy (default: `true`)
- `upload-artifact`: Upload the report (`/tmp/report/`) as a build artifact at teardown (default: `true`)
- `artifact-name`: Name of the uploaded report artifact (default: `network-report`)

## Outputs

Outputs are set by the post-action after teardown completes:

- `report-path`: Path to the generated report directory
- `blocked-count`: Number of blocked connections
- `status`: `pass` or `fail` (fail when mode is enforce and blocked connections > 0)

**Note:** These outputs are only available in the post-action context, not in subsequent workflow steps (GitHub Actions limitation).

## What the Post-Action Does Automatically

When your job completes (or fails), the post-action automatically:

1. ✅ Stops the mitmproxy process
2. ✅ Stops the DNS server (if enabled)
3. ✅ Flushes iptables rules (if transparent mode)
4. ✅ Restores systemd-resolved
5. ✅ Parses iptables logs and merges with connection log
6. ✅ Generates the network monitoring report
7. ✅ **Displays connection log (first 20 entries)**
8. ✅ **Displays report summary**
9. ✅ Sets outputs (status, blocked-count, report-path)
10. ✅ Uploads the report as the `network-report` artifact (set `upload-artifact: false` to skip, or `artifact-name:` to rename)
11. ✅ Cleans up CA certificates

> The artifact upload happens **inside the post-action**. Don't add your own `actions/upload-artifact` step for `/tmp/report/` with the single-step action — the report is generated in this post-step, which runs *after* all your job steps, so an in-job upload step would find nothing.

The post-action approach has several advantages:

1. **Guaranteed cleanup**: Teardown runs even if your tests fail
2. **Simpler workflows**: No need for `if: always()` on teardown steps
3. **No manual steps**: Just one action, automatic cleanup
4. **Proper exit codes**: Teardown can exit with error in enforce mode without failing the post-action itself

## Migration from Setup/Teardown Pattern

**Old pattern (two steps):**
```yaml
- uses: ./native-proxy/action-setup
  with: { policy-file: ..., mode: monitor }
# ... your steps ...
- uses: ./native-proxy/action-teardown
  if: always()  # Easy to forget!
```

**New pattern (one step):**
```yaml
- uses: ./native-proxy/action
  with: { policy-file: ..., mode: monitor }
# ... your steps ... (teardown happens automatically)
```

The old `action-setup` and `action-teardown` composite actions are still available for backward compatibility.
