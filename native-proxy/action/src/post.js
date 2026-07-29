// post.js — Runs teardown.sh automatically after the job completes.
// GitHub Actions guarantees this runs even if earlier steps fail (post-if: always()).
const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const { decideEnforceExit } = require("./decide");
// @actions/artifact v6 is ESM-only (its exports map has no "require" entry),
// so it must be loaded with dynamic import() — see uploadReport().

// Resolve the native-proxy root (holds setup.sh/teardown.sh). GITHUB_ACTION_PATH
// is only set for composite actions, not JS actions, so for the JS bundle we
// derive it from __dirname: this file is bundled at native-proxy/action/dist/<x>/,
// three levels below native-proxy.
const nativeProxyDir = process.env.GITHUB_ACTION_PATH
  ? path.resolve(process.env.GITHUB_ACTION_PATH, "..")
  : path.resolve(__dirname, "..", "..", "..");

const env = {
  ...process.env,
  INPUT_ACTION_PATH: nativeProxyDir,
};

let teardownExitCode = 0;
try {
  execFileSync("bash", [path.join(nativeProxyDir, "teardown.sh")], {
    env,
    stdio: "inherit",
  });
} catch (err) {
  teardownExitCode = err.status || 1;
  // Don't fail the post-action itself — just warn
  console.log(`::warning::NFW teardown exited with code ${teardownExitCode}`);
}

// Read outputs from teardown and decide whether the blocked traffic should
// fail the job. This is the single-step action's enforcement point: the
// teardown runs in this post-step, so the block decision has to be made and
// acted on here. Exiting non-zero at the end of a post-step fails the job.
const reportDir = "/tmp/report";
const githubOutput = process.env.GITHUB_OUTPUT;

// Set when enforce mode blocked at least one connection and fail-on-block is
// not disabled — propagated to a non-zero process exit at the very end (after
// best-effort artifact upload and cache save).
let enforceViolation = false;

try {
  const reportJson = path.join(reportDir, "report.json");
  if (fs.existsSync(reportJson)) {
    const report = JSON.parse(fs.readFileSync(reportJson, "utf8"));
    // total_blocked includes DNS-layer blocks (NXDOMAIN); fall back to
    // blocked_connections for reports produced before that field existed.
    const blockedCount =
      report.total_blocked != null ? report.total_blocked : (report.blocked_connections || 0);
    const mode = process.env.NFW_MODE || "monitor";
    // setup.sh persists NFW_FAIL_ON_BLOCK to GITHUB_ENV, so the post-step sees it.
    const decision = decideEnforceExit({
      blockedCount,
      mode,
      failOnBlock: process.env.NFW_FAIL_ON_BLOCK,
    });

    if (githubOutput) {
      const outputLines = [
        `report-path=${reportDir}`,
        `blocked-count=${blockedCount}`,
        `status=${decision.status}`,
      ];
      fs.appendFileSync(githubOutput, outputLines.join("\n") + "\n");
    }
    console.log(`NFW outputs: status=${decision.status}, blocked=${blockedCount}, report=${reportDir}`);

    if (decision.shouldFail) {
      enforceViolation = true;
      console.log(
        `::error::PipeWarden: blocked ${blockedCount} connection(s) in enforce mode — stopping the pipeline. ` +
        "Set fail-on-block: false to block the traffic but let the job continue, or use monitor mode to only observe."
      );
    } else if (decision.blockedInEnforce) {
      console.log(
        `::warning::PipeWarden: blocked ${blockedCount} connection(s) in enforce mode; fail-on-block is false, so the job continues. The traffic was still blocked.`
      );
    }
  }
} catch (e) {
  console.log(`::warning::Could not read report outputs: ${e.message}`);
}

// Display monitoring results
console.log("\n📊 === Network Monitoring Results ===\n");

const logDir = process.env.NFW_LOG_DIR || "/tmp/monitor-logs";
const connLog = path.join(logDir, "connections.jsonl");
if (fs.existsSync(connLog)) {
  console.log("Connection log (first 20 entries):");
  try {
    const lines = fs.readFileSync(connLog, "utf8").split("\n").filter(l => l.trim()).slice(0, 20);
    if (lines.length > 0) {
      lines.forEach(line => console.log(line));
    } else {
      console.log("(empty)");
    }
  } catch (e) {
    console.log("(could not read log)");
  }
} else {
  console.log("Connection log: (not found)");
}

console.log("\n");

const summaryTxt = path.join(reportDir, "summary.txt");
if (fs.existsSync(summaryTxt)) {
  console.log("Network monitoring report:");
  try {
    console.log(fs.readFileSync(summaryTxt, "utf8"));
  } catch (e) {
    console.log("(could not read report)");
  }
} else {
  console.log("Report: (not generated)");
}

console.log("\n📤 Report available at: /tmp/report/");

// Upload the report as a build artifact directly from this post-step.
// This is the only place that works for the single-step action: the report is
// generated here (teardown), which runs AFTER all normal job steps — so an
// in-job `upload-artifact` step would run before the report exists. Doing it
// here means the single-step action produces a downloadable artifact with no
// extra workflow steps. Best-effort: never fail the job on upload problems.
async function uploadReport() {
  // Post-steps don't get INPUT_*; main.js persisted these to GITHUB_ENV as NFW_*.
  const uploadSetting = process.env.NFW_UPLOAD_ARTIFACT || process.env["INPUT_UPLOAD-ARTIFACT"] || "true";
  const enabled = uploadSetting.toLowerCase() !== "false";
  if (!enabled) {
    console.log("PipeWarden: artifact upload disabled (upload-artifact: false)");
    return;
  }
  if (!fs.existsSync(reportDir)) {
    console.log("PipeWarden: no /tmp/report/ to upload");
    return;
  }
  let files = [];
  try {
    files = fs.readdirSync(reportDir)
      .map((f) => path.join(reportDir, f))
      .filter((f) => {
        try { return fs.statSync(f).isFile(); } catch (e) { return false; }
      });
  } catch (e) {
    console.log(`::warning::PipeWarden could not list report dir: ${e.message}`);
    return;
  }
  if (files.length === 0) {
    console.log("PipeWarden: report dir is empty, nothing to upload");
    return;
  }
  if (!process.env.ACTIONS_RUNTIME_TOKEN && !process.env.ACTIONS_RESULTS_URL) {
    console.log("PipeWarden: no Actions artifact backend available, skipping upload");
    return;
  }
  const name =
    process.env.NFW_ARTIFACT_NAME ||
    process.env["INPUT_ARTIFACT-NAME"] ||
    `network-report-${process.env.GITHUB_JOB || "job"}`;
  try {
    const { DefaultArtifactClient } = await import("@actions/artifact");
    const client = new DefaultArtifactClient();
    await client.uploadArtifact(name, files, reportDir);
    console.log(`::notice title=PipeWarden::Uploaded '${name}' artifact (${files.length} files from /tmp/report/).`);
  } catch (e) {
    console.log(
      `::warning::PipeWarden could not upload the '${name}' artifact: ${e.message}. ` +
      "The report is still in the job summary and /tmp/report/."
    );
  }
}

// Save the pip wheel cache when main.js recorded a cache miss. Best-effort:
// a failed save only costs the next run a PyPI download, never the job.
async function savePipCache() {
  const key = process.env.NFW_PIP_CACHE_SAVE_KEY;
  const dir = process.env.NFW_PIP_CACHE_DIR;
  if (!key || !dir) return; // hit (or caching disabled/unavailable) — nothing to save
  if (!fs.existsSync(dir)) {
    console.log("PipeWarden: pip cache dir empty, nothing to save");
    return;
  }
  try {
    const cache = await import("@actions/cache");
    if (!cache.isFeatureAvailable()) return;
    const size = execFileSync("du", ["-sh", dir]).toString().split("\t")[0];
    const cacheId = await cache.saveCache([dir], key);
    if (cacheId === -1) {
      console.log(`::warning::PipeWarden pip cache save was skipped by the cache service (${key}, ${size})`);
    } else {
      console.log(`PipeWarden: saved pip cache (${key}, ${size}, id ${cacheId})`);
    }
  } catch (e) {
    console.log(`::warning::PipeWarden pip cache save failed: ${e.message}`);
  }
}

savePipCache()
  .then(() => uploadReport())
  .finally(() => {
    // Cache save and artifact upload are best-effort and must never fail the
    // job on their own — so they run first and their errors are swallowed.
    // The ONLY thing that fails the job here is an enforce-mode policy
    // violation (blocked connection with fail-on-block enabled); that is the
    // whole point of enforce mode. Incidental teardown errors stay
    // informational (they do not set enforceViolation).
    process.exit(enforceViolation ? 1 : 0);
  });
