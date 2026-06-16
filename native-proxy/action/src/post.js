// post.js — Runs teardown.sh automatically after the job completes.
// GitHub Actions guarantees this runs even if earlier steps fail (post-if: always()).
const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const { DefaultArtifactClient } = require("@actions/artifact");

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

// Read outputs from teardown and ensure they're set as action outputs
const reportDir = "/tmp/report";
const githubOutput = process.env.GITHUB_OUTPUT;

if (githubOutput && fs.existsSync(reportDir)) {
  try {
    const reportJson = path.join(reportDir, "report.json");
    if (fs.existsSync(reportJson)) {
      const report = JSON.parse(fs.readFileSync(reportJson, "utf8"));
      const blockedCount = report.blocked_connections || 0;
      const mode = process.env.NFW_MODE || "monitor";
      const status = (mode === "enforce" && blockedCount > 0) ? "fail" : "pass";
      
      // Append outputs (teardown.sh may have already written them, but ensure they're there)
      const outputLines = [
        `report-path=${reportDir}`,
        `blocked-count=${blockedCount}`,
        `status=${status}`
      ];
      
      fs.appendFileSync(githubOutput, outputLines.join("\n") + "\n");
      
      console.log(`NFW outputs: status=${status}, blocked=${blockedCount}, report=${reportDir}`);
    }
  } catch (e) {
    console.log(`::warning::Could not read report outputs: ${e.message}`);
  }
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
  const uploadSetting = process.env.NFW_UPLOAD_ARTIFACT || process.env.INPUT_UPLOAD_ARTIFACT || "true";
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
  const name = process.env.NFW_ARTIFACT_NAME || process.env.INPUT_ARTIFACT_NAME || "network-report";
  try {
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

uploadReport().finally(() => {
  // Exit 0 so the post-action never fails the job; teardown exit code is informational.
  process.exit(0);
});
