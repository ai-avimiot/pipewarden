// main.js — Thin Node.js wrapper that runs setup.sh
// This enables the "post:" hook in action.yml for automatic teardown.
const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

// Resolve the native-proxy root (holds setup.sh/teardown.sh). GITHUB_ACTION_PATH
// is only set for composite actions, not JS actions, so for the JS bundle we
// derive it from __dirname: this file is bundled at native-proxy/action/dist/<x>/,
// three levels below native-proxy.
const nativeProxyDir = process.env.GITHUB_ACTION_PATH
  ? path.resolve(process.env.GITHUB_ACTION_PATH, "..")
  : path.resolve(__dirname, "..", "..", "..");

const env = {
  ...process.env,
  INPUT_POLICY_FILE: process.env.INPUT_POLICY_FILE || "",
  INPUT_MODE: process.env.INPUT_MODE || "monitor",
  INPUT_PROXY_PORT: process.env["INPUT_PROXY-PORT"] || "8080",
  INPUT_DNS: process.env.INPUT_DNS || "true",
  INPUT_TRANSPARENT: process.env.INPUT_TRANSPARENT || "true",
  INPUT_ACTION_PATH: nativeProxyDir,
};

try {
  execFileSync("bash", [path.join(nativeProxyDir, "setup.sh")], {
    env,
    stdio: "inherit",
  });
} catch (err) {
  process.exitCode = 1;
}

// Persist artifact settings for the post-step. JS-action post-steps do NOT
// receive INPUT_* env vars, but values written to GITHUB_ENV here are available
// to the post-step (same mechanism setup.sh uses for NFW_* state).
if (process.env.GITHUB_ENV) {
  try {
    // Note: GitHub maps dashed input names to dashed env keys (e.g. artifact-name
    // -> INPUT_ARTIFACT-NAME), not underscores — same as INPUT_PROXY-PORT above.
    const uploadArtifact = process.env["INPUT_UPLOAD-ARTIFACT"] || "true";
    const artifactName = process.env["INPUT_ARTIFACT-NAME"] || "network-report";
    fs.appendFileSync(
      process.env.GITHUB_ENV,
      `NFW_UPLOAD_ARTIFACT=${uploadArtifact}\nNFW_ARTIFACT_NAME=${artifactName}\n`
    );
  } catch (e) {
    console.log(`::warning::PipeWarden could not persist artifact settings: ${e.message}`);
  }
}
