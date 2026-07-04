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

// Keep the default in lockstep with setup.sh (MITMPROXY_VERSION) and
// proxy/Dockerfile.
const MITMPROXY_VERSION =
  process.env["INPUT_MITMPROXY-VERSION"] || process.env.INPUT_MITMPROXY_VERSION || "12.2.3";

// Pip wheel cache shared with setup.sh's `pip install mitmproxy` (setup.sh
// forwards it through sudo as PIP_CACHE_DIR). Caching wheels rather than
// installed site-packages keeps the cache valid across runner images.
const PIP_CACHE_DIR = "/tmp/pipewarden-pip-cache";

function appendState(lines) {
  // Post-steps don't get INPUT_*; GITHUB_ENV is the state channel this action
  // already uses for NFW_* values.
  if (!process.env.GITHUB_ENV) return;
  fs.appendFileSync(process.env.GITHUB_ENV, lines.join("\n") + "\n");
}

// Restore the pip wheel cache. Strictly best-effort: any failure (cache
// service unavailable, bundling regression, network) degrades to a warning —
// setup.sh just downloads from PyPI as before.
async function restorePipCache() {
  const cacheSetting = process.env.INPUT_CACHE || "true";
  if (cacheSetting.toLowerCase() === "false") {
    console.log("PipeWarden: pip cache disabled (cache: false)");
    return;
  }
  try {
    const cache = await import("@actions/cache");
    if (!cache.isFeatureAvailable()) {
      console.log("PipeWarden: cache service unavailable, skipping pip cache");
      return;
    }
    const key = `pipewarden-pip-${process.env.RUNNER_OS || process.platform}-${process.env.ImageOS || "img"}-mitmproxy-${MITMPROXY_VERSION}`;
    const hit = await cache.restoreCache([PIP_CACHE_DIR], key);
    if (hit) {
      console.log(`PipeWarden: restored pip cache (${key})`);
    } else {
      console.log(`PipeWarden: pip cache miss (${key}) — will save after setup`);
      // Tell the post-step to save the freshly populated cache.
      appendState([`NFW_PIP_CACHE_SAVE_KEY=${key}`, `NFW_PIP_CACHE_DIR=${PIP_CACHE_DIR}`]);
    }
  } catch (e) {
    console.log(`::warning::PipeWarden pip cache restore failed (continuing without): ${e.message}`);
  }
}

async function main() {
  await restorePipCache();

  const env = {
    ...process.env,
    INPUT_POLICY_FILE: process.env.INPUT_POLICY_FILE || "",
    INPUT_MODE: process.env.INPUT_MODE || "monitor",
    INPUT_PROXY_PORT: process.env["INPUT_PROXY-PORT"] || "8080",
    INPUT_DNS: process.env.INPUT_DNS || "true",
    INPUT_TRANSPARENT: process.env.INPUT_TRANSPARENT || "true",
    // Dashed input names map to dashed env keys (e.g. INPUT_FAIL-FAST).
    INPUT_FAIL_FAST: process.env["INPUT_FAIL-FAST"] || "false",
    INPUT_GITHUB_TOKEN: process.env["INPUT_GITHUB-TOKEN"] || "",
    INPUT_ACTION_PATH: nativeProxyDir,
    INPUT_MITMPROXY_VERSION: MITMPROXY_VERSION,
    PIP_CACHE_DIR,
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
  try {
    // Note: GitHub maps dashed input names to dashed env keys (e.g. artifact-name
    // -> INPUT_ARTIFACT-NAME), not underscores — same as INPUT_PROXY-PORT above.
    const uploadArtifact = process.env["INPUT_UPLOAD-ARTIFACT"] || "true";
    const artifactName = process.env["INPUT_ARTIFACT-NAME"] || "network-report";
    appendState([`NFW_UPLOAD_ARTIFACT=${uploadArtifact}`, `NFW_ARTIFACT_NAME=${artifactName}`]);
  } catch (e) {
    console.log(`::warning::PipeWarden could not persist artifact settings: ${e.message}`);
  }
}

main();
