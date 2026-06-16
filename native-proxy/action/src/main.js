// main.js — Thin Node.js wrapper that runs setup.sh
// This enables the "post:" hook in action.yml for automatic teardown.
const { execFileSync } = require("child_process");
const path = require("path");

// GITHUB_ACTION_PATH points at the action dir (native-proxy/action) regardless
// of where this file is bundled; the native-proxy root (setup.sh/teardown.sh) is
// one level up. Fall back to __dirname math for the bundled dist/<x>/index.js.
const actionDir = process.env.GITHUB_ACTION_PATH || path.resolve(__dirname, "..", "..", "..");
const nativeProxyDir = path.resolve(actionDir, "..");

const env = {
  ...process.env,
  INPUT_POLICY_FILE: process.env.INPUT_POLICY_FILE || "network-policy.yml",
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
