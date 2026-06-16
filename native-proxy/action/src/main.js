// main.js — Thin Node.js wrapper that runs setup.sh
// This enables the "post:" hook in action.yml for automatic teardown.
const { execFileSync } = require("child_process");
const path = require("path");

// At runtime this file is bundled to native-proxy/action/dist/, so the
// native-proxy root (holding setup.sh/teardown.sh) is two levels up.
const actionDir = __dirname;
const nativeProxyDir = path.resolve(actionDir, "..", "..");

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
