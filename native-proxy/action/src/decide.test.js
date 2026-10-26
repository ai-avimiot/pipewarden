// Unit test for the enforce-exit decision (run via `npm test`, no framework).
// This is the single-step action's stop-the-pipeline logic; a regression here
// would silently let blocked connections pass, so it is exercised in CI.
const assert = require("node:assert");
const { decideEnforceExit } = require("./decide");

const cases = [
  // [name, args, expected shouldFail]
  ["enforce + blocked + default -> fail", { blockedCount: 2, mode: "enforce", failOnBlock: undefined }, true],
  ["enforce + blocked + fail-on-block false -> continue", { blockedCount: 2, mode: "enforce", failOnBlock: "false" }, false],
  ["enforce + blocked + FALSE (case-insensitive) -> continue", { blockedCount: 2, mode: "enforce", failOnBlock: "FALSE" }, false],
  ["enforce + blocked + 'true' -> fail", { blockedCount: 1, mode: "enforce", failOnBlock: "true" }, true],
  ["enforce + zero blocked -> pass", { blockedCount: 0, mode: "enforce", failOnBlock: "true" }, false],
  ["monitor + blocked -> never fail", { blockedCount: 9, mode: "monitor", failOnBlock: "true" }, false],
  ["enforce + unverified + zero blocked -> fail", { blockedCount: 0, mode: "enforce", failOnBlock: "true", unverified: true }, true],
  ["enforce + unverified + fail-on-block false -> continue", { blockedCount: 0, mode: "enforce", failOnBlock: "false", unverified: true }, false],
  ["monitor + unverified -> never fail", { blockedCount: 0, mode: "monitor", failOnBlock: "true", unverified: true }, false],
  ["enforce + boundary broken + zero blocked -> fail", { blockedCount: 0, mode: "enforce", failOnBlock: undefined, boundaryBroken: true }, true],
  ["enforce + boundary broken + fail-on-block false -> continue", { blockedCount: 0, mode: "enforce", failOnBlock: "false", boundaryBroken: true }, false],
  ["monitor + boundary broken -> never fail", { blockedCount: 0, mode: "monitor", failOnBlock: "true", boundaryBroken: true }, false],
];

let failures = 0;
for (const [name, args, expected] of cases) {
  const { shouldFail } = decideEnforceExit(args);
  try {
    assert.strictEqual(shouldFail, expected, name);
    console.log(`ok   - ${name}`);
  } catch (e) {
    failures++;
    console.error(`FAIL - ${name} (got shouldFail=${shouldFail}, want ${expected})`);
  }
}

// status/blockedInEnforce sanity
assert.strictEqual(decideEnforceExit({ blockedCount: 3, mode: "enforce", failOnBlock: "true" }).status, "fail");
assert.strictEqual(decideEnforceExit({ blockedCount: 0, mode: "enforce", failOnBlock: "true" }).status, "pass");
assert.strictEqual(decideEnforceExit({ blockedCount: 0, mode: "enforce", failOnBlock: "false", boundaryBroken: true }).status, "fail");

if (failures > 0) {
  console.error(`${failures} decision test(s) failed`);
  process.exit(1);
}
console.log("all decision tests passed");
