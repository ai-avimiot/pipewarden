// Pure decision for whether an enforce-mode run should fail the job.
// Extracted so it can be unit-tested without running the post-step's teardown.
//
// A run fails only when the mode is enforce, at least one connection was
// blocked (or the run could not be verified: no report, unparsable log
// lines, or a firewall boundary found broken at teardown), and fail-on-block
// was not opted out. Monitor mode never fails.
function decideEnforceExit({ blockedCount, mode, failOnBlock, unverified = false, boundaryBroken = false }) {
  const blocked = Number(blockedCount) || 0;
  const failOn = String(failOnBlock == null ? "true" : failOnBlock).toLowerCase() !== "false";
  const blockedInEnforce = mode === "enforce" && blocked > 0;
  const unverifiedInEnforce = mode === "enforce" && Boolean(unverified);
  const boundaryBrokenInEnforce = mode === "enforce" && Boolean(boundaryBroken);
  const failing = blockedInEnforce || unverifiedInEnforce || boundaryBrokenInEnforce;
  return {
    blockedInEnforce,
    unverifiedInEnforce,
    boundaryBrokenInEnforce,
    status: failing ? "fail" : "pass",
    shouldFail: failing && failOn,
  };
}

module.exports = { decideEnforceExit };
