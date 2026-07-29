// Pure decision for whether an enforce-mode run should fail the job.
// Extracted so it can be unit-tested without running the post-step's teardown.
//
// A run fails only when the mode is enforce, at least one connection was
// blocked, and fail-on-block was not opted out. Monitor mode never fails; a
// clean enforce run never fails.
function decideEnforceExit({ blockedCount, mode, failOnBlock }) {
  const blocked = Number(blockedCount) || 0;
  const failOn = String(failOnBlock == null ? "true" : failOnBlock).toLowerCase() !== "false";
  const blockedInEnforce = mode === "enforce" && blocked > 0;
  return {
    blockedInEnforce,
    status: blockedInEnforce ? "fail" : "pass",
    shouldFail: blockedInEnforce && failOn,
  };
}

module.exports = { decideEnforceExit };
