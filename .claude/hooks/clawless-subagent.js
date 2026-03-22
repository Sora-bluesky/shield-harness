#!/usr/bin/env node
// clawless-subagent.js — Subagent constraint injection
// Spec: DETAILED_DESIGN.md §5.6
// Event: SubagentStart
// Target response time: < 10ms
"use strict";

const {
  readHookInput,
  allow,
  deny,
  readSession,
  appendEvidence,
} = require("./lib/clawless-utils");

const HOOK_NAME = "clawless-subagent";
const SUBAGENT_BUDGET_RATIO = 0.25; // 25% cap per subagent

// ---------------------------------------------------------------------------
// Budget Calculation
// ---------------------------------------------------------------------------

/**
 * Calculate subagent token budget from session state.
 * @param {Object} session
 * @returns {number}
 */
function calculateSubagentBudget(session) {
  const budget =
    (session.token_budget && session.token_budget.session_limit) || 200000;
  const used = (session.token_budget && session.token_budget.used) || 0;
  const remaining = Math.max(0, budget - used);
  return Math.floor(remaining * SUBAGENT_BUDGET_RATIO);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

try {
  const input = readHookInput();
  const session = readSession();

  const subagentBudget = calculateSubagentBudget(session);

  // Record evidence
  try {
    appendEvidence({
      hook: HOOK_NAME,
      event: "SubagentStart",
      decision: "allow",
      subagent_budget: subagentBudget,
      session_id: input.sessionId,
    });
  } catch {
    // Non-blocking
  }

  // Inject constraints via additionalContext
  const constraints = [
    "【Clawless サブエージェント制約】",
    `- トークン予算: ${subagentBudget.toLocaleString()} tokens（セッション残量の 25%）`,
    "- ファイル書込: プロジェクトルート内のみ",
    "- ネットワーク: 禁止（WebFetch 不可）",
    "- 他のサブエージェント起動: 禁止",
  ].join("\n");

  allow(constraints);
} catch (err) {
  // SECURITY hook — fail-close
  process.stdout.write(
    JSON.stringify({
      reason: `[${HOOK_NAME}] Hook error (fail-close): ${err.message}`,
    }),
  );
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  SUBAGENT_BUDGET_RATIO,
  calculateSubagentBudget,
};
