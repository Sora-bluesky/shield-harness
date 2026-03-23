#!/usr/bin/env node
// sh-output-control.js — Output truncation + token budget tracking
// Spec: DETAILED_DESIGN.md §4.2
// Hook event: PostToolUse
// Matcher: "" (all tools)
// Target response time: < 20ms
"use strict";

const {
  readHookInput,
  allow,
  allowWithResult,
  readSession,
  writeSession,
} = require("./lib/sh-utils");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HOOK_NAME = "sh-output-control";

// Truncation limits per tool (bytes)
const TRUNCATION_LIMITS = {
  Bash: { max: 20 * 1024, head: 10 * 1024, tail: 5 * 1024 },
  Task: { max: 6 * 1024, head: 3 * 1024, tail: 2 * 1024 },
  _default: { max: 50 * 1024, head: 25 * 1024, tail: 10 * 1024 },
};

// Token budget thresholds
const BUDGET_WARNING_RATIO = 0.8;
const BUDGET_LIMIT_RATIO = 1.0;

// Rough token estimation: ~4 chars per token
const CHARS_PER_TOKEN = 4;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/**
 * Get truncation limits for a given tool.
 * @param {string} toolName
 * @returns {{ max: number, head: number, tail: number }}
 */
function getLimits(toolName) {
  return TRUNCATION_LIMITS[toolName] || TRUNCATION_LIMITS._default;
}

/**
 * Truncate output if it exceeds the limit.
 * @param {string} output
 * @param {string} toolName
 * @returns {{ text: string, truncated: boolean }}
 */
function truncateOutput(output, toolName) {
  if (!output) return { text: output, truncated: false };

  const limits = getLimits(toolName);
  if (output.length <= limits.max) {
    return { text: output, truncated: false };
  }

  const head = output.slice(0, limits.head);
  const tail = output.slice(-limits.tail);
  const omitted = output.length - limits.head - limits.tail;
  const notice = `\n\n--- [sh-output-control] ${omitted} bytes omitted (${output.length} total → ${limits.head + limits.tail} retained) ---\n\n`;

  return {
    text: head + notice + tail,
    truncated: true,
  };
}

/**
 * Estimate token count from character length.
 * @param {number} charCount
 * @returns {number}
 */
function estimateTokens(charCount) {
  return Math.ceil(charCount / CHARS_PER_TOKEN);
}

/**
 * Track token budget and return warning context if thresholds are crossed.
 * @param {number} outputSize - Size of tool output in characters
 * @returns {string|null} Warning context or null
 */
function trackTokenBudget(outputSize) {
  try {
    const session = readSession();
    const tokenBudget = session.token_budget;
    if (!tokenBudget || !tokenBudget.session_limit) return null; // No budget configured

    const budgetLimit = tokenBudget.session_limit;
    const currentUsage = tokenBudget.used || 0;
    const newTokens = estimateTokens(outputSize);
    const updatedUsage = currentUsage + newTokens;

    // Update session — write to token_budget.used (single source of truth)
    writeSession({
      ...session,
      token_budget: {
        ...tokenBudget,
        used: updatedUsage,
      },
    });

    const ratio = updatedUsage / budgetLimit;

    if (ratio >= BUDGET_LIMIT_RATIO) {
      return `[${HOOK_NAME}] トークン予算を超過しました（${updatedUsage}/${budgetLimit} tokens）。ユーザー確認が必要です。`;
    }
    if (ratio >= BUDGET_WARNING_RATIO) {
      return `[${HOOK_NAME}] トークン予算の 80% に到達しました（${updatedUsage}/${budgetLimit} tokens）。`;
    }

    return null;
  } catch {
    // Budget tracking failure is non-blocking
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

try {
  const input = readHookInput();
  const { toolName, toolResult } = input;

  const resultStr =
    typeof toolResult === "string" ? toolResult : JSON.stringify(toolResult);

  // Truncate if necessary
  const { text, truncated } = truncateOutput(resultStr, toolName);

  // Track token budget
  const budgetWarning = trackTokenBudget(resultStr ? resultStr.length : 0);

  // Build context messages
  const context = [];
  if (truncated) {
    context.push(
      `[${HOOK_NAME}] ${toolName} の出力を切り詰めました（制限超過）。`,
    );
  }
  if (budgetWarning) {
    context.push(budgetWarning);
  }

  // Output result
  if (truncated) {
    // Must use allowWithResult to replace the tool output
    if (context.length > 0) {
      // allowWithResult doesn't support additionalContext, so prepend warnings to the result
      const contextHeader = context.join("\n") + "\n\n";
      allowWithResult(contextHeader + text);
    } else {
      allowWithResult(text);
    }
  } else if (context.length > 0) {
    allow(context.join("\n"));
  } else {
    allow();
  }
} catch (_err) {
  // Operational hook — on error, pass through the original output.
  allow();
}

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  TRUNCATION_LIMITS,
  truncateOutput,
  estimateTokens,
  getLimits,
  trackTokenBudget,
};
