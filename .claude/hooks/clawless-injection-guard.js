#!/usr/bin/env node
// clawless-injection-guard.js — 9-category 50+ pattern injection detection (Injection Stage 2)
// Spec: DETAILED_DESIGN.md §3.3
// Hook event: PreToolUse
// Matcher: Bash|Edit|Write|Read|WebFetch
// Target response time: < 50ms
"use strict";

const {
  readHookInput,
  allow,
  deny,
  nfkcNormalize,
  loadPatterns,
  appendEvidence,
} = require("./lib/clawless-utils");

// Zero-width character regex (checked BEFORE pattern matching to prevent bypass)
// U+200B-200F: zero-width space, non-joiner, joiner, LTR mark, RTL mark
// U+2028-2029: line separator, paragraph separator
// U+2060-2064: word joiner, invisible operators
// U+FEFF: byte order mark
// U+00AD: soft hyphen
// U+034F: combining grapheme joiner
const ZERO_WIDTH_RE =
  /[\u200b-\u200f\u2028\u2029\u2060-\u2064\ufeff\u00ad\u034f]/;

/**
 * Extract the text to scan from tool_input based on tool_name.
 * @param {string} toolName
 * @param {Object} toolInput
 * @returns {string} text to scan (empty string if nothing to scan)
 */
function extractText(toolName, toolInput) {
  switch (toolName) {
    case "Bash":
      return toolInput.command || "";
    case "Edit":
      return toolInput.new_string || "";
    case "Write":
      return toolInput.content || "";
    case "Read":
      return toolInput.file_path || "";
    case "WebFetch":
      return toolInput.url || "";
    default:
      return "";
  }
}

try {
  const input = readHookInput();
  const { toolName, toolInput, sessionId } = input;

  // Step 0: Extract text to scan
  const rawText = extractText(toolName, toolInput);

  // If no text to scan, allow (nothing to check)
  if (!rawText) {
    allow();
  }

  // Step 1: NFKC normalization
  const text = nfkcNormalize(rawText);

  // Step 2: Zero-width character detection (BEFORE pattern load — prevents bypass)
  if (ZERO_WIDTH_RE.test(rawText)) {
    // Test against raw text (pre-NFKC) since NFKC may normalize some away
    appendEvidence({
      hook: "clawless-injection-guard",
      event: "deny",
      tool: toolName,
      category: "zero_width",
      severity: "high",
      detail: "Zero-width character detected in raw input",
      session_id: sessionId,
    });
    deny(
      "[clawless-injection-guard] Zero-width character detected. " +
        "Invisible characters can be used to bypass security patterns. " +
        "Category: zero_width (severity: high)",
    );
  }

  // Step 3: Load injection patterns (fail-close on missing/corrupted file)
  const patterns = loadPatterns();

  if (!patterns || !patterns.categories) {
    deny(
      "[clawless-injection-guard] injection-patterns.json has invalid structure.",
    );
  }

  // Step 4: Match each category's patterns in severity order
  // Collect medium-severity warnings (not blocking)
  const warnings = [];
  const categories = patterns.categories;

  for (const [categoryName, category] of Object.entries(categories)) {
    const severity = category.severity || "medium";
    const categoryPatterns = category.patterns || [];

    for (const patternStr of categoryPatterns) {
      let re;
      try {
        re = new RegExp(patternStr, "i");
      } catch {
        // Invalid regex in patterns file — skip (don't crash the hook)
        continue;
      }

      if (re.test(text)) {
        if (severity === "critical" || severity === "high") {
          // Deny immediately with evidence
          appendEvidence({
            hook: "clawless-injection-guard",
            event: "deny",
            tool: toolName,
            category: categoryName,
            severity,
            pattern: patternStr,
            session_id: sessionId,
          });
          deny(
            `[clawless-injection-guard] Injection pattern detected. ` +
              `Category: ${categoryName} (severity: ${severity}). ` +
              `Description: ${category.description || "N/A"}`,
          );
        }

        if (severity === "medium") {
          // Collect warning — do not deny
          warnings.push({
            category: categoryName,
            severity,
            pattern: patternStr,
            description: category.description || "",
          });
          // Only record the first match per category for warnings
          break;
        }
      }
    }
  }

  // Step 5: If only medium warnings, allow with additionalContext
  if (warnings.length > 0) {
    const warningMessages = warnings.map(
      (w) => `[${w.category}] ${w.description}`,
    );
    allow(
      `[clawless-injection-guard] Warning: potential security concern detected.\n` +
        warningMessages.join("\n"),
    );
  }

  // All patterns passed — allow
  allow();
} catch (err) {
  // fail-close: any uncaught error = deny
  process.stdout.write(
    JSON.stringify({
      reason: `Hook error (clawless-injection-guard): ${err.message}`,
    }),
  );
  process.exit(2);
}
