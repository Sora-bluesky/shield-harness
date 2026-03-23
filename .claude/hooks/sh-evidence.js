#!/usr/bin/env node
// sh-evidence.js — SHA-256 hash chain evidence recording
// Spec: DETAILED_DESIGN.md §4.1
// Hook events: PostToolUse, PostToolUseFailure, ElicitationResult, TeammateIdle, StopFailure
// Matcher: "" (all tools)
// Target response time: < 30ms
"use strict";

const {
  readHookInput,
  allow,
  sha256,
  appendEvidence,
  readSession,
  EVIDENCE_FILE,
} = require("./lib/sh-utils");
const fs = require("fs");

// ---------------------------------------------------------------------------
// Constants / Patterns
// ---------------------------------------------------------------------------

const HOOK_NAME = "sh-evidence";

// PII detection patterns (FR-05-02)
const PII_PATTERNS = [
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // email
  /\b\d{3}-\d{4}-\d{4}\b/, // JP phone
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // credit card
  /\bAIza[0-9A-Za-z_-]{35}\b/, // Google API key
  /\bsk-[a-zA-Z0-9]{20,}\b/, // OpenAI/Anthropic key
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, // AWS access key
  /\bghp_[a-zA-Z0-9]{36}\b/, // GitHub token
];

// Data leakage patterns (FR-03-03)
const LEAKAGE_PATTERNS = [
  /https?:\/\/[^?]+\?(.*)(password|token|secret|key|api_key)=/, // secrets in URL
  /Authorization:\s*(Bearer|Basic)\s+[A-Za-z0-9+/=]+/, // auth headers
  /data:.*base64,.*[A-Za-z0-9+/=]{100,}/, // large base64 blobs
];

// Tools whose output should be scanned for PII
const PII_SCAN_TOOLS = ["Write", "Edit"];

// Tools whose output should be scanned for leakage
const LEAKAGE_SCAN_TOOLS = ["WebFetch", "Bash"];

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/**
 * Get the next sequence number from the evidence ledger.
 * @returns {number}
 */
function getNextSeq() {
  try {
    const content = fs.readFileSync(EVIDENCE_FILE, "utf8").trim();
    if (!content) return 1;
    const lines = content.split("\n");
    const lastEntry = JSON.parse(lines[lines.length - 1]);
    return (lastEntry.seq || 0) + 1;
  } catch {
    return 1;
  }
}

/**
 * Scan text for PII patterns.
 * @param {string} text
 * @returns {string[]} matched pattern labels
 */
function detectPII(text) {
  if (!text) return [];
  const labels = [
    "email",
    "JP phone",
    "credit card",
    "Google API key",
    "API secret key",
    "AWS access key",
    "GitHub token",
  ];
  const found = [];
  for (let i = 0; i < PII_PATTERNS.length; i++) {
    if (PII_PATTERNS[i].test(text)) {
      found.push(labels[i]);
    }
  }
  return found;
}

/**
 * Scan text for data leakage patterns.
 * @param {string} text
 * @returns {boolean}
 */
function detectLeakage(text) {
  if (!text) return false;
  return LEAKAGE_PATTERNS.some((p) => p.test(text));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

try {
  const input = readHookInput();
  const { hookType, toolName, toolInput, toolResult, sessionId } = input;

  // Check channel source for evidence metadata (§8.6.3)
  let isChannel = false;
  try {
    const session = readSession();
    isChannel = session.source === "channel";
  } catch {
    // Session read failure is non-blocking for evidence
  }

  // Build evidence entry
  const inputStr = JSON.stringify(toolInput);
  const resultStr =
    typeof toolResult === "string" ? toolResult : JSON.stringify(toolResult);

  const entry = {
    seq: getNextSeq(),
    event: hookType,
    tool: toolName,
    input_hash: "sha256:" + sha256(inputStr),
    output_hash: "sha256:" + sha256(resultStr || ""),
    output_size: resultStr ? resultStr.length : 0,
    decision: "allow",
    hook: HOOK_NAME,
    category: null,
    is_channel: isChannel,
    session_id: sessionId,
  };

  // Collect context messages
  const warnings = [];

  // PII scan for Write/Edit tool results
  if (PII_SCAN_TOOLS.includes(toolName)) {
    const piiFound = detectPII(resultStr);
    if (piiFound.length > 0) {
      warnings.push(
        `[${HOOK_NAME}] プレーンテキストの認証情報が検出されました: ${piiFound.join(", ")}`,
      );
      entry.category = "pii_detected";
    }
  }

  // Leakage scan for WebFetch/Bash tool results
  if (LEAKAGE_SCAN_TOOLS.includes(toolName)) {
    if (detectLeakage(resultStr)) {
      warnings.push(
        `[${HOOK_NAME}] 出力にデータ漏洩の可能性があります。機密情報が含まれていないか確認してください。`,
      );
      entry.category = entry.category || "leakage_detected";
    }
  }

  // Record evidence (failure must not block the response)
  try {
    appendEvidence(entry);
  } catch (_) {
    // Evidence recording failure is non-blocking
  }

  // Allow with optional warnings
  if (warnings.length > 0) {
    allow(warnings.join("\n"));
  } else {
    allow();
  }
} catch (_err) {
  // Evidence hook is operational, not security-blocking.
  // On error, allow the tool result through.
  allow();
}

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  PII_PATTERNS,
  LEAKAGE_PATTERNS,
  detectPII,
  detectLeakage,
  getNextSeq,
};
