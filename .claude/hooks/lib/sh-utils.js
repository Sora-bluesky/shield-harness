#!/usr/bin/env node
// sh-utils.js — Shared utilities for all Shield Harness hooks (Node.js)
// Spec: DETAILED_DESIGN.md §2.2b
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");

// --- Constants ---

const SH_DIR = ".shield-harness";
const EVIDENCE_FILE = path.join(SH_DIR, "logs", "evidence-ledger.jsonl");
const SESSION_FILE = path.join(SH_DIR, "session.json");
const PATTERNS_FILE = path.join(
  ".claude",
  "patterns",
  "injection-patterns.json",
);
const CHAIN_GENESIS_HASH = "0".repeat(64);

// --- Hook I/O ---

/**
 * Read and parse hook input from stdin.
 * @returns {Object} { raw, hookType, toolName, toolInput, toolResult, sessionId, timestamp }
 */
function readHookInput() {
  let raw;
  try {
    raw = fs.readFileSync("/dev/stdin", "utf8");
  } catch {
    // Windows fallback: file descriptor 0
    raw = fs.readFileSync(0, "utf8");
  }
  const input = JSON.parse(raw);
  return {
    raw,
    hookType: input.hook_type || "",
    toolName: input.tool_name || "",
    toolInput: input.tool_input || {},
    toolResult: input.tool_result || "",
    sessionId: input.session_id || "",
    timestamp: input.timestamp || "",
  };
}

/**
 * Output allow response and exit 0.
 * @param {string} [context] - Optional additionalContext
 */
function allow(context) {
  if (context) {
    process.stdout.write(JSON.stringify({ additionalContext: context }));
  } else {
    process.stdout.write("{}");
  }
  process.exit(0);
}

/**
 * Output allow response with updatedInput and exit 0.
 * @param {Object} updatedInput - Modified tool input
 */
function allowWithUpdate(updatedInput) {
  process.stdout.write(JSON.stringify({ updatedInput }));
  process.exit(0);
}

/**
 * Output allow response with updatedToolResult and exit 0.
 * @param {string} updatedToolResult - Modified tool output
 */
function allowWithResult(updatedToolResult) {
  process.stdout.write(JSON.stringify({ updatedToolResult }));
  process.exit(0);
}

/**
 * Output deny response and exit 2.
 * @param {string} reason - Denial reason
 */
function deny(reason) {
  process.stdout.write(JSON.stringify({ reason }));
  process.exit(2);
}

// --- Normalization ---

/**
 * NFKC normalization (native — no subprocess).
 * @param {string} input
 * @returns {string}
 */
function nfkcNormalize(input) {
  return input.normalize("NFKC");
}

/**
 * Normalize file path (Windows backslash -> forward slash, resolve).
 * @param {string} filePath
 * @returns {string}
 */
function normalizePath(filePath) {
  return path.resolve(filePath.replace(/\\/g, "/"));
}

// --- Crypto ---

/**
 * SHA-256 hash (native crypto).
 * @param {string} input
 * @returns {string} hex digest
 */
function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

// --- Session ---

/**
 * Read session.json (fail-safe: returns {} on error).
 * @returns {Object}
 */
function readSession() {
  try {
    return JSON.parse(fs.readFileSync(SESSION_FILE, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Write session.json atomically (tmp + rename).
 * @param {Object} data
 */
function writeSession(data) {
  const dir = path.dirname(SESSION_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${SESSION_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, SESSION_FILE);
}

// --- Evidence ---

/**
 * Append evidence entry to JSONL ledger with SHA-256 hash chain.
 * Entries are transformed to OCSF Detection Finding (class_uid: 2004) format.
 * @param {Object} entry
 */
function appendEvidence(entry) {
  const dir = path.dirname(EVIDENCE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  // OCSF transformation (lazy require to avoid startup cost)
  let ocsfEntry;
  try {
    const { toDetectionFinding } = require("./ocsf-mapper");
    ocsfEntry = toDetectionFinding(entry);
  } catch {
    // Fallback: use raw entry if OCSF mapper is unavailable
    ocsfEntry = { ...entry };
  }

  // Read last hash for chain continuity
  let prevHash = CHAIN_GENESIS_HASH;
  try {
    const content = fs.readFileSync(EVIDENCE_FILE, "utf8").trim();
    if (content) {
      const lines = content.split("\n");
      const lastLine = lines[lines.length - 1];
      const lastEntry = JSON.parse(lastLine);
      if (lastEntry.hash) prevHash = lastEntry.hash;
    }
  } catch {
    // First entry or file doesn't exist — use genesis hash
  }

  const record = {
    ...ocsfEntry,
    recorded_at: new Date().toISOString(),
    prev_hash: prevHash,
  };
  record.hash = sha256(JSON.stringify(record));

  fs.appendFileSync(EVIDENCE_FILE, JSON.stringify(record) + "\n");
}

// --- Hash Chain Verification ---

/**
 * Verify the integrity of the evidence-ledger hash chain.
 * @param {string} [ledgerPath] - Path to evidence-ledger.jsonl (defaults to EVIDENCE_FILE)
 * @returns {{ valid: boolean, entries: number, brokenAt?: number, reason?: string }}
 */
function verifyHashChain(ledgerPath) {
  const filePath = ledgerPath || EVIDENCE_FILE;

  let content;
  try {
    content = fs.readFileSync(filePath, "utf8").trim();
  } catch {
    // File does not exist — empty chain is valid
    return { valid: true, entries: 0 };
  }

  if (!content) {
    return { valid: true, entries: 0 };
  }

  const lines = content.split("\n");
  let expectedPrevHash = CHAIN_GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    const entry = JSON.parse(lines[i]);

    // Check prev_hash linkage
    if (entry.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        entries: lines.length,
        brokenAt: i,
        reason: "prev_hash_mismatch",
      };
    }

    // Recompute hash: remove 'hash' field, hash the rest
    const { hash, ...rest } = entry;
    const computed = sha256(JSON.stringify(rest));
    if (computed !== hash) {
      return {
        valid: false,
        entries: lines.length,
        brokenAt: i,
        reason: "hash_mismatch",
      };
    }

    expectedPrevHash = hash;
  }

  return { valid: true, entries: lines.length };
}

// --- YAML ---

/**
 * Read YAML file (requires js-yaml). Fail-close if js-yaml unavailable.
 * @param {string} filePath
 * @returns {Object}
 */
function readYaml(filePath) {
  let yaml;
  try {
    yaml = require("js-yaml");
  } catch {
    deny("js-yaml is not installed. Required for YAML operations.");
  }
  return yaml.load(fs.readFileSync(filePath, "utf8"));
}

// --- Command Detection ---

/**
 * Check if a command exists on the system.
 * Tries 'which' (Unix/Git Bash) first, then 'where' (Windows cmd).
 * @param {string} cmd
 * @returns {boolean}
 */
function commandExists(cmd) {
  // Reject non-alphanumeric command names to prevent injection
  if (!/^[a-zA-Z0-9_\-]+$/.test(cmd)) {
    return false;
  }
  for (const checker of ["which", "where"]) {
    try {
      execSync(`${checker} ${cmd}`, {
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      return true;
    } catch {
      // Try next checker
    }
  }
  return false;
}

// --- Patterns ---

/**
 * Load injection patterns from JSON file.
 * Fail-close: if file missing or corrupted, deny.
 * @returns {Object} parsed patterns
 */
function loadPatterns() {
  if (!fs.existsSync(PATTERNS_FILE)) {
    deny("injection-patterns.json not found. Run npx shield-harness init.");
  }
  try {
    return JSON.parse(fs.readFileSync(PATTERNS_FILE, "utf8"));
  } catch {
    deny("injection-patterns.json is corrupted.");
  }
}

// --- Repeat Deny Tracking (§4.5 FR-04-07) ---

const REPEAT_DENY_THRESHOLD = 3;

/**
 * Track deny occurrences per pattern key in session.
 * Increments deny_tracker[patternKey] in session.json.
 * @param {string} patternKey - Identifier for the denied pattern
 * @returns {{ exceeded: boolean, count: number }}
 */
function trackDeny(patternKey) {
  const session = readSession();
  if (!session.deny_tracker) session.deny_tracker = {};
  const count = (session.deny_tracker[patternKey] || 0) + 1;
  session.deny_tracker[patternKey] = count;
  writeSession(session);
  return { exceeded: count >= REPEAT_DENY_THRESHOLD, count };
}

module.exports = {
  // Constants
  SH_DIR,
  EVIDENCE_FILE,
  SESSION_FILE,
  PATTERNS_FILE,
  CHAIN_GENESIS_HASH,
  // Hook I/O
  readHookInput,
  allow,
  allowWithUpdate,
  allowWithResult,
  deny,
  // Normalization
  nfkcNormalize,
  normalizePath,
  // Crypto
  sha256,
  // Session
  readSession,
  writeSession,
  // Evidence
  appendEvidence,
  // YAML
  readYaml,
  // Command Detection
  commandExists,
  // Patterns
  loadPatterns,
  // Hash Chain
  verifyHashChain,
  // Deny Tracking
  trackDeny,
  REPEAT_DENY_THRESHOLD,
};
