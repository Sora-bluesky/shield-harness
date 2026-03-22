#!/usr/bin/env node
// clawless-utils.js — Shared utilities for all Clawless hooks (Node.js)
// Spec: DETAILED_DESIGN.md §2.2b
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// --- Constants ---

const CLAWLESS_DIR = ".clawless";
const EVIDENCE_FILE = path.join(CLAWLESS_DIR, "logs", "evidence-ledger.jsonl");
const SESSION_FILE = path.join(CLAWLESS_DIR, "session.json");
const PATTERNS_FILE = path.join(
  ".claude",
  "patterns",
  "injection-patterns.json",
);
const CHAIN_GENESIS_HASH = "0".repeat(64);

// --- Hook I/O ---

/**
 * Read and parse hook input from stdin.
 * @returns {Object} { raw, hookType, toolName, toolInput, sessionId, timestamp }
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
 * @param {Object} entry
 */
function appendEvidence(entry) {
  const dir = path.dirname(EVIDENCE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

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
    ...entry,
    recorded_at: new Date().toISOString(),
    prev_hash: prevHash,
  };
  record.hash = sha256(JSON.stringify(record));

  fs.appendFileSync(EVIDENCE_FILE, JSON.stringify(record) + "\n");
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

// --- Patterns ---

/**
 * Load injection patterns from JSON file.
 * Fail-close: if file missing or corrupted, deny.
 * @returns {Object} parsed patterns
 */
function loadPatterns() {
  if (!fs.existsSync(PATTERNS_FILE)) {
    deny("injection-patterns.json not found. Run npx clawless init.");
  }
  try {
    return JSON.parse(fs.readFileSync(PATTERNS_FILE, "utf8"));
  } catch {
    deny("injection-patterns.json is corrupted.");
  }
}

module.exports = {
  // Constants
  CLAWLESS_DIR,
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
  // Patterns
  loadPatterns,
};
