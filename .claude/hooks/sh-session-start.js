#!/usr/bin/env node
// sh-session-start.js — Session initialization & integrity baseline
// Spec: DETAILED_DESIGN.md §5.1
// Event: SessionStart
// Target response time: < 500ms
"use strict";

const fs = require("fs");
const path = require("path");
const {
  readHookInput,
  allow,
  sha256,
  readSession,
  writeSession,
  appendEvidence,
} = require("./lib/sh-utils");

const HOOK_NAME = "sh-session-start";
const CLAUDE_MD = "CLAUDE.md";
const SETTINGS_FILE = path.join(".claude", "settings.json");
const RULES_DIR = path.join(".claude", "rules");
const HOOKS_DIR = path.join(".claude", "hooks");
const HASHES_FILE = path.join(".claude", "logs", "instructions-hashes.json");
const PATTERNS_FILE = path.join(
  ".claude",
  "patterns",
  "injection-patterns.json",
);
const SESSION_FILE = path.join(".shield-harness", "session.json");
const VERSION_FILE = path.join(
  ".shield-harness",
  "state",
  "last-known-version.txt",
);

// Expected minimum deny rules (§5.1.1)
const REQUIRED_DENY_PATTERNS = [
  "backlog.yaml", // Edit/Write deny for backlog
];

// Expected minimum hook count
const MIN_HOOK_COUNT = 10; // Wave 0+1+2 = 10 hooks minimum

// Token budget defaults (§5.1.2, ADR-026)
const DEFAULT_TOKEN_BUDGET = {
  session_limit: 200000,
  tool_output_limit: 50000,
  used: 0,
};

try {
  const input = readHookInput();
  const contextParts = [];

  // --- Module 1: Gate Check (§5.1.1) ---

  // 1a: CLAUDE.md baseline hash
  let claudeMdHash = null;
  if (fs.existsSync(CLAUDE_MD)) {
    const content = fs.readFileSync(CLAUDE_MD, "utf8");
    claudeMdHash = sha256(content);
    contextParts.push(
      `[gate-check] CLAUDE.md baseline: ${claudeMdHash.slice(0, 12)}...`,
    );
  } else {
    contextParts.push("[gate-check] WARNING: CLAUDE.md not found");
  }

  // 1b: settings.json deny rules check
  if (fs.existsSync(SETTINGS_FILE)) {
    try {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
      const denyRules =
        (settings.permissions && settings.permissions.deny) || [];
      const missingDeny = REQUIRED_DENY_PATTERNS.filter(
        (p) => !denyRules.some((rule) => rule.includes(p)),
      );
      if (missingDeny.length > 0) {
        contextParts.push(
          `[gate-check] WARNING: Missing deny rules for: ${missingDeny.join(", ")}`,
        );
      }
    } catch {
      contextParts.push("[gate-check] WARNING: settings.json parse error");
    }
  }

  // 1c: Hook count verification
  if (fs.existsSync(HOOKS_DIR)) {
    const hookFiles = fs
      .readdirSync(HOOKS_DIR)
      .filter((f) => f.startsWith("sh-") && f.endsWith(".js"));
    if (hookFiles.length < MIN_HOOK_COUNT) {
      contextParts.push(
        `[gate-check] Hook count: ${hookFiles.length}/${MIN_HOOK_COUNT} (below minimum)`,
      );
    } else {
      contextParts.push(
        `[gate-check] Hooks verified: ${hookFiles.length} scripts`,
      );
    }
  }

  // 1d: injection-patterns.json validation
  if (fs.existsSync(PATTERNS_FILE)) {
    try {
      const patterns = JSON.parse(fs.readFileSync(PATTERNS_FILE, "utf8"));
      const categoryCount = Object.keys(patterns).length;
      contextParts.push(
        `[gate-check] Injection patterns: ${categoryCount} categories loaded`,
      );
    } catch {
      contextParts.push(
        "[gate-check] WARNING: injection-patterns.json corrupted",
      );
    }
  } else {
    contextParts.push(
      "[gate-check] WARNING: injection-patterns.json not found",
    );
  }

  // --- Module 2: Env Check (§5.1.2) ---

  // 2a: OS detection
  const platform = process.platform;
  contextParts.push(`[env-check] Platform: ${platform}`);

  // 2b: Token budget initialization
  const session = readSession();
  if (!session.token_budget) {
    session.token_budget = { ...DEFAULT_TOKEN_BUDGET };
  }
  session.session_start = new Date().toISOString();
  session.retry_count = 0;
  session.stop_hook_active = false;
  writeSession(session);
  contextParts.push("[env-check] Session initialized, token budget set");

  // --- Module 3: Version Check (§5.1.4) ---
  // Store baseline hashes for instructions monitoring
  const hashes = {};
  if (fs.existsSync(CLAUDE_MD)) {
    hashes[CLAUDE_MD] = claudeMdHash;
  }
  if (fs.existsSync(RULES_DIR)) {
    try {
      const ruleFiles = fs
        .readdirSync(RULES_DIR)
        .filter((f) => f.endsWith(".md"));
      for (const f of ruleFiles) {
        const fp = path.join(RULES_DIR, f);
        hashes[fp] = sha256(fs.readFileSync(fp, "utf8"));
      }
    } catch {
      // Non-critical
    }
  }
  // Save baseline hashes (used by instructions hook later)
  const hashDir = path.dirname(HASHES_FILE);
  if (!fs.existsSync(hashDir)) fs.mkdirSync(hashDir, { recursive: true });
  fs.writeFileSync(HASHES_FILE, JSON.stringify(hashes, null, 2));

  // --- Evidence Recording ---
  try {
    appendEvidence({
      hook: HOOK_NAME,
      event: "SessionStart",
      decision: "allow",
      claude_md_hash: claudeMdHash ? `sha256:${claudeMdHash}` : null,
      platform,
      session_id: input.sessionId,
    });
  } catch {
    // Evidence failure is non-blocking
  }

  // --- Output ---
  const context = [
    "=== Shield Harness Security Harness Initialized ===",
    ...contextParts,
    "=============================================",
  ].join("\n");

  allow(context);
} catch (_err) {
  // Operational hook — fail-open
  allow("[sh-session-start] Initialization error (fail-open): " + _err.message);
}

module.exports = {
  REQUIRED_DENY_PATTERNS,
  MIN_HOOK_COUNT,
  DEFAULT_TOKEN_BUDGET,
};
