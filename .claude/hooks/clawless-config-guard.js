#!/usr/bin/env node
// clawless-config-guard.js — Settings.json mutation guard
// Spec: DETAILED_DESIGN.md §5.3
// Event: ConfigChange
// Target response time: < 100ms
"use strict";

const fs = require("fs");
const path = require("path");
const {
  readHookInput,
  allow,
  deny,
  sha256,
  appendEvidence,
} = require("./lib/clawless-utils");

const HOOK_NAME = "clawless-config-guard";
const SETTINGS_FILE = path.join(".claude", "settings.json");
const CONFIG_HASH_FILE = path.join(".claude", "logs", "config-hash.json");

// ---------------------------------------------------------------------------
// Config Analysis
// ---------------------------------------------------------------------------

/**
 * Read and parse settings.json.
 * @returns {Object|null}
 */
function readSettings() {
  try {
    if (!fs.existsSync(SETTINGS_FILE)) return null;
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Load previously stored config snapshot.
 * @returns {{ hash: string, deny_rules: string[], hook_count: number, sandbox: boolean }|null}
 */
function loadStoredConfig() {
  try {
    if (!fs.existsSync(CONFIG_HASH_FILE)) return null;
    const data = JSON.parse(fs.readFileSync(CONFIG_HASH_FILE, "utf8"));
    // Validate clawless format (deny_rules array required)
    // Reject tobari-format snapshots (hash + snapshot_keys only)
    if (!Array.isArray(data.deny_rules)) return null;
    return data;
  } catch {
    return null;
  }
}

/**
 * Save current config snapshot.
 * @param {Object} snapshot
 */
function saveConfigSnapshot(snapshot) {
  const dir = path.dirname(CONFIG_HASH_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(CONFIG_HASH_FILE, JSON.stringify(snapshot, null, 2));
}

/**
 * Extract security-critical fields from settings.
 * @param {Object} settings
 * @returns {{ deny_rules: string[], hook_count: number, hook_events: string[], sandbox: boolean, unsandboxed: boolean, disableAllHooks: boolean }}
 */
function extractSecurityFields(settings) {
  const denyRules = (settings.permissions && settings.permissions.deny) || [];

  // Count total hooks across all events
  const hooks = settings.hooks || {};
  let hookCount = 0;
  const hookEvents = [];
  for (const [event, entries] of Object.entries(hooks)) {
    hookEvents.push(event);
    for (const entry of Array.isArray(entries) ? entries : []) {
      const hookList = entry.hooks || [];
      hookCount += hookList.length;
    }
  }

  return {
    deny_rules: denyRules,
    hook_count: hookCount,
    hook_events: hookEvents,
    sandbox:
      settings.sandbox !== undefined
        ? Boolean(settings.sandbox.enabled !== false)
        : true,
    unsandboxed: Boolean(settings.allowUnsandboxedCommands),
    disableAllHooks: Boolean(settings.disableAllHooks),
  };
}

/**
 * Check for dangerous mutations between stored and current config.
 * @param {Object} stored - Previous security fields
 * @param {Object} current - Current security fields
 * @returns {{ blocked: boolean, reasons: string[] }}
 */
function detectDangerousMutations(stored, current) {
  const reasons = [];

  // Check 1: deny rules removed
  for (const rule of stored.deny_rules) {
    if (!current.deny_rules.includes(rule)) {
      reasons.push(`deny rule removed: "${rule}"`);
    }
  }

  // Check 2: hooks removed (event-level check)
  if (current.hook_count < stored.hook_count) {
    const removedCount = stored.hook_count - current.hook_count;
    reasons.push(`${removedCount} hook(s) removed from configuration`);
  }
  for (const event of stored.hook_events) {
    if (!current.hook_events.includes(event)) {
      reasons.push(`hook event "${event}" entirely removed`);
    }
  }

  // Check 3: sandbox disabled
  if (stored.sandbox && !current.sandbox) {
    reasons.push("sandbox.enabled set to false");
  }

  // Check 4: unsandboxed commands allowed
  if (!stored.unsandboxed && current.unsandboxed) {
    reasons.push("allowUnsandboxedCommands set to true");
  }

  // Check 5: all hooks disabled
  if (!stored.disableAllHooks && current.disableAllHooks) {
    reasons.push("disableAllHooks set to true");
  }

  return {
    blocked: reasons.length > 0,
    reasons,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

try {
  const input = readHookInput();

  const settings = readSettings();
  if (!settings) {
    deny(`[${HOOK_NAME}] settings.json not found or unreadable — fail-close`);
  }

  const currentFields = extractSecurityFields(settings);
  const settingsContent = fs.readFileSync(SETTINGS_FILE, "utf8");
  const currentHash = sha256(settingsContent);

  const stored = loadStoredConfig();

  // First run: record baseline
  if (!stored) {
    saveConfigSnapshot({
      hash: currentHash,
      ...currentFields,
    });

    try {
      appendEvidence({
        hook: HOOK_NAME,
        event: "ConfigChange",
        decision: "allow",
        action: "baseline_recorded",
        settings_hash: `sha256:${currentHash}`,
        session_id: input.sessionId,
      });
    } catch {
      // Non-blocking
    }

    allow(`[${HOOK_NAME}] Config baseline recorded`);
  }

  // Check for dangerous mutations
  const mutations = detectDangerousMutations(stored, currentFields);

  if (mutations.blocked) {
    try {
      appendEvidence({
        hook: HOOK_NAME,
        event: "ConfigChange",
        decision: "deny",
        reasons: mutations.reasons,
        settings_hash: `sha256:${currentHash}`,
        previous_hash: `sha256:${stored.hash}`,
        session_id: input.sessionId,
      });
    } catch {
      // Non-blocking
    }

    deny(
      `[${HOOK_NAME}] Blocked dangerous config change: ${mutations.reasons.join("; ")}`,
    );
  }

  // Safe change — update snapshot and allow
  saveConfigSnapshot({
    hash: currentHash,
    ...currentFields,
  });

  try {
    appendEvidence({
      hook: HOOK_NAME,
      event: "ConfigChange",
      decision: "allow",
      action: "config_updated",
      settings_hash: `sha256:${currentHash}`,
      previous_hash: stored ? `sha256:${stored.hash}` : null,
      session_id: input.sessionId,
    });
  } catch {
    // Non-blocking
  }

  allow();
} catch (err) {
  // SECURITY hook — fail-close (§2.3b)
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
  readSettings,
  loadStoredConfig,
  saveConfigSnapshot,
  extractSecurityFields,
  detectDangerousMutations,
};
