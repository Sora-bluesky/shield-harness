#!/usr/bin/env node
// config-guard-automode.test.js — Auto Mode Check 7/8 tests for sh-config-guard.js
// Reference: Phase 7 ADR-038, TASK-058
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const CONFIG_GUARD_PATH = path.resolve(
  __dirname,
  "..",
  ".claude",
  "hooks",
  "sh-config-guard.js",
);

const { detectDangerousMutations } = require(CONFIG_GUARD_PATH);

// ---------------------------------------------------------------------------
// Helper: build minimal stored/current config objects
// ---------------------------------------------------------------------------

function buildConfig(overrides = {}) {
  return {
    deny_rules: [],
    hook_count: 22,
    hook_events: ["PreToolUse", "PostToolUse"],
    hook_commands: [],
    sandbox: true,
    unsandboxed: false,
    disableAllHooks: false,
    policy_hashes: {},
    policy_metrics: {},
    soft_deny_count: 0,
    soft_allow_count: 0,
    ...overrides,
  };
}

// ==========================================================================
// Check 7: Auto Mode soft_deny detection (5 tests)
// ==========================================================================

describe("Config Guard — Auto Mode Check 7/8", () => {
  it("Check 7: detects soft_deny addition (0 → 1) as blocked", () => {
    const stored = buildConfig({ soft_deny_count: 0 });
    const current = buildConfig({ soft_deny_count: 1 });
    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(
      result.reasons.some((r) => r.includes("soft_deny")),
      "reasons should mention soft_deny",
    );
    assert.ok(
      result.reasons.some((r) => r.includes("ALL default protections")),
      "reasons should mention ALL default protections",
    );
  });

  it("Check 7: soft_deny reduction (improvement) is not blocked", () => {
    const stored = buildConfig({ soft_deny_count: 2 });
    const current = buildConfig({ soft_deny_count: 1 });
    const result = detectDangerousMutations(stored, current);

    // soft_deny decreased — not a dangerous mutation (improvement)
    const softDenyReasons = result.reasons.filter((r) =>
      r.includes("soft_deny"),
    );
    assert.equal(softDenyReasons.length, 0);
  });

  it("Check 8: detects soft_allow expansion as blocked", () => {
    const stored = buildConfig({ soft_allow_count: 1 });
    const current = buildConfig({ soft_allow_count: 3 });
    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(
      result.reasons.some((r) => r.includes("soft_allow")),
      "reasons should mention soft_allow",
    );
  });

  it("Check 8: soft_allow reduction is not blocked", () => {
    const stored = buildConfig({ soft_allow_count: 5 });
    const current = buildConfig({ soft_allow_count: 2 });
    const result = detectDangerousMutations(stored, current);

    const softAllowReasons = result.reasons.filter((r) =>
      r.includes("soft_allow"),
    );
    assert.equal(softAllowReasons.length, 0);
  });

  it("backward compat: missing soft_deny_count in stored is treated as 0", () => {
    const stored = buildConfig();
    delete stored.soft_deny_count;
    delete stored.soft_allow_count;
    const current = buildConfig({ soft_deny_count: 0, soft_allow_count: 0 });
    const result = detectDangerousMutations(stored, current);

    // No change from default (0) — should not block
    assert.equal(result.blocked, false);
  });
});
