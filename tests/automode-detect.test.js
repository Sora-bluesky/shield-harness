#!/usr/bin/env node
// automode-detect.test.js — Auto Mode detection module tests
// Reference: Phase 7 ADR-038, TASK-058
"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { createTempDir, cleanupTempDir } = require("./helpers/hook-test-utils");

const MODULE_PATH = path.resolve(
  __dirname,
  "..",
  ".claude",
  "hooks",
  "lib",
  "automode-detect.js",
);

// ---------------------------------------------------------------------------
// Helper: fresh require (clear cache to pick up temp file stubs)
// ---------------------------------------------------------------------------

function freshRequire() {
  delete require.cache[MODULE_PATH];
  return require(MODULE_PATH);
}

// ==========================================================================
// 1. classifyDangerLevel() — pure function tests (5 tests)
// ==========================================================================

describe("classifyDangerLevel()", () => {
  const { classifyDangerLevel } = require(MODULE_PATH);

  it("returns safe when both counts are 0", () => {
    assert.equal(classifyDangerLevel(0, 0), "safe");
  });

  it("returns warn when only soft_allow is present", () => {
    assert.equal(classifyDangerLevel(0, 3), "warn");
  });

  it("returns critical when soft_deny is present", () => {
    assert.equal(classifyDangerLevel(1, 0), "critical");
  });

  it("returns critical when both soft_deny and soft_allow are present", () => {
    assert.equal(classifyDangerLevel(2, 5), "critical");
  });

  it("returns warn for boundary case soft_allow=1", () => {
    assert.equal(classifyDangerLevel(0, 1), "warn");
  });
});

// ==========================================================================
// 2. readSettingsFile() — file I/O tests (3 tests)
// ==========================================================================

describe("readSettingsFile()", () => {
  let tmpDir;

  afterEach(() => {
    if (tmpDir) cleanupTempDir(tmpDir);
    tmpDir = null;
  });

  it("returns null for non-existent file", () => {
    const { readSettingsFile } = freshRequire();
    const result = readSettingsFile("/nonexistent/path/settings.json");
    assert.equal(result, null);
  });

  it("returns null when JSON has no autoMode section", () => {
    tmpDir = createTempDir({
      "test-settings.json": JSON.stringify({
        permissions: { deny: [] },
      }),
    });
    const { readSettingsFile } = freshRequire();
    const result = readSettingsFile(path.join(tmpDir, "test-settings.json"));
    assert.equal(result, null);
  });

  it("returns correct structure when autoMode is present", () => {
    tmpDir = createTempDir({
      "test-settings.json": JSON.stringify({
        autoMode: {
          soft_deny: ["Bash(rm*)"],
          soft_allow: ["Read(*)"],
          environment: "Trusted CI environment",
        },
      }),
    });
    const { readSettingsFile } = freshRequire();
    const result = readSettingsFile(path.join(tmpDir, "test-settings.json"));

    assert.notEqual(result, null);
    assert.deepEqual(result.soft_deny, ["Bash(rm*)"]);
    assert.deepEqual(result.soft_allow, ["Read(*)"]);
    assert.equal(result.environment, "Trusted CI environment");
  });
});

// ==========================================================================
// 3. detectAutoMode() — integration tests (7 tests)
// ==========================================================================

describe("detectAutoMode()", () => {
  let tmpDir;
  let originalCwd;

  beforeEach(() => {
    originalCwd = process.cwd();
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (tmpDir) cleanupTempDir(tmpDir);
    tmpDir = null;
  });

  it("returns not_configured when no settings files exist", () => {
    tmpDir = createTempDir({
      ".placeholder": "",
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.detected, false);
    assert.equal(result.danger_level, "safe");
    assert.equal(result.reason, "not_configured");
    assert.equal(result.source, "none");
  });

  it("returns configured_safe when autoMode exists but no soft_deny/allow", () => {
    tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: {
          environment: "Safe test environment",
        },
      }),
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.detected, true);
    assert.equal(result.danger_level, "safe");
    assert.equal(result.reason, "configured_safe");
    assert.equal(result.has_environment, true);
    assert.equal(result.source, "settings_local");
  });

  it("returns warn with soft_allow_only", () => {
    tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: {
          soft_allow: ["Read(*)", "Glob(*)"],
        },
      }),
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.detected, true);
    assert.equal(result.danger_level, "warn");
    assert.equal(result.reason, "soft_allow_only");
    assert.equal(result.soft_allow_count, 2);
    assert.deepEqual(result.danger_items, []);
  });

  it("returns critical with soft_deny and populates danger_items", () => {
    tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: {
          soft_deny: ["Bash(git push --force)"],
        },
      }),
    });
    process.chdir(tmpDir);
    const { detectAutoMode, LOST_PROTECTIONS } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.detected, true);
    assert.equal(result.danger_level, "critical");
    assert.equal(result.reason, "soft_deny_present");
    assert.equal(result.soft_deny_count, 1);
    assert.deepEqual(result.danger_items, LOST_PROTECTIONS);
  });

  it("merges and deduplicates from both settings files", () => {
    tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: {
          soft_allow: ["Read(*)", "Glob(*)"],
        },
      }),
      ".claude/settings.json": JSON.stringify({
        autoMode: {
          soft_allow: ["Read(*)", "Grep(*)"],
        },
      }),
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.detected, true);
    assert.equal(result.source, "both");
    // Read(*) deduplicated: only 3 unique entries
    assert.equal(result.soft_allow_count, 3);
  });

  it("handles environment field with snippet truncation", () => {
    const longEnv =
      "This is a very long environment description that exceeds eighty characters and should be truncated to exactly 80 chars";
    tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: {
          environment: longEnv,
        },
      }),
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    assert.equal(result.has_environment, true);
    assert.equal(result.environment_snippet.length, 80);
    assert.equal(result.environment_snippet, longEnv.slice(0, 80));
  });

  it("returns read_error on corrupted JSON (fail-safe)", () => {
    tmpDir = createTempDir({
      ".claude/settings.local.json": "{ INVALID JSON !!!",
    });
    process.chdir(tmpDir);
    const { detectAutoMode } = freshRequire();
    const result = detectAutoMode();

    // readSettingsFile returns null for parse errors,
    // so detectAutoMode sees no autoMode → not_configured
    assert.equal(result.detected, false);
    assert.equal(result.danger_level, "safe");
  });
});
