#!/usr/bin/env node
// policy-compat.test.js — Policy version compatibility check tests
// TASK-021: Adversarial + unit tests for policy-compat.js
"use strict";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { createTempDir, cleanupTempDir } = require("./helpers/hook-test-utils");

// Module under test
const {
  extractPolicyVersion,
  compareSemver,
  semverInRange,
  checkPolicyCompatibility,
  COMPAT_MATRIX,
} = require("../.claude/hooks/lib/policy-compat");

// ============================================================
// extractPolicyVersion() — YAML version field extraction
// ============================================================

describe("extractPolicyVersion -- version field extraction", () => {
  it("should extract integer version from standard YAML", () => {
    const content = "version: 1\nfilesystem_policy:\n  include_workdir: true";
    assert.equal(extractPolicyVersion(content), 1, "should extract version 1");
  });

  it("should extract double-quoted string version", () => {
    const content = 'version: "2"\nfilesystem_policy:';
    assert.equal(extractPolicyVersion(content), 2, "should parse quoted '2'");
  });

  it("should extract single-quoted string version", () => {
    const content = "version: '3'\nfilesystem_policy:";
    assert.equal(
      extractPolicyVersion(content),
      3,
      "should parse single-quoted '3'",
    );
  });

  it("should return null for missing version field", () => {
    const content = "filesystem_policy:\n  include_workdir: true";
    assert.equal(
      extractPolicyVersion(content),
      null,
      "no version field = null",
    );
  });

  it("should return null for empty content", () => {
    assert.equal(extractPolicyVersion(""), null, "empty string = null");
  });

  it("should return null for non-numeric version", () => {
    const content = "version: beta\nfilesystem_policy:";
    assert.equal(extractPolicyVersion(content), null, "non-numeric = null");
  });

  it("should ignore version in comments", () => {
    const content = "# version: 99\nversion: 1\nfilesystem_policy:";
    assert.equal(
      extractPolicyVersion(content),
      1,
      "should skip commented version",
    );
  });

  it("should handle version: 0 edge case", () => {
    const content = "version: 0\nfilesystem_policy:";
    assert.equal(extractPolicyVersion(content), 0, "version 0 is valid");
  });

  it("should return null for indented version (not top-level)", () => {
    const content = "  version: 1\nfilesystem_policy:";
    assert.equal(
      extractPolicyVersion(content),
      null,
      "indented = not top-level",
    );
  });
});

// ============================================================
// compareSemver() — Semantic version comparison
// ============================================================

describe("compareSemver -- semver comparison", () => {
  it("should return 0 for equal versions", () => {
    assert.equal(compareSemver("1.2.3", "1.2.3"), 0, "equal versions = 0");
  });

  it("should return -1 when a < b (major)", () => {
    assert.equal(compareSemver("0.9.0", "1.0.0"), -1, "0.9.0 < 1.0.0");
  });

  it("should return 1 when a > b (minor)", () => {
    assert.equal(compareSemver("1.1.0", "1.0.0"), 1, "1.1.0 > 1.0.0");
  });

  it("should return -1 when a < b (patch)", () => {
    assert.equal(compareSemver("1.0.0", "1.0.1"), -1, "1.0.0 < 1.0.1");
  });

  it("should handle alpha-range versions", () => {
    assert.equal(compareSemver("0.0.14", "0.0.15"), -1, "0.0.14 < 0.0.15");
  });
});

// ============================================================
// semverInRange() — Range check (min inclusive, max exclusive)
// ============================================================

describe("semverInRange -- version range check", () => {
  it("should return true for version in range", () => {
    assert.ok(
      semverInRange("0.0.14", "0.0.0", "1.0.0"),
      "0.0.14 in [0.0.0, 1.0.0)",
    );
  });

  it("should return false for version below range", () => {
    assert.ok(
      !semverInRange("0.0.0", "0.1.0", "1.0.0"),
      "0.0.0 not in [0.1.0, 1.0.0)",
    );
  });

  it("should return false for version at upper bound (exclusive)", () => {
    assert.ok(
      !semverInRange("1.0.0", "0.0.0", "1.0.0"),
      "upper bound is exclusive",
    );
  });

  it("should return true for version at lower bound (inclusive)", () => {
    assert.ok(
      semverInRange("0.0.0", "0.0.0", "1.0.0"),
      "lower bound is inclusive",
    );
  });
});

// ============================================================
// checkPolicyCompatibility() — Main compatibility check
// ============================================================

describe("checkPolicyCompatibility -- integration", () => {
  let tmpDir;

  before(() => {
    tmpDir = createTempDir({
      "valid-policy.yaml":
        "# Schema: OpenShell Policy v1\nversion: 1\nfilesystem_policy:\n  include_workdir: true\n",
      "corrupted-policy.yaml": "\x00\x01\x02\x03binary-garbage",
      "no-version-policy.yaml": "filesystem_policy:\n  include_workdir: true\n",
      "future-policy.yaml":
        "version: 99\nfilesystem_policy:\n  include_workdir: true\n",
    });
  });

  after(() => {
    cleanupTempDir(tmpDir);
  });

  it("should return compatible for valid v1 policy with Alpha OpenShell", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "valid-policy.yaml"),
    });
    assert.equal(result.compatible, true, "v1 + 0.0.14 should be compatible");
    assert.equal(result.policy_version, 1);
    assert.equal(result.openshell_version, "0.0.14");
    assert.ok(result.checked_at, "should have timestamp");
  });

  it("should return policy_not_found when file missing", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "nonexistent.yaml"),
    });
    assert.equal(result.compatible, null);
    assert.equal(result.reason, "policy_not_found");
  });

  it("should return version_not_readable for corrupted policy", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "corrupted-policy.yaml"),
    });
    assert.equal(result.compatible, null);
    assert.equal(result.reason, "version_not_readable");
  });

  it("should return openshell_version_unknown when version is null", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: null,
      policyFilePath: path.join(tmpDir, "valid-policy.yaml"),
    });
    assert.equal(result.compatible, null);
    assert.equal(result.reason, "openshell_version_unknown");
    assert.equal(
      result.policy_version,
      1,
      "should still extract policy version",
    );
  });

  it("should return unknown_combination for unrecognized OpenShell version", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "99.0.0",
      policyFilePath: path.join(tmpDir, "valid-policy.yaml"),
    });
    assert.equal(result.compatible, null);
    assert.equal(result.reason, "unknown_combination");
  });

  it("should return incompatible when policy version not in supported list", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "future-policy.yaml"),
    });
    assert.equal(result.compatible, false, "policy v99 not supported by Alpha");
    assert.ok(
      result.recommended_policy_version != null,
      "should suggest recommended version",
    );
    assert.ok(result.migration_hint, "should provide migration hint");
  });
});

// ============================================================
// COMPAT_MATRIX — Structure validation
// ============================================================

describe("COMPAT_MATRIX -- structure validation", () => {
  it("should have at least one entry", () => {
    assert.ok(Array.isArray(COMPAT_MATRIX), "should be an array");
    assert.ok(COMPAT_MATRIX.length >= 1, "should have at least one entry");
  });

  it("should have valid structure for each entry", () => {
    for (const entry of COMPAT_MATRIX) {
      assert.ok(
        typeof entry.openshell_min === "string",
        "openshell_min should be string",
      );
      assert.ok(
        typeof entry.openshell_max === "string",
        "openshell_max should be string",
      );
      assert.ok(
        Array.isArray(entry.supported_policy_versions),
        "supported_policy_versions should be array",
      );
      assert.ok(
        typeof entry.latest_policy_version === "number",
        "latest_policy_version should be number",
      );
    }
  });
});

// ============================================================
// Adversarial tests — Security edge cases
// ============================================================

describe("adversarial -- security edge cases", () => {
  let tmpDir;

  before(() => {
    tmpDir = createTempDir({
      "yaml-injection.yaml":
        "version: 1\n!!python/object:os.system\n  command: rm -rf /\n",
      "huge-version.yaml": "version: 999999999\nfilesystem_policy:\n",
      "null-bytes.yaml": "version: 1\x00malicious\nfilesystem_policy:\n",
      "homoglyph.yaml": "versi\u043E\u043F: 1\nfilesystem_policy:\n",
      "binary.yaml": Buffer.from([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
      ]).toString("binary"),
    });
  });

  after(() => {
    cleanupTempDir(tmpDir);
  });

  it("should safely extract version despite YAML injection payload", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "yaml-injection.yaml"),
    });
    assert.equal(
      result.policy_version,
      1,
      "should extract version 1 ignoring injection",
    );
    assert.equal(result.compatible, true, "should still be compatible");
  });

  it("should handle extremely large version number", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "huge-version.yaml"),
    });
    assert.equal(
      result.compatible,
      false,
      "huge version not in supported list",
    );
  });

  it("should handle null bytes in policy content", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "null-bytes.yaml"),
    });
    assert.equal(
      result.policy_version,
      1,
      "should extract version despite null bytes",
    );
  });

  it("should reject unicode homoglyph version field", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "homoglyph.yaml"),
    });
    assert.equal(result.compatible, null, "homoglyph should not match");
    assert.equal(result.reason, "version_not_readable");
  });

  it("should not throw on binary input", () => {
    const result = checkPolicyCompatibility({
      openshellVersion: "0.0.14",
      policyFilePath: path.join(tmpDir, "binary.yaml"),
    });
    assert.equal(result.compatible, null, "binary file = unreadable");
    assert.equal(result.reason, "version_not_readable");
  });
});
