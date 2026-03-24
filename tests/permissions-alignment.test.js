"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  loadPermissionsSpec,
  loadSettingsPermissions,
  setDiff,
  diffPermissions,
  validateAlignment,
  formatReport,
} = require("../.claude/hooks/lib/permissions-validator");

const SPEC_PATH = path.join(".claude", "permissions-spec.json");
const SETTINGS_PATH = path.join(".claude", "settings.json");

// ---------------------------------------------------------------------------
// Unit tests for permissions-validator.js
// ---------------------------------------------------------------------------

describe("permissions-validator", () => {
  describe("loadPermissionsSpec", () => {
    it("loads and parses permissions-spec.json", () => {
      const spec = loadPermissionsSpec(SPEC_PATH);
      assert.ok(Array.isArray(spec.deny), "deny should be an array");
      assert.ok(Array.isArray(spec.ask), "ask should be an array");
      assert.ok(Array.isArray(spec.allow), "allow should be an array");
    });

    it("extracts rule strings from objects", () => {
      const spec = loadPermissionsSpec(SPEC_PATH);
      // All entries should be plain strings after extraction
      spec.deny.forEach((rule) => {
        assert.equal(
          typeof rule,
          "string",
          `deny rule should be string: ${rule}`,
        );
      });
      spec.allow.forEach((rule) => {
        assert.equal(
          typeof rule,
          "string",
          `allow rule should be string: ${rule}`,
        );
      });
    });

    it("throws on missing file", () => {
      assert.throws(() => loadPermissionsSpec("nonexistent.json"), /not found/);
    });
  });

  describe("loadSettingsPermissions", () => {
    it("loads permissions from settings.json", () => {
      const settings = loadSettingsPermissions(SETTINGS_PATH);
      assert.ok(Array.isArray(settings.deny), "deny should be an array");
      assert.ok(Array.isArray(settings.allow), "allow should be an array");
    });

    it("throws on missing file", () => {
      assert.throws(
        () => loadSettingsPermissions("nonexistent.json"),
        /not found/,
      );
    });
  });

  describe("setDiff", () => {
    it("returns items in A but not in B", () => {
      const diff = setDiff(["a", "b", "c"], ["b", "c", "d"]);
      assert.deepEqual(diff, ["a"]);
    });

    it("returns empty array when A is subset of B", () => {
      const diff = setDiff(["a", "b"], ["a", "b", "c"]);
      assert.deepEqual(diff, []);
    });

    it("handles empty arrays", () => {
      assert.deepEqual(setDiff([], ["a"]), []);
      assert.deepEqual(setDiff(["a"], []), ["a"]);
      assert.deepEqual(setDiff([], []), []);
    });
  });

  describe("diffPermissions", () => {
    it("detects aligned permissions", () => {
      const spec = { deny: ["a", "b"], ask: ["c"], allow: ["d"] };
      const settings = { deny: ["b", "a"], ask: ["c"], allow: ["d"] };
      const diff = diffPermissions(spec, settings);
      assert.equal(diff.aligned, true);
      assert.equal(diff.totalMissing, 0);
      assert.equal(diff.totalExtra, 0);
    });

    it("detects missing rules", () => {
      const spec = { deny: ["a", "b", "c"], ask: [], allow: [] };
      const settings = { deny: ["a"], ask: [], allow: [] };
      const diff = diffPermissions(spec, settings);
      assert.equal(diff.aligned, false);
      assert.deepEqual(diff.missingDeny, ["b", "c"]);
      assert.equal(diff.totalMissing, 2);
    });

    it("detects extra rules", () => {
      const spec = { deny: ["a"], ask: [], allow: [] };
      const settings = { deny: ["a", "x", "y"], ask: [], allow: [] };
      const diff = diffPermissions(spec, settings);
      assert.equal(diff.aligned, false);
      assert.deepEqual(diff.extraDeny, ["x", "y"]);
      assert.equal(diff.totalExtra, 2);
    });

    it("detects mixed missing and extra across categories", () => {
      const spec = { deny: ["a"], ask: ["b"], allow: ["c", "d"] };
      const settings = { deny: ["a", "x"], ask: [], allow: ["c"] };
      const diff = diffPermissions(spec, settings);
      assert.equal(diff.aligned, false);
      assert.equal(diff.missingAsk.length, 1);
      assert.equal(diff.extraDeny.length, 1);
      assert.equal(diff.missingAllow.length, 1);
    });
  });

  describe("validateAlignment", () => {
    it("returns result object with required fields", () => {
      const result = validateAlignment(SPEC_PATH, SETTINGS_PATH);
      assert.ok("aligned" in result, "should have aligned field");
      assert.ok("diff" in result, "should have diff field");
      assert.ok("summary" in result, "should have summary field");
      assert.ok("counts" in result, "should have counts field");
    });
  });

  describe("formatReport", () => {
    it("returns OK for aligned result", () => {
      const report = formatReport({ aligned: true, diff: {}, summary: "OK" });
      assert.match(report, /OK/);
    });

    it("returns detailed report for misaligned result", () => {
      const report = formatReport({
        aligned: false,
        diff: {
          missingDeny: ["rule1"],
          extraDeny: [],
          missingAsk: [],
          extraAsk: [],
          missingAllow: [],
          extraAllow: ["rule2"],
        },
        summary: "1 missing, 1 extra",
      });
      assert.match(report, /DIVERGENCE/);
      assert.match(report, /rule1/);
      assert.match(report, /rule2/);
    });
  });

  // ---------------------------------------------------------------------------
  // Self-consistency checks
  // ---------------------------------------------------------------------------

  describe("permissions-spec.json self-consistency", () => {
    it("exists and is valid JSON", () => {
      assert.ok(fs.existsSync(SPEC_PATH), "permissions-spec.json should exist");
      const content = fs.readFileSync(SPEC_PATH, "utf8");
      assert.doesNotThrow(() => JSON.parse(content), "should be valid JSON");
    });

    it("has expected_counts matching actual rule counts", () => {
      const raw = JSON.parse(fs.readFileSync(SPEC_PATH, "utf8"));
      const spec = loadPermissionsSpec(SPEC_PATH);
      if (raw.expected_counts) {
        assert.equal(
          spec.deny.length,
          raw.expected_counts.deny,
          `deny count: expected ${raw.expected_counts.deny}, got ${spec.deny.length}`,
        );
        assert.equal(
          spec.ask.length,
          raw.expected_counts.ask,
          `ask count: expected ${raw.expected_counts.ask}, got ${spec.ask.length}`,
        );
        assert.equal(
          spec.allow.length,
          raw.expected_counts.allow,
          `allow count: expected ${raw.expected_counts.allow}, got ${spec.allow.length}`,
        );
      }
    });

    it("has no duplicate rules within each category", () => {
      const spec = loadPermissionsSpec(SPEC_PATH);
      const denySet = new Set(spec.deny);
      assert.equal(
        denySet.size,
        spec.deny.length,
        "deny should have no duplicates",
      );
      const askSet = new Set(spec.ask);
      assert.equal(
        askSet.size,
        spec.ask.length,
        "ask should have no duplicates",
      );
      const allowSet = new Set(spec.allow);
      assert.equal(
        allowSet.size,
        spec.allow.length,
        "allow should have no duplicates",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Alignment check (TODO until TASK-023/024 fix settings.json)
  // ---------------------------------------------------------------------------

  describe("permissions alignment", () => {
    it("deny rules match settings.json", () => {
      const result = validateAlignment(SPEC_PATH, SETTINGS_PATH);
      assert.equal(
        result.diff.missingDeny.length,
        0,
        `Missing deny: ${result.diff.missingDeny.join(", ")}`,
      );
      assert.equal(
        result.diff.extraDeny.length,
        0,
        `Extra deny: ${result.diff.extraDeny.join(", ")}`,
      );
    });

    it("allow rules match settings.json", () => {
      const result = validateAlignment(SPEC_PATH, SETTINGS_PATH);
      assert.equal(
        result.diff.missingAllow.length,
        0,
        `Missing allow: ${result.diff.missingAllow.join(", ")}`,
      );
      assert.equal(
        result.diff.extraAllow.length,
        0,
        `Extra allow: ${result.diff.extraAllow.join(", ")}`,
      );
    });

    it("ask rules match settings.json", () => {
      const result = validateAlignment(SPEC_PATH, SETTINGS_PATH);
      assert.equal(
        result.diff.missingAsk.length,
        0,
        `Missing ask: ${result.diff.missingAsk.join(", ")}`,
      );
      assert.equal(
        result.diff.extraAsk.length,
        0,
        `Extra ask: ${result.diff.extraAsk.join(", ")}`,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // SoT protection check
  // ---------------------------------------------------------------------------

  describe("permissions-spec.json protection", () => {
    it("is protected by deny rules in settings.json", () => {
      const settings = loadSettingsPermissions(SETTINGS_PATH);
      const hasEditDeny = settings.deny.some(
        (r) => r.includes("permissions-spec.json") && r.startsWith("Edit"),
      );
      const hasWriteDeny = settings.deny.some(
        (r) => r.includes("permissions-spec.json") && r.startsWith("Write"),
      );
      assert.ok(
        hasEditDeny,
        "Edit(.claude/permissions-spec.json) should be in deny rules",
      );
      assert.ok(
        hasWriteDeny,
        "Write(.claude/permissions-spec.json) should be in deny rules",
      );
    });
  });
});
