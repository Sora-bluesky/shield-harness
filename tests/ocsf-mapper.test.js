#!/usr/bin/env node
// ocsf-mapper.test.js — Unit tests for OCSF Detection Finding mapper
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

// Module under test
const {
  toDetectionFinding,
  resolveSeverityId,
  resolveDispositionId,
  generateTitle,
  extractUnmapped,
  generateUUID,
  OCSF_VERSION,
} = require("../.claude/hooks/lib/ocsf-mapper");

// ---------------------------------------------------------------------------
// resolveSeverityId()
// ---------------------------------------------------------------------------

describe("resolveSeverityId()", () => {
  it("should return 1 (Informational) for allow decisions without severity", () => {
    assert.equal(resolveSeverityId("sh-gate", "allow"), 1);
    assert.equal(resolveSeverityId("sh-evidence", "allow"), 1);
  });

  it("should return 4 (High) for deny from sh-injection-guard", () => {
    assert.equal(resolveSeverityId("sh-injection-guard", "deny"), 4);
  });

  it("should return 3 (Medium) for deny from sh-gate", () => {
    assert.equal(resolveSeverityId("sh-gate", "deny"), 3);
  });

  it("should map explicit severity strings correctly", () => {
    assert.equal(resolveSeverityId("any-hook", "deny", "low"), 2);
    assert.equal(resolveSeverityId("any-hook", "deny", "medium"), 3);
    assert.equal(resolveSeverityId("any-hook", "deny", "high"), 4);
    assert.equal(resolveSeverityId("any-hook", "deny", "critical"), 5);
  });

  it("should be case-insensitive for severity strings", () => {
    assert.equal(resolveSeverityId("any-hook", "deny", "HIGH"), 4);
    assert.equal(resolveSeverityId("any-hook", "deny", "Critical"), 5);
  });

  it("should fall back to 3 for unknown severity string", () => {
    assert.equal(resolveSeverityId("any-hook", "deny", "unknown"), 3);
  });
});

// ---------------------------------------------------------------------------
// resolveDispositionId()
// ---------------------------------------------------------------------------

describe("resolveDispositionId()", () => {
  it("should return 2 (Blocked) for deny decisions", () => {
    assert.equal(resolveDispositionId("deny", null), 2);
  });

  it("should return 1 (Allowed) for allow decisions", () => {
    assert.equal(resolveDispositionId("allow", null), 1);
  });

  it("should return 15 (Detected) for pii_detected category on allow", () => {
    assert.equal(resolveDispositionId("allow", "pii_detected"), 15);
  });

  it("should return 15 (Detected) for leakage_detected category on allow", () => {
    assert.equal(resolveDispositionId("allow", "leakage_detected"), 15);
  });
});

// ---------------------------------------------------------------------------
// generateTitle()
// ---------------------------------------------------------------------------

describe("generateTitle()", () => {
  it("should generate correct title for sh-gate", () => {
    const title = generateTitle("sh-gate", { decision: "deny" });
    assert.equal(title, "Bash command gate: deny");
  });

  it("should generate correct title for sh-injection-guard", () => {
    const title = generateTitle("sh-injection-guard", {
      category: "prompt-injection",
    });
    assert.equal(title, "Injection pattern detected: prompt-injection");
  });

  it("should generate correct title for sh-evidence with tool", () => {
    const title = generateTitle("sh-evidence", { tool: "Bash" });
    assert.equal(title, "Tool execution recorded: Bash");
  });

  it("should handle unknown hook gracefully with fallback format", () => {
    const title = generateTitle("sh-unknown-hook", { decision: "allow" });
    assert.equal(title, "sh-unknown-hook: allow");
  });

  it("should use event as fallback when decision is absent for unknown hook", () => {
    const title = generateTitle("sh-unknown-hook", { event: "PreToolUse" });
    assert.equal(title, "sh-unknown-hook: PreToolUse");
  });
});

// ---------------------------------------------------------------------------
// extractUnmapped()
// ---------------------------------------------------------------------------

describe("extractUnmapped()", () => {
  it("should extract fields beyond OCSF common fields", () => {
    const entry = {
      hook: "sh-gate",
      decision: "deny",
      command: "rm -rf /",
      reason: "blocked",
    };
    const unmapped = extractUnmapped(entry);
    assert.deepEqual(unmapped, { command: "rm -rf /", reason: "blocked" });
  });

  it("should return undefined when no extra fields exist", () => {
    const entry = {
      hook: "sh-gate",
      event: "PreToolUse",
      decision: "allow",
      session_id: "abc",
      tool: "Bash",
      seq: 1,
      severity: "low",
    };
    const unmapped = extractUnmapped(entry);
    assert.equal(unmapped, undefined);
  });

  it("should skip undefined values in extra fields", () => {
    const entry = {
      hook: "sh-gate",
      decision: "allow",
      extra_field: undefined,
    };
    const unmapped = extractUnmapped(entry);
    assert.equal(unmapped, undefined);
  });
});

// ---------------------------------------------------------------------------
// generateUUID()
// ---------------------------------------------------------------------------

describe("generateUUID()", () => {
  it("should produce unique UUIDs on repeated calls", () => {
    const uuid1 = generateUUID();
    const uuid2 = generateUUID();
    assert.notEqual(uuid1, uuid2);
  });

  it("should produce valid UUID v4 format", () => {
    const uuid = generateUUID();
    const uuidV4Regex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    assert.match(uuid, uuidV4Regex, `UUID "${uuid}" is not valid v4 format`);
  });
});

// ---------------------------------------------------------------------------
// toDetectionFinding()
// ---------------------------------------------------------------------------

describe("toDetectionFinding()", () => {
  it("should produce a valid OCSF Detection Finding structure", () => {
    const entry = {
      hook: "sh-gate",
      event: "PreToolUse",
      decision: "deny",
      session_id: "sess-001",
      tool: "Bash",
      seq: 5,
      command: "rm -rf /",
    };

    const finding = toDetectionFinding(entry);

    // Required OCSF fields
    assert.equal(finding.class_uid, 2004);
    assert.equal(finding.class_name, "Detection Finding");
    assert.equal(finding.category_uid, 2);
    assert.equal(finding.category_name, "Findings");
    assert.equal(finding.type_uid, 200401);
    assert.equal(finding.activity_id, 1);
    assert.equal(finding.status_id, 1);
    assert.equal(finding.status, "New");
    assert.ok(typeof finding.time === "number");

    // Severity
    assert.equal(finding.severity_id, 3); // sh-gate deny = Medium
    assert.equal(finding.severity, "Medium");

    // Action / disposition
    assert.equal(finding.action_id, 2);
    assert.equal(finding.action, "Denied");
    assert.equal(finding.disposition_id, 2); // Blocked

    // Metadata
    assert.equal(finding.metadata.version, OCSF_VERSION);
    assert.equal(finding.metadata.product.name, "Shield Harness");
    assert.equal(finding.metadata.correlation_uid, "sess-001");
    assert.equal(finding.metadata.sequence, 5);

    // Finding info
    assert.ok(finding.finding_info.uid, "should have a UUID");
    assert.equal(finding.finding_info.title, "Bash command gate: deny");
    assert.equal(finding.finding_info.analytic.name, "sh-gate");

    // Resources
    assert.equal(finding.resources[0].name, "Bash");

    // Unmapped (extra field: command)
    assert.deepEqual(finding.unmapped, { command: "rm -rf /" });
  });

  it("should set action to Allowed for allow decisions", () => {
    const entry = { hook: "sh-evidence", decision: "allow", tool: "Bash" };
    const finding = toDetectionFinding(entry);
    assert.equal(finding.action_id, 1);
    assert.equal(finding.action, "Allowed");
    assert.equal(finding.disposition_id, 1);
  });
});

// ---------------------------------------------------------------------------
// OCSF_VERSION constant
// ---------------------------------------------------------------------------

describe("OCSF_VERSION", () => {
  it("should be '1.3.0'", () => {
    assert.equal(OCSF_VERSION, "1.3.0");
  });
});

// ---------------------------------------------------------------------------
// Channel metadata
// ---------------------------------------------------------------------------

describe("Channel metadata in OCSF output", () => {
  it("should preserve is_channel field in unmapped when present", () => {
    const entry = {
      hook: "sh-user-prompt",
      decision: "allow",
      event: "UserPromptSubmit",
      is_channel: true,
      channel_source: "telegram",
    };
    const finding = toDetectionFinding(entry);
    assert.ok(finding.unmapped, "should have unmapped fields");
    assert.equal(finding.unmapped.is_channel, true);
    assert.equal(finding.unmapped.channel_source, "telegram");
  });
});
