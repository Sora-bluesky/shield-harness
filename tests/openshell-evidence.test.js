#!/usr/bin/env node
// openshell-evidence.test.js — TDD Red: OCSF sandbox metadata tests
// These tests define the EXPECTED behavior after Stream B modifies ocsf-mapper.js.
// They will fail initially (TDD Red phase).
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

// Module under test
const { toDetectionFinding } = require("../.claude/hooks/lib/ocsf-mapper");

// ---------------------------------------------------------------------------
// Sandbox metadata in OCSF resources (TDD Red — not yet implemented)
// ---------------------------------------------------------------------------

describe("OCSF sandbox metadata (TDD Red)", () => {
  it("should include container resource when sandbox_state is 'active'", () => {
    const entry = {
      hook: "sh-gate",
      decision: "deny",
      tool: "Bash",
      sandbox_state: "active",
    };

    const finding = toDetectionFinding(entry);

    // Expect resources array to contain both tool and container resources
    assert.ok(Array.isArray(finding.resources), "resources should be an array");

    const containerResource = finding.resources.find(
      (r) => r.type === "container",
    );
    assert.ok(
      containerResource,
      "should have a container resource when sandbox_state is active",
    );
    assert.equal(
      containerResource.name,
      "openshell-sandbox",
      "container resource should be named 'openshell-sandbox'",
    );
  });

  it("should NOT include container resource when sandbox_state is absent", () => {
    const entry = {
      hook: "sh-gate",
      decision: "deny",
      tool: "Bash",
    };

    const finding = toDetectionFinding(entry);

    // resources may exist (for tool), but should not contain container type
    if (finding.resources) {
      const containerResource = finding.resources.find(
        (r) => r.type === "container",
      );
      assert.equal(
        containerResource,
        undefined,
        "should NOT have container resource when sandbox_state is absent",
      );
    }
  });

  it("should NOT include container resource when sandbox_state is not 'active'", () => {
    const entry = {
      hook: "sh-gate",
      decision: "deny",
      tool: "Bash",
      sandbox_state: "inactive",
    };

    const finding = toDetectionFinding(entry);

    if (finding.resources) {
      const containerResource = finding.resources.find(
        (r) => r.type === "container",
      );
      assert.equal(
        containerResource,
        undefined,
        "should NOT have container resource when sandbox_state is inactive",
      );
    }
  });

  it("should include sandbox_version in labels when present", () => {
    const entry = {
      hook: "sh-gate",
      decision: "deny",
      tool: "Bash",
      sandbox_state: "active",
      sandbox_version: "0.0.14",
    };

    const finding = toDetectionFinding(entry);

    const containerResource = finding.resources.find(
      (r) => r.type === "container",
    );
    assert.ok(containerResource, "container resource should exist");
    assert.ok(
      containerResource.labels,
      "container resource should have labels",
    );
    const versionLabel = containerResource.labels.find((l) =>
      l.startsWith("version:"),
    );
    assert.equal(
      versionLabel,
      "version:0.0.14",
      "labels should contain sandbox_version",
    );
  });

  it("should preserve tool resource alongside container resource", () => {
    const entry = {
      hook: "sh-evidence",
      decision: "allow",
      tool: "Bash",
      sandbox_state: "active",
    };

    const finding = toDetectionFinding(entry);

    assert.ok(Array.isArray(finding.resources), "resources should be an array");

    const toolResource = finding.resources.find((r) => r.type === "tool");
    assert.ok(toolResource, "should still have tool resource");
    assert.equal(toolResource.name, "Bash");

    const containerResource = finding.resources.find(
      (r) => r.type === "container",
    );
    assert.ok(containerResource, "should also have container resource");
  });
});
