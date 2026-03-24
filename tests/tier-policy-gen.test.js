#!/usr/bin/env node
// tier-policy-gen.test.js — TDD Red: Tier policy generator tests
// Tests for the tier-policy-gen.js module (to be created in Stream C).
// These tests define the EXPECTED behavior. They will fail initially (TDD Red phase).
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

// Module under test (Stream C implementation)
const {
  parsePermissionRule,
  generatePolicyYaml,
  classifyRulesByDomain,
  cleanGlobPath,
  mergeClassified,
} = require("../.claude/hooks/lib/tier-policy-gen");

// ---------------------------------------------------------------------------
// parsePermissionRule()
// ---------------------------------------------------------------------------

describe("parsePermissionRule()", () => {
  it("should parse Read(~/.ssh/**) into action and target", () => {
    const result = parsePermissionRule("Read(~/.ssh/**)");
    assert.ok(result, "should return a parsed object");
    assert.equal(result.action, "Read");
    assert.equal(result.target, "~/.ssh/**");
  });

  it("should parse Bash(curl *) into action, command, and pattern", () => {
    const result = parsePermissionRule("Bash(curl *)");
    assert.ok(result, "should return a parsed object");
    assert.equal(result.action, "Bash");
    assert.equal(result.command, "curl");
    assert.equal(result.pattern, "*");
  });

  it("should parse Edit(.claude/hooks/**) into action and target", () => {
    const result = parsePermissionRule("Edit(.claude/hooks/**)");
    assert.ok(result, "should return a parsed object");
    assert.equal(result.action, "Edit");
    assert.equal(result.target, ".claude/hooks/**");
  });

  it("should return null for invalid rule format", () => {
    const result = parsePermissionRule("invalid");
    assert.equal(result, null);
  });

  it("should return null for empty string", () => {
    const result = parsePermissionRule("");
    assert.equal(result, null);
  });

  it("should parse Write(.claude/settings.json) correctly", () => {
    const result = parsePermissionRule("Write(.claude/settings.json)");
    assert.ok(result, "should return a parsed object");
    assert.equal(result.action, "Write");
    assert.equal(result.target, ".claude/settings.json");
  });

  it("should parse Bash(rm -rf /) with full command", () => {
    const result = parsePermissionRule("Bash(rm -rf /)");
    assert.ok(result, "should return a parsed object");
    assert.equal(result.action, "Bash");
    assert.equal(result.command, "rm");
  });
});

// ---------------------------------------------------------------------------
// generatePolicyYaml()
// ---------------------------------------------------------------------------

describe("generatePolicyYaml()", () => {
  it("should contain 'version: 1' header", () => {
    const yaml = generatePolicyYaml({
      permissions: {
        deny: [{ rule: "Read(~/.ssh/**)" }],
        allow: [],
      },
    });
    assert.ok(yaml.includes("version: 1"), "should have version: 1");
  });

  it("should contain deny_read section for Read deny rules", () => {
    const yaml = generatePolicyYaml({
      permissions: {
        deny: [{ rule: "Read(~/.ssh/**)" }],
        allow: [],
      },
    });
    assert.ok(yaml.includes("deny_read:"), "should have deny_read section");
    // cleanGlobPath removes trailing /**, so path becomes ~/.ssh
    assert.ok(yaml.includes("~/.ssh"), "should include the denied path");
  });

  it("should contain deny_write section for Edit/Write deny rules", () => {
    const yaml = generatePolicyYaml({
      permissions: {
        deny: [{ rule: "Edit(.claude/hooks/**)" }],
        allow: [],
      },
    });
    assert.ok(yaml.includes("deny_write:"), "should have deny_write section");
    // cleanGlobPath removes trailing /**, so path becomes .claude/hooks
    assert.ok(yaml.includes(".claude/hooks"), "should include the denied path");
  });

  it("should contain network section for Bash network deny rules", () => {
    const yaml = generatePolicyYaml({
      permissions: {
        deny: [{ rule: "Bash(curl *)" }, { rule: "Bash(wget *)" }],
        allow: [],
      },
    });
    assert.ok(
      yaml.includes("network_policies:"),
      "should have network_policies section",
    );
    // Blocked network commands appear as comments
    assert.ok(yaml.includes("curl *"), "should include blocked curl command");
  });

  it("should promote ask rules to deny in strict profile", () => {
    const yaml = generatePolicyYaml(
      {
        permissions: {
          deny: [{ rule: "Read(~/.ssh/**)" }],
          ask: [{ rule: "Edit(.claude/**)" }],
          allow: [],
        },
      },
      { profile: "strict" },
    );
    assert.ok(yaml.includes("deny_write:"), "should have deny_write from ask");
    assert.ok(yaml.includes(".claude"), "should include ask rule path");
    assert.ok(yaml.includes("# Profile: strict"), "should show strict profile");
  });

  it("should throw on invalid spec (missing permissions)", () => {
    assert.throws(() => generatePolicyYaml({}), /missing permissions/);
  });
});

// ---------------------------------------------------------------------------
// classifyRulesByDomain()
// ---------------------------------------------------------------------------

describe("classifyRulesByDomain()", () => {
  it("should classify Read rules as denyRead", () => {
    const result = classifyRulesByDomain([
      { rule: "Read(~/.ssh/**)" },
      { rule: "Read(**/.env)" },
    ]);
    assert.ok(
      result.denyRead.length >= 2,
      "Read rules should be in denyRead domain",
    );
  });

  it("should classify Bash(curl *) as network", () => {
    const result = classifyRulesByDomain([
      { rule: "Bash(curl *)" },
      { rule: "Bash(wget *)" },
      { rule: "Bash(nc *)" },
    ]);
    assert.ok(
      result.network.length >= 3,
      "Network commands should be in network domain",
    );
  });

  it("should classify Edit/Write rules as denyWrite", () => {
    const result = classifyRulesByDomain([
      { rule: "Edit(.claude/hooks/**)" },
      { rule: "Write(.claude/settings.json)" },
    ]);
    assert.ok(
      result.denyWrite.length >= 2,
      "Edit/Write rules should be in denyWrite domain",
    );
  });

  it("should classify Bash(rm -rf /) as process", () => {
    const result = classifyRulesByDomain([{ rule: "Bash(rm -rf /)" }]);
    assert.ok(
      result.process.length >= 1,
      "Destructive Bash rules should be in process domain",
    );
  });

  it("should return empty arrays for empty input", () => {
    const result = classifyRulesByDomain([]);
    assert.deepEqual(result.denyRead, []);
    assert.deepEqual(result.denyWrite, []);
    assert.deepEqual(result.network, []);
    assert.deepEqual(result.process, []);
  });

  it("should deduplicate Edit and Write on same path", () => {
    const result = classifyRulesByDomain([
      { rule: "Edit(.claude/hooks/**)" },
      { rule: "Write(.claude/hooks/**)" },
    ]);
    assert.equal(
      result.denyWrite.length,
      1,
      "Edit+Write on same path should produce one entry",
    );
  });

  it("should classify git push --force as network", () => {
    const result = classifyRulesByDomain([
      { rule: "Bash(git push --force *)" },
    ]);
    assert.ok(
      result.network.length >= 1,
      "Force push should be in network domain",
    );
  });

  it("should classify npm publish as network", () => {
    const result = classifyRulesByDomain([{ rule: "Bash(npm publish *)" }]);
    assert.ok(
      result.network.length >= 1,
      "npm publish should be in network domain",
    );
  });
});
