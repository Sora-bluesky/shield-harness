#!/usr/bin/env node
// policy-drift.test.js — Tests for lib/policy-drift.js
// Covers: checkPolicyDrift, parsePolicyYaml, extractYamlList, extractBlockedNetworkComments
"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const {
  checkPolicyDrift,
  extractYamlList,
  extractBlockedNetworkComments,
  parsePolicyYaml,
} = require("../.claude/hooks/lib/policy-drift.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir;

function setup() {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "policy-drift-test-"));
}

function cleanup() {
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Create a minimal permissions-spec.json in tmpDir.
 * @param {{ deny?: Array<string|{rule:string}>, ask?: Array<string|{rule:string}>, allow?: Array<string|{rule:string}> }} perms
 */
function writeSpec(perms = {}) {
  const spec = {
    version: "1.0.0",
    permissions: {
      deny: perms.deny || [],
      ask: perms.ask || [],
      allow: perms.allow || [],
    },
  };
  fs.writeFileSync(
    path.join(tmpDir, "permissions-spec.json"),
    JSON.stringify(spec, null, 2),
  );
  return path.join(tmpDir, "permissions-spec.json");
}

/**
 * Create a policy YAML file in tmpDir/policies/.
 * @param {string} content - YAML content
 * @param {string} [filename] - Filename (default: openshell-default.yaml)
 */
function writePolicy(content, filename = "openshell-default.yaml") {
  const policyDir = path.join(tmpDir, "policies");
  if (!fs.existsSync(policyDir)) fs.mkdirSync(policyDir, { recursive: true });
  fs.writeFileSync(path.join(policyDir, filename), content);
  return policyDir;
}

// ---------------------------------------------------------------------------
// Test: extractYamlList
// ---------------------------------------------------------------------------

describe("extractYamlList — YAML section parsing", () => {
  it("should extract deny_read paths", () => {
    const yaml = `filesystem_policy:
  include_workdir: true
  deny_read:
    - ~/.ssh
    - ~/.gnupg
  read_only:
    - /usr
`;
    const result = extractYamlList(yaml, "deny_read");
    assert.deepStrictEqual(result, ["~/.ssh", "~/.gnupg"]);
  });

  it("should return empty array for missing section", () => {
    const yaml = `filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
`;
    const result = extractYamlList(yaml, "deny_read");
    assert.deepStrictEqual(result, []);
  });

  it("should extract deny_write paths", () => {
    const yaml = `filesystem_policy:
  deny_write:
    - .claude/hooks
    - .claude/patterns
  read_write:
    - /tmp
`;
    const result = extractYamlList(yaml, "deny_write");
    assert.deepStrictEqual(result, [".claude/hooks", ".claude/patterns"]);
  });

  it("should extract read_write paths", () => {
    const yaml = `filesystem_policy:
  read_write:
    - /sandbox
    - /tmp
`;
    const result = extractYamlList(yaml, "read_write");
    assert.deepStrictEqual(result, ["/sandbox", "/tmp"]);
  });
});

// ---------------------------------------------------------------------------
// Test: extractBlockedNetworkComments
// ---------------------------------------------------------------------------

describe("extractBlockedNetworkComments — comment block parsing", () => {
  it("should extract blocked commands from comment block", () => {
    const yaml = `network_policies:
  anthropic_api:
    name: anthropic-api

# Blocked network operations (from permissions-spec.json deny rules):
#   - curl *
#   - wget *
`;
    const result = extractBlockedNetworkComments(yaml);
    assert.deepStrictEqual(result, ["curl *", "wget *"]);
  });

  it("should return empty array when no comment block", () => {
    const yaml = `network_policies:
  anthropic_api:
    name: anthropic-api
`;
    const result = extractBlockedNetworkComments(yaml);
    assert.deepStrictEqual(result, []);
  });
});

// ---------------------------------------------------------------------------
// Test: parsePolicyYaml
// ---------------------------------------------------------------------------

describe("parsePolicyYaml — full policy parsing", () => {
  it("should parse all sections from generated policy", () => {
    const yaml = `version: 1

filesystem_policy:
  include_workdir: true
  deny_read:
    - ~/.ssh
  deny_write:
    - .claude/hooks
  read_only:
    - /usr
  read_write:
    - /sandbox
    - /tmp

network_policies:
  anthropic_api:
    name: anthropic-api

# Blocked network operations (from permissions-spec.json deny rules):
#   - curl *
`;
    const result = parsePolicyYaml(yaml);
    assert.deepStrictEqual(result.denyRead, ["~/.ssh"]);
    assert.deepStrictEqual(result.denyWrite, [".claude/hooks"]);
    assert.deepStrictEqual(result.readWrite, ["/sandbox", "/tmp"]);
    assert.deepStrictEqual(result.blockedNetwork, ["curl *"]);
  });
});

// ---------------------------------------------------------------------------
// Test: checkPolicyDrift — integration
// ---------------------------------------------------------------------------

describe("checkPolicyDrift — no drift (aligned)", () => {
  beforeEach(setup);
  afterEach(cleanup);

  it("should return has_drift: false when spec and policy are aligned", () => {
    const specPath = writeSpec({
      deny: [
        { rule: "Read(~/.ssh/**)" },
        { rule: "Edit(.claude/hooks/**)" },
        { rule: "Bash(curl *)" },
      ],
    });
    const policyDir = writePolicy(`version: 1

filesystem_policy:
  include_workdir: true
  deny_read:
    - ~/.ssh
  deny_write:
    - .claude/hooks
  read_only:
    - /usr
  read_write:
    - /sandbox
    - /tmp

network_policies:
  anthropic_api:
    name: anthropic-api

# Blocked network operations (from permissions-spec.json deny rules):
#   - curl *
`);

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
    assert.equal(result.warnings.length, 0);
  });
});

describe("checkPolicyDrift — drift detection", () => {
  beforeEach(setup);
  afterEach(cleanup);

  it("should detect missing deny_read in policy", () => {
    const specPath = writeSpec({
      deny: [{ rule: "Read(~/.ssh/**)" }, { rule: "Read(~/.gnupg/**)" }],
    });
    // Policy only has ~/.ssh, missing ~/.gnupg
    const policyDir = writePolicy(`version: 1

filesystem_policy:
  deny_read:
    - ~/.ssh
  read_write:
    - /tmp
`);

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, true);
    assert.ok(result.details.missing_filesystem_deny.includes("~/.gnupg"));
    assert.ok(result.warnings.some((w) => w.includes("~/.gnupg")));
  });

  it("should detect missing deny_write in policy", () => {
    const specPath = writeSpec({
      deny: [{ rule: "Edit(.claude/hooks/**)" }],
    });
    // Policy has no deny_write section
    const policyDir = writePolicy(`version: 1

filesystem_policy:
  read_write:
    - /tmp
`);

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, true);
    assert.ok(result.details.missing_filesystem_deny.includes(".claude/hooks"));
  });

  it("should detect conflict: read_write allows denied path", () => {
    const specPath = writeSpec({
      deny: [{ rule: "Read(/tmp/**)" }],
    });
    // Policy has /tmp in both deny_read AND read_write (conflict)
    const policyDir = writePolicy(`version: 1

filesystem_policy:
  deny_read:
    - /tmp
  read_write:
    - /tmp
`);

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, true);
    assert.ok(result.details.policy_allows_denied.includes("/tmp"));
    assert.ok(result.warnings.some((w) => w.includes("conflict")));
  });

  it("should detect missing network deny in comments", () => {
    const specPath = writeSpec({
      deny: [{ rule: "Bash(curl *)" }, { rule: "Bash(wget *)" }],
    });
    // Policy only mentions curl, missing wget
    const policyDir = writePolicy(`version: 1

filesystem_policy:
  read_write:
    - /tmp

# Blocked network operations (from permissions-spec.json deny rules):
#   - curl *
`);

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, true);
    assert.ok(result.details.missing_network_deny.includes("wget *"));
  });
});

describe("checkPolicyDrift — skip cases", () => {
  beforeEach(setup);
  afterEach(cleanup);

  it("should skip when no policy directory exists", () => {
    const specPath = writeSpec({ deny: [{ rule: "Read(~/.ssh/**)" }] });
    const policyDir = path.join(tmpDir, "nonexistent-policies");

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
    assert.equal(result.warnings.length, 0);
  });

  it("should skip when no spec file exists", () => {
    const policyDir = writePolicy("version: 1\n");
    const specPath = path.join(tmpDir, "nonexistent-spec.json");

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
    assert.equal(result.warnings.length, 0);
  });

  it("should skip when policy directory has no YAML files", () => {
    const specPath = writeSpec({ deny: [{ rule: "Read(~/.ssh/**)" }] });
    const policyDir = path.join(tmpDir, "policies");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, "readme.txt"), "not a policy");

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
  });

  it("should return no drift when spec has empty deny rules", () => {
    const specPath = writeSpec({ deny: [] });
    const policyDir = writePolicy("version: 1\n");

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
  });
});

describe("checkPolicyDrift — error handling", () => {
  beforeEach(setup);
  afterEach(cleanup);

  it("should handle malformed spec JSON gracefully", () => {
    const specPath = path.join(tmpDir, "permissions-spec.json");
    fs.writeFileSync(specPath, "{ invalid json }}}");
    const policyDir = writePolicy("version: 1\n");

    const result = checkPolicyDrift({ specPath, policyDir });
    assert.equal(result.has_drift, false);
    assert.ok(result.warnings.some((w) => w.includes("parse_error")));
  });
});
