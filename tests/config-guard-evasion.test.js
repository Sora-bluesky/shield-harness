#!/usr/bin/env node
// config-guard-evasion.test.js — Security tests for sh-config-guard.js
// Covers: extractSecurityFields, detectDangerousMutations, edge cases
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  extractSecurityFields,
  detectDangerousMutations,
} = require("../.claude/hooks/sh-config-guard.js");

// ---------------------------------------------------------------------------
// Test: extractSecurityFields
// ---------------------------------------------------------------------------

describe("extractSecurityFields — field extraction", () => {
  it("should extract deny rules and hook metadata from settings", () => {
    const settings = {
      permissions: {
        deny: ["rm -rf", "git push --force"],
      },
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash",
            hooks: [
              { type: "command", command: "node .claude/hooks/sh-gate.js" },
              {
                type: "command",
                command: "node .claude/hooks/sh-permission.js",
              },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: "Bash",
            hooks: [
              { type: "command", command: "node .claude/hooks/sh-evidence.js" },
            ],
          },
        ],
      },
      sandbox: { enabled: true },
    };

    const fields = extractSecurityFields(settings);

    assert.deepStrictEqual(fields.deny_rules, ["rm -rf", "git push --force"]);
    assert.equal(fields.hook_count, 3);
    assert.deepStrictEqual(fields.hook_events.sort(), [
      "PostToolUse",
      "PreToolUse",
    ]);
    assert.deepStrictEqual(fields.hook_commands, [
      "node .claude/hooks/sh-evidence.js",
      "node .claude/hooks/sh-gate.js",
      "node .claude/hooks/sh-permission.js",
    ]);
    assert.equal(fields.sandbox, true);
    assert.equal(fields.unsandboxed, false);
    assert.equal(fields.disableAllHooks, false);
  });

  it("should handle missing permissions and hooks gracefully", () => {
    const fields = extractSecurityFields({});

    assert.deepStrictEqual(fields.deny_rules, []);
    assert.equal(fields.hook_count, 0);
    assert.deepStrictEqual(fields.hook_events, []);
    assert.deepStrictEqual(fields.hook_commands, []);
    assert.equal(fields.sandbox, true); // default
    assert.equal(fields.unsandboxed, false);
    assert.equal(fields.disableAllHooks, false);
  });
});

// ---------------------------------------------------------------------------
// Test: detectDangerousMutations — deny rule changes
// ---------------------------------------------------------------------------

describe("detectDangerousMutations — deny rule detection", () => {
  it("should detect deny rule content swap (B22: same count, different patterns)", () => {
    const stored = {
      deny_rules: ["rm -rf", "git push --force"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node .claude/hooks/sh-permission.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = {
      deny_rules: ["echo hello", "git push --force"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node .claude/hooks/sh-permission.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(
      result.reasons.some((r) => r.includes("rm -rf")),
      "Should report removed deny rule 'rm -rf'",
    );
  });

  it("should detect deny rule removal", () => {
    const stored = {
      deny_rules: ["rm -rf", "git push --force", "shred"],
      hook_count: 1,
      hook_events: ["PreToolUse"],
      hook_commands: ["node .claude/hooks/sh-gate.js"],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = {
      deny_rules: ["rm -rf"],
      hook_count: 1,
      hook_events: ["PreToolUse"],
      hook_commands: ["node .claude/hooks/sh-gate.js"],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(
      result.reasons.some((r) => r.includes("git push --force")),
      "Should detect removed 'git push --force'",
    );
    assert.ok(
      result.reasons.some((r) => r.includes("shred")),
      "Should detect removed 'shred'",
    );
  });

  it("should return no mutations when nothing changed", () => {
    const config = {
      deny_rules: ["rm -rf", "git push --force"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node .claude/hooks/sh-permission.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    const result = detectDangerousMutations(config, { ...config });

    assert.equal(result.blocked, false);
    assert.equal(result.reasons.length, 0);
  });
});

// ---------------------------------------------------------------------------
// Test: detectDangerousMutations — hook command swap (B23)
// ---------------------------------------------------------------------------

describe("detectDangerousMutations — hook command swap (B23)", () => {
  it("should detect hook command string swap (same count, different command)", () => {
    const stored = {
      deny_rules: ["rm -rf"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node .claude/hooks/sh-permission.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = {
      deny_rules: ["rm -rf"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node /tmp/evil-hook.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true, "Hook command swap must be blocked");
    assert.ok(
      result.reasons.some((r) => r.includes("hook command")),
      "Reason should mention hook command change",
    );
  });
});

// ---------------------------------------------------------------------------
// Test: detectDangerousMutations — sandbox and global flags
// ---------------------------------------------------------------------------

describe("detectDangerousMutations — sandbox & flag changes", () => {
  it("should detect sandbox disabled", () => {
    const stored = {
      deny_rules: [],
      hook_count: 0,
      hook_events: [],
      hook_commands: [],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = { ...stored, sandbox: false };

    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(result.reasons.some((r) => r.includes("sandbox")));
  });

  it("should detect disableAllHooks toggled to true", () => {
    const stored = {
      deny_rules: [],
      hook_count: 0,
      hook_events: [],
      hook_commands: [],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = { ...stored, disableAllHooks: true };

    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, true);
    assert.ok(result.reasons.some((r) => r.includes("disableAllHooks")));
  });
});

// ---------------------------------------------------------------------------
// Test: Edge cases
// ---------------------------------------------------------------------------

describe("detectDangerousMutations — edge cases", () => {
  it("should handle empty previous config (no deny rules, no hooks)", () => {
    const stored = {
      deny_rules: [],
      hook_count: 0,
      hook_events: [],
      hook_commands: [],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = {
      deny_rules: ["rm -rf"],
      hook_count: 1,
      hook_events: ["PreToolUse"],
      hook_commands: ["node .claude/hooks/sh-gate.js"],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    // Adding rules/hooks from empty state is not dangerous
    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, false);
    assert.equal(result.reasons.length, 0);
  });

  it("should handle missing hook_commands field in stored config gracefully", () => {
    const stored = {
      deny_rules: ["rm -rf"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      // hook_commands is absent (legacy snapshot)
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };
    const current = {
      deny_rules: ["rm -rf"],
      hook_count: 2,
      hook_events: ["PreToolUse"],
      hook_commands: [
        "node .claude/hooks/sh-gate.js",
        "node .claude/hooks/sh-permission.js",
      ],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
    };

    // Should not throw, and should not block (no baseline to compare)
    const result = detectDangerousMutations(stored, current);

    assert.equal(result.blocked, false);
  });
});
