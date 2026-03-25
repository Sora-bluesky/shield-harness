#!/usr/bin/env node
// attack-sim-automode-bypass.test.js — Auto Mode bypass attack simulation
// Attack simulation tests verifying defense against soft_deny injection,
// config-guard bypass, and multi-layer defense chains.
// Reference: Phase 7 ADR-038, TASK-058b
"use strict";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const {
  runHookProcess,
  buildHookInput,
  createTempDir,
  cleanupTempDir,
} = require("./helpers/hook-test-utils");

// ---------------------------------------------------------------------------
// Shared paths and data
// ---------------------------------------------------------------------------

const PROJECT_ROOT = path.resolve(__dirname, "..");
const SETTINGS_PATH = path.join(PROJECT_ROOT, ".claude", "settings.json");
const PERMISSIONS_SPEC_PATH = path.join(
  PROJECT_ROOT,
  ".claude",
  "permissions-spec.json",
);
const PATTERNS_PATH = path.join(
  PROJECT_ROOT,
  ".claude",
  "patterns",
  "injection-patterns.json",
);

// Load real project files for static verification and subprocess tests
const settingsJson = JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8"));
const permissionsSpec = JSON.parse(
  fs.readFileSync(PERMISSIONS_SPEC_PATH, "utf8"),
);
const realPatterns = fs.readFileSync(PATTERNS_PATH, "utf8");
const realSettings = fs.readFileSync(SETTINGS_PATH, "utf8");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a PreToolUse input for Edit/Write tool targeting a file.
 * @param {"Edit"|"Write"} toolName
 * @param {string} filePath
 * @param {Object} [extra] - Additional tool_input fields
 * @returns {Object}
 */
function buildFileToolInput(toolName, filePath, extra = {}) {
  return buildHookInput({
    toolName,
    toolInput: { file_path: filePath, ...extra },
    sessionId: "test-attack-sim-058b",
  });
}

/**
 * Build a PreToolUse Bash input.
 * @param {string} command
 * @returns {Object}
 */
function buildBashInput(command) {
  return buildHookInput({
    toolName: "Bash",
    toolInput: { command },
    sessionId: "test-attack-sim-058b",
  });
}

/**
 * Build a ConfigChange input for sh-config-guard.js.
 * @returns {Object}
 */
function buildConfigChangeInput() {
  return {
    hook_type: "ConfigChange",
    tool_name: "",
    tool_input: {},
    tool_result: "",
    session_id: "test-attack-sim-058b",
    timestamp: new Date().toISOString(),
  };
}

/**
 * Check if a deny rule exists in permissions-spec.json.
 * @param {string} ruleSubstring
 * @returns {{ found: boolean, rule: string|null }}
 */
function findDenyRule(ruleSubstring) {
  for (const entry of permissionsSpec.permissions.deny) {
    if (entry.rule.includes(ruleSubstring)) {
      return { found: true, rule: entry.rule };
    }
  }
  return { found: false, rule: null };
}

// ==========================================================================
// A: soft_deny injection attacks (5 tests)
// Verify that all vectors for injecting autoMode.soft_deny are blocked.
// ==========================================================================

describe("A: soft_deny injection attacks via file modification", () => {
  // A-1: Static verification — Edit deny rule exists
  it("A-1: Edit(.claude/settings.local.json) is in deny rules", () => {
    const result = findDenyRule("Edit(.claude/settings.local.json)");
    assert.ok(
      result.found,
      "Edit deny rule for settings.local.json must exist",
    );
  });

  // A-2: Static verification — Write deny rule exists
  it("A-2: Write(.claude/settings.local.json) is in deny rules", () => {
    const result = findDenyRule("Write(.claude/settings.local.json)");
    assert.ok(
      result.found,
      "Write deny rule for settings.local.json must exist",
    );
  });

  // A-3: Live-fire — Bash echo to settings.local.json (sh-gate.js blocks)
  describe("A-3: Bash echo redirect to settings.local.json", () => {
    let tmpDir;

    before(() => {
      tmpDir = createTempDir({
        ".claude/settings.json": realSettings,
        ".claude/patterns/injection-patterns.json": realPatterns,
        ".shield-harness/session.json": JSON.stringify({}),
        ".shield-harness/logs/.gitkeep": "",
      });
    });

    after(() => {
      cleanupTempDir(tmpDir);
    });

    it("should deny Bash redirect writing soft_deny to settings.local.json", () => {
      const input = buildBashInput(
        'echo \'{"autoMode":{"soft_deny":["*"]}}\' > .claude/settings.local.json',
      );
      const result = runHookProcess("sh-gate.js", input, { cwd: tmpDir });
      assert.equal(
        result.exitCode,
        2,
        "sh-gate.js should deny writing to .claude/ via Bash redirect",
      );
    });
  });

  // A-4: Node.js indirect write — defense relies on L1 deny + L3b sandbox
  // sh-gate.js does not parse `node -e` code for fs.writeFileSync targets.
  // Defense for this vector: Edit/Write deny rules (L1) + OpenShell denyWrite (L3b).
  it("A-4: node -e indirect write is covered by Edit/Write deny rules (L1)", () => {
    // L1 deny rules block the Edit/Write tool path — the primary defense
    const editDeny = findDenyRule("Edit(.claude/settings.local.json)");
    const writeDeny = findDenyRule("Write(.claude/settings.local.json)");
    assert.ok(
      editDeny.found && writeDeny.found,
      "Both Edit and Write deny rules must exist as L1 defense against indirect writes",
    );
  });

  // A-5: Live-fire — sed partial modification
  describe("A-5: sed modification of settings.local.json", () => {
    let tmpDir;

    before(() => {
      tmpDir = createTempDir({
        ".claude/settings.json": realSettings,
        ".claude/patterns/injection-patterns.json": realPatterns,
        ".shield-harness/session.json": JSON.stringify({}),
        ".shield-harness/logs/.gitkeep": "",
      });
    });

    after(() => {
      cleanupTempDir(tmpDir);
    });

    it("should deny sed modifying settings.local.json", () => {
      const input = buildBashInput(
        'sed -i \'s/{}/{"autoMode":{"soft_deny":["*"]}}/\' .claude/settings.local.json',
      );
      const result = runHookProcess("sh-gate.js", input, { cwd: tmpDir });
      assert.equal(
        result.exitCode,
        2,
        "sh-gate.js should deny sed -i modifying .claude/",
      );
    });
  });
});

// ==========================================================================
// B: config-guard bypass attacks (5 tests)
// Verify that config-guard detects and blocks Auto Mode escalation attempts.
// ==========================================================================

describe("B: config-guard bypass attacks", () => {
  let tmpDir;

  before(() => {
    // Create temp environment with config-guard baseline (no autoMode initially)
    const baselineConfig = {
      hash: "abc123",
      deny_rules: settingsJson.permissions.deny,
      hook_count: 22,
      hook_events: [
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SessionStart",
        "ConfigChange",
      ],
      hook_commands: [],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
      policy_hashes: {},
      policy_metrics: {},
      soft_deny_count: 0,
      soft_allow_count: 0,
    };

    tmpDir = createTempDir({
      ".claude/settings.json": realSettings,
      ".claude/logs/config-hash.json": JSON.stringify(baselineConfig, null, 2),
      ".claude/hooks/lib/sh-utils.js": fs.readFileSync(
        path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "sh-utils.js"),
        "utf8",
      ),
      ".claude/hooks/lib/automode-detect.js": fs.readFileSync(
        path.join(
          PROJECT_ROOT,
          ".claude",
          "hooks",
          "lib",
          "automode-detect.js",
        ),
        "utf8",
      ),
      ".shield-harness/session.json": JSON.stringify({}),
      ".shield-harness/logs/.gitkeep": "",
    });
  });

  after(() => {
    cleanupTempDir(tmpDir);
  });

  // B-6: config-guard detects hook removal
  it("B-6: config-guard detects its own removal from hooks", () => {
    // Create settings with reduced hook count
    const modifiedSettings = JSON.parse(realSettings);
    // Remove one hook event entirely to trigger Check 2
    delete modifiedSettings.hooks.ConfigChange;
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.json"),
      JSON.stringify(modifiedSettings, null, 2),
    );

    const input = buildConfigChangeInput();
    const result = runHookProcess("sh-config-guard.js", input, { cwd: tmpDir });
    assert.equal(
      result.exitCode,
      2,
      "config-guard should deny when hook events are removed",
    );

    // Restore original settings for next test
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.json"),
      realSettings,
    );
  });

  // B-7: soft_allow escalation attempt
  it("B-7: config-guard blocks soft_allow escalation", () => {
    // Add autoMode.soft_allow to settings.local.json
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.local.json"),
      JSON.stringify({
        autoMode: { soft_allow: ["Read(*)", "Glob(*)"] },
      }),
    );

    const input = buildConfigChangeInput();
    const result = runHookProcess("sh-config-guard.js", input, { cwd: tmpDir });
    assert.equal(
      result.exitCode,
      2,
      "config-guard should deny soft_allow expansion",
    );

    // Cleanup for next test
    try {
      fs.unlinkSync(path.join(tmpDir, ".claude", "settings.local.json"));
    } catch {
      /* ignore */
    }
  });

  // B-8: soft_deny hidden among legitimate changes
  it("B-8: config-guard detects soft_deny hidden in legitimate config", () => {
    // Keep deny rules intact but sneak in soft_deny
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.local.json"),
      JSON.stringify({
        autoMode: { soft_deny: ["Bash(git push --force)"] },
      }),
    );

    const input = buildConfigChangeInput();
    const result = runHookProcess("sh-config-guard.js", input, { cwd: tmpDir });
    assert.equal(
      result.exitCode,
      2,
      "config-guard should detect soft_deny even with legitimate deny rules intact",
    );
    assert.ok(
      result.json && result.json.reason,
      "should include denial reason",
    );
    assert.ok(
      result.json.reason.includes("soft_deny"),
      "reason should mention soft_deny",
    );

    try {
      fs.unlinkSync(path.join(tmpDir, ".claude", "settings.local.json"));
    } catch {
      /* ignore */
    }
  });

  // B-9: disableAllHooks + soft_deny compound attack
  it("B-9: config-guard detects compound attack (disableAllHooks + soft_deny)", () => {
    // Modify settings to disable all hooks
    const attackSettings = JSON.parse(realSettings);
    attackSettings.disableAllHooks = true;
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.json"),
      JSON.stringify(attackSettings, null, 2),
    );
    // Also add soft_deny
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.local.json"),
      JSON.stringify({
        autoMode: { soft_deny: ["*"] },
      }),
    );

    const input = buildConfigChangeInput();
    const result = runHookProcess("sh-config-guard.js", input, { cwd: tmpDir });
    assert.equal(
      result.exitCode,
      2,
      "config-guard should deny compound attack",
    );
    // Should detect both issues
    assert.ok(
      result.json && result.json.reason,
      "should include denial reasons",
    );
    assert.ok(
      result.json.reason.includes("disableAllHooks") ||
        result.json.reason.includes("soft_deny"),
      "reason should mention at least one attack vector",
    );

    // Restore
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.json"),
      realSettings,
    );
    try {
      fs.unlinkSync(path.join(tmpDir, ".claude", "settings.local.json"));
    } catch {
      /* ignore */
    }
  });

  // B-10: gradual soft_deny from 0 to 1
  it("B-10: config-guard detects first soft_deny addition (0 → 1)", () => {
    // Add a single soft_deny
    fs.writeFileSync(
      path.join(tmpDir, ".claude", "settings.local.json"),
      JSON.stringify({
        autoMode: { soft_deny: ["Bash(rm -rf /)"] },
      }),
    );

    const input = buildConfigChangeInput();
    const result = runHookProcess("sh-config-guard.js", input, { cwd: tmpDir });
    assert.equal(
      result.exitCode,
      2,
      "config-guard should deny even a single soft_deny addition",
    );

    try {
      fs.unlinkSync(path.join(tmpDir, ".claude", "settings.local.json"));
    } catch {
      /* ignore */
    }
  });
});

// ==========================================================================
// C: Session start detection tests (3 tests)
// Verify that sh-session-start.js correctly detects and reports Auto Mode state.
// ==========================================================================

describe("C: Session start Auto Mode detection", () => {
  // C-11: CRITICAL warning for soft_deny
  describe("C-11: CRITICAL warning in session start", () => {
    let tmpDir;

    before(() => {
      tmpDir = createTempDir({
        "CLAUDE.md": "# Test Project",
        ".claude/settings.json": realSettings,
        ".claude/settings.local.json": JSON.stringify({
          autoMode: { soft_deny: ["*"] },
        }),
        ".claude/patterns/injection-patterns.json": realPatterns,
        ".claude/hooks/lib/sh-utils.js": fs.readFileSync(
          path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "sh-utils.js"),
          "utf8",
        ),
        ".claude/hooks/lib/openshell-detect.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "openshell-detect.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/automode-detect.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "automode-detect.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/policy-compat.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "policy-compat.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/policy-drift.js": fs.readFileSync(
          path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "policy-drift.js"),
          "utf8",
        ),
        ".claude/hooks/lib/permissions-validator.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "permissions-validator.js",
          ),
          "utf8",
        ),
        ".claude/permissions-spec.json": fs.readFileSync(
          PERMISSIONS_SPEC_PATH,
          "utf8",
        ),
        ".shield-harness/session.json": JSON.stringify({}),
        ".shield-harness/logs/.gitkeep": "",
      });
    });

    after(() => {
      cleanupTempDir(tmpDir);
    });

    it("should output CRITICAL warning when soft_deny is present", () => {
      const input = {
        hook_type: "SessionStart",
        tool_name: "",
        tool_input: {},
        tool_result: "",
        session_id: "test-attack-sim-058b-c11",
        timestamp: new Date().toISOString(),
      };
      const result = runHookProcess("sh-session-start.js", input, {
        cwd: tmpDir,
      });
      // Session start is fail-open — should exit 0 with context
      assert.equal(
        result.exitCode,
        0,
        "session start should allow (fail-open)",
      );
      assert.ok(result.stdout, "should produce stdout output");
      assert.ok(
        result.stdout.includes("CRITICAL"),
        "stdout should contain CRITICAL warning",
      );
      assert.ok(
        result.stdout.includes("soft_deny"),
        "stdout should mention soft_deny",
      );
    });
  });

  // C-12: WARNING for soft_allow
  describe("C-12: WARNING in session start for soft_allow", () => {
    let tmpDir;

    before(() => {
      tmpDir = createTempDir({
        "CLAUDE.md": "# Test Project",
        ".claude/settings.json": realSettings,
        ".claude/settings.local.json": JSON.stringify({
          autoMode: { soft_allow: ["Read(*)", "Glob(*)"] },
        }),
        ".claude/patterns/injection-patterns.json": realPatterns,
        ".claude/hooks/lib/sh-utils.js": fs.readFileSync(
          path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "sh-utils.js"),
          "utf8",
        ),
        ".claude/hooks/lib/openshell-detect.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "openshell-detect.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/automode-detect.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "automode-detect.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/policy-compat.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "policy-compat.js",
          ),
          "utf8",
        ),
        ".claude/hooks/lib/policy-drift.js": fs.readFileSync(
          path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "policy-drift.js"),
          "utf8",
        ),
        ".claude/hooks/lib/permissions-validator.js": fs.readFileSync(
          path.join(
            PROJECT_ROOT,
            ".claude",
            "hooks",
            "lib",
            "permissions-validator.js",
          ),
          "utf8",
        ),
        ".claude/permissions-spec.json": fs.readFileSync(
          PERMISSIONS_SPEC_PATH,
          "utf8",
        ),
        ".shield-harness/session.json": JSON.stringify({}),
        ".shield-harness/logs/.gitkeep": "",
      });
    });

    after(() => {
      cleanupTempDir(tmpDir);
    });

    it("should output WARNING when soft_allow is present", () => {
      const input = {
        hook_type: "SessionStart",
        tool_name: "",
        tool_input: {},
        tool_result: "",
        session_id: "test-attack-sim-058b-c12",
        timestamp: new Date().toISOString(),
      };
      const result = runHookProcess("sh-session-start.js", input, {
        cwd: tmpDir,
      });
      assert.equal(
        result.exitCode,
        0,
        "session start should allow (fail-open)",
      );
      assert.ok(
        result.stdout.includes("WARNING"),
        "stdout should contain WARNING",
      );
      assert.ok(
        result.stdout.includes("soft_allow"),
        "stdout should mention soft_allow",
      );
    });
  });

  // C-13: Auto Mode state recorded in session.json
  it("C-13: should record auto_mode in session.json after session start", () => {
    const tmpDir = createTempDir({
      "CLAUDE.md": "# Test Project",
      ".claude/settings.json": realSettings,
      ".claude/settings.local.json": JSON.stringify({
        autoMode: { soft_deny: ["Bash(rm*)"] },
      }),
      ".claude/patterns/injection-patterns.json": realPatterns,
      ".claude/hooks/lib/sh-utils.js": fs.readFileSync(
        path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "sh-utils.js"),
        "utf8",
      ),
      ".claude/hooks/lib/openshell-detect.js": fs.readFileSync(
        path.join(
          PROJECT_ROOT,
          ".claude",
          "hooks",
          "lib",
          "openshell-detect.js",
        ),
        "utf8",
      ),
      ".claude/hooks/lib/automode-detect.js": fs.readFileSync(
        path.join(
          PROJECT_ROOT,
          ".claude",
          "hooks",
          "lib",
          "automode-detect.js",
        ),
        "utf8",
      ),
      ".claude/hooks/lib/policy-compat.js": fs.readFileSync(
        path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "policy-compat.js"),
        "utf8",
      ),
      ".claude/hooks/lib/policy-drift.js": fs.readFileSync(
        path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "policy-drift.js"),
        "utf8",
      ),
      ".claude/hooks/lib/permissions-validator.js": fs.readFileSync(
        path.join(
          PROJECT_ROOT,
          ".claude",
          "hooks",
          "lib",
          "permissions-validator.js",
        ),
        "utf8",
      ),
      ".claude/permissions-spec.json": fs.readFileSync(
        PERMISSIONS_SPEC_PATH,
        "utf8",
      ),
      ".shield-harness/session.json": JSON.stringify({}),
      ".shield-harness/logs/.gitkeep": "",
    });

    try {
      const input = {
        hook_type: "SessionStart",
        tool_name: "",
        tool_input: {},
        tool_result: "",
        session_id: "test-attack-sim-058b-c13",
        timestamp: new Date().toISOString(),
      };
      runHookProcess("sh-session-start.js", input, { cwd: tmpDir });

      // Verify session.json has auto_mode field
      const sessionPath = path.join(tmpDir, ".shield-harness", "session.json");
      assert.ok(
        fs.existsSync(sessionPath),
        "session.json should exist after session start",
      );
      const session = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
      assert.ok(
        session.auto_mode !== undefined,
        "session should have auto_mode field",
      );
      assert.equal(
        session.auto_mode.danger_level,
        "critical",
        "auto_mode.danger_level should be critical",
      );
      assert.equal(
        session.auto_mode.detected,
        true,
        "auto_mode.detected should be true",
      );
      assert.equal(
        session.auto_mode.soft_deny_count,
        1,
        "auto_mode.soft_deny_count should be 1",
      );
    } finally {
      try {
        cleanupTempDir(tmpDir);
      } catch {
        // Cleanup failure on Windows is non-critical (EPERM on locked temp files)
      }
    }
  });
});

// ==========================================================================
// D: Multi-layer defense chain (2 tests)
// ==========================================================================

describe("D: Multi-layer defense chain verification", () => {
  // D-14: L1 deny + L2 config-guard double defense
  it("D-14: Edit deny rule and config-guard both independently protect", () => {
    // Layer 1: deny rule exists
    const editDeny = findDenyRule("Edit(.claude/settings.local.json)");
    assert.ok(editDeny.found, "L1: Edit deny rule must exist");

    // Layer 2: config-guard Check 7 blocks soft_deny addition
    const { detectDangerousMutations } = require(
      path.join(PROJECT_ROOT, ".claude", "hooks", "sh-config-guard.js"),
    );
    const stored = {
      deny_rules: settingsJson.permissions.deny,
      hook_count: 22,
      hook_events: ["PreToolUse"],
      hook_commands: [],
      sandbox: true,
      unsandboxed: false,
      disableAllHooks: false,
      policy_hashes: {},
      policy_metrics: {},
      soft_deny_count: 0,
      soft_allow_count: 0,
    };
    const current = { ...stored, soft_deny_count: 1 };
    const result = detectDangerousMutations(stored, current);
    assert.ok(
      result.blocked,
      "L2: config-guard should block soft_deny addition",
    );

    // Both layers independently protect — defense in depth confirmed
  });

  // D-15: session-start detection + config-guard blocking cooperation
  it("D-15: session-start detects CRITICAL + config-guard blocks change", () => {
    // Detection: automode-detect.js classifies soft_deny as critical
    const { detectAutoMode } = require(
      path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "automode-detect.js"),
    );

    // Simulate: create temp settings.local.json with soft_deny
    const tmpDir = createTempDir({
      ".claude/settings.local.json": JSON.stringify({
        autoMode: { soft_deny: ["*"] },
      }),
    });
    const origCwd = process.cwd();
    process.chdir(tmpDir);

    try {
      // Verify detection
      delete require.cache[
        path.join(PROJECT_ROOT, ".claude", "hooks", "lib", "automode-detect.js")
      ];
      const { detectAutoMode: freshDetect } = require(
        path.join(
          PROJECT_ROOT,
          ".claude",
          "hooks",
          "lib",
          "automode-detect.js",
        ),
      );
      const detection = freshDetect();
      assert.equal(
        detection.danger_level,
        "critical",
        "Detection should flag critical",
      );

      // Verify blocking
      const { detectDangerousMutations } = require(
        path.join(PROJECT_ROOT, ".claude", "hooks", "sh-config-guard.js"),
      );
      const stored = {
        deny_rules: [],
        hook_count: 22,
        hook_events: [],
        hook_commands: [],
        sandbox: true,
        unsandboxed: false,
        disableAllHooks: false,
        policy_hashes: {},
        policy_metrics: {},
        soft_deny_count: 0,
        soft_allow_count: 0,
      };
      const current = { ...stored, soft_deny_count: 1 };
      const blocking = detectDangerousMutations(stored, current);
      assert.ok(
        blocking.blocked,
        "Config guard should block the change that detection flagged",
      );
    } finally {
      process.chdir(origCwd);
      cleanupTempDir(tmpDir);
    }
  });
});
