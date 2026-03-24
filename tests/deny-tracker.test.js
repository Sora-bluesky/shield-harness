"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const {
  createTempDir,
  cleanupTempDir,
  runHookProcess,
  buildHookInput,
} = require("./helpers/hook-test-utils");

// ---------------------------------------------------------------------------
// trackDeny() unit tests
// ---------------------------------------------------------------------------

describe("trackDeny — repeat deny tracking (§4.5)", () => {
  let tmpDir;
  let origDir;

  beforeEach(() => {
    origDir = process.cwd();
    tmpDir = createTempDir({
      ".shield-harness/session.json": JSON.stringify({}),
    });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origDir);
    cleanupTempDir(tmpDir);
  });

  // Require after chdir so SESSION_FILE resolves to tmpDir
  function getUtils() {
    // Clear module cache to pick up new cwd
    const utilsPath = path.resolve(
      origDir,
      ".claude",
      "hooks",
      "lib",
      "sh-utils.js",
    );
    delete require.cache[utilsPath];
    return require(utilsPath);
  }

  it("increments count correctly on first call", () => {
    const { trackDeny, readSession } = getUtils();
    const result = trackDeny("test:pattern_a");
    assert.equal(result.count, 1);
    assert.equal(result.exceeded, false);

    const session = readSession();
    assert.equal(session.deny_tracker["test:pattern_a"], 1);
  });

  it("increments count on repeated calls", () => {
    const { trackDeny } = getUtils();
    trackDeny("test:pattern_b");
    const result = trackDeny("test:pattern_b");
    assert.equal(result.count, 2);
    assert.equal(result.exceeded, false);
  });

  it("returns exceeded=true at threshold (3)", () => {
    const { trackDeny, REPEAT_DENY_THRESHOLD } = getUtils();
    assert.equal(REPEAT_DENY_THRESHOLD, 3);

    trackDeny("test:pattern_c");
    trackDeny("test:pattern_c");
    const result = trackDeny("test:pattern_c");
    assert.equal(result.count, 3);
    assert.equal(result.exceeded, true);
  });

  it("returns exceeded=true beyond threshold", () => {
    const { trackDeny } = getUtils();
    trackDeny("test:pattern_d");
    trackDeny("test:pattern_d");
    trackDeny("test:pattern_d");
    const result = trackDeny("test:pattern_d");
    assert.equal(result.count, 4);
    assert.equal(result.exceeded, true);
  });

  it("handles missing deny_tracker in session.json", () => {
    const { trackDeny, readSession } = getUtils();
    // session.json starts with {} — no deny_tracker field
    const result = trackDeny("test:new_key");
    assert.equal(result.count, 1);
    assert.equal(result.exceeded, false);

    const session = readSession();
    assert.ok(session.deny_tracker, "deny_tracker should be created");
  });

  it("tracks different pattern keys independently", () => {
    const { trackDeny } = getUtils();
    trackDeny("test:alpha");
    trackDeny("test:alpha");
    trackDeny("test:beta");

    const resultAlpha = trackDeny("test:alpha");
    const resultBeta = trackDeny("test:beta");

    assert.equal(resultAlpha.count, 3);
    assert.equal(resultAlpha.exceeded, true);
    assert.equal(resultBeta.count, 2);
    assert.equal(resultBeta.exceeded, false);
  });

  it("handles missing session.json gracefully", () => {
    // Remove session.json to simulate first run
    const sessionPath = path.join(tmpDir, ".shield-harness", "session.json");
    fs.unlinkSync(sessionPath);

    const { trackDeny } = getUtils();
    const result = trackDeny("test:no_session");
    assert.equal(result.count, 1);
    assert.equal(result.exceeded, false);
  });
});

// ---------------------------------------------------------------------------
// sh-gate.js integration: PROBING DETECTED message
// ---------------------------------------------------------------------------

describe("sh-gate.js — deny tracker integration", () => {
  let tmpDir;

  beforeEach(() => {
    // Pre-seed session with 2 prior denies for the rm -rf pattern
    tmpDir = createTempDir({
      ".shield-harness/session.json": JSON.stringify({
        deny_tracker: {
          "gate:rm -rf / (root filesystem destruction)": 2,
        },
      }),
    });
  });

  afterEach(() => {
    cleanupTempDir(tmpDir);
  });

  it("includes PROBING DETECTED when threshold exceeded", () => {
    const input = buildHookInput({
      toolInput: { command: "rm -rf /" },
    });
    const result = runHookProcess("sh-gate.js", input, { cwd: tmpDir });
    assert.equal(result.exitCode, 2, "should deny");
    assert.ok(result.json, "should have JSON output");
    assert.ok(
      result.json.reason.includes("PROBING DETECTED"),
      `Expected PROBING DETECTED, got: ${result.json.reason}`,
    );
  });

  it("shows normal deny message when under threshold", () => {
    // Fresh session — no prior denies
    const freshDir = createTempDir({
      ".shield-harness/session.json": JSON.stringify({}),
    });
    try {
      const input = buildHookInput({
        toolInput: { command: "rm -rf /" },
      });
      const result = runHookProcess("sh-gate.js", input, { cwd: freshDir });
      assert.equal(result.exitCode, 2, "should deny");
      assert.ok(result.json, "should have JSON output");
      assert.ok(
        result.json.reason.includes("[sh-gate] Blocked:"),
        `Expected normal deny, got: ${result.json.reason}`,
      );
      assert.ok(
        !result.json.reason.includes("PROBING"),
        "Should NOT include PROBING on first deny",
      );
    } finally {
      cleanupTempDir(freshDir);
    }
  });
});

// ---------------------------------------------------------------------------
// sh-session-start.js: deny_tracker reset
// ---------------------------------------------------------------------------

describe("sh-session-start.js — deny_tracker reset", () => {
  let tmpDir;

  afterEach(() => {
    cleanupTempDir(tmpDir);
  });

  it("resets deny_tracker on session start", () => {
    // Pre-seed with existing deny_tracker data
    tmpDir = createTempDir({
      ".shield-harness/session.json": JSON.stringify({
        deny_tracker: { "gate:something": 5 },
      }),
      "CLAUDE.md": "# Test",
      ".claude/settings.json": JSON.stringify({
        permissions: { deny: ["Edit(tasks/backlog.yaml)"] },
        hooks: {},
      }),
      ".claude/hooks/sh-session-start.js": "",
      ".claude/patterns/injection-patterns.json": JSON.stringify({
        categories: {},
      }),
    });

    const input = { hook_type: "SessionStart" };
    const result = runHookProcess("sh-session-start.js", input, {
      cwd: tmpDir,
    });

    assert.equal(result.exitCode, 0, "should allow");

    // Read session and verify deny_tracker is reset
    const sessionPath = path.join(tmpDir, ".shield-harness", "session.json");
    const session = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
    assert.deepEqual(
      session.deny_tracker,
      {},
      "deny_tracker should be reset to empty object",
    );
  });
});
