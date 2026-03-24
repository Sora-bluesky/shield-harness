#!/usr/bin/env node
// openshell-detect.test.js — Unit tests for OpenShell detection module
"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { mockExecSync } = require("./helpers/hook-test-utils");

// Module under test — parseVersion is a pure function, safe to import directly
const { parseVersion } = require("../.claude/hooks/lib/openshell-detect");

// Cache paths for module invalidation (detectOpenShell depends on execSync)
const DETECT_MOD = require.resolve("../.claude/hooks/lib/openshell-detect");
const UTILS_MOD = require.resolve("../.claude/hooks/lib/sh-utils");

// ---------------------------------------------------------------------------
// parseVersion()
// ---------------------------------------------------------------------------

describe("parseVersion()", () => {
  it("should parse 'openshell 0.0.13' format", () => {
    assert.equal(parseVersion("openshell 0.0.13"), "0.0.13");
  });

  it("should parse bare version '0.0.14'", () => {
    assert.equal(parseVersion("0.0.14"), "0.0.14");
  });

  it("should parse version with surrounding text", () => {
    assert.equal(parseVersion("version 1.2.3-beta"), "1.2.3");
  });

  it("should return null for empty string", () => {
    assert.equal(parseVersion(""), null);
  });

  it("should return null for null input", () => {
    assert.equal(parseVersion(null), null);
  });

  it("should return null for undefined input", () => {
    assert.equal(parseVersion(undefined), null);
  });

  it("should return null for non-version string", () => {
    assert.equal(parseVersion("no version here"), null);
  });
});

// ---------------------------------------------------------------------------
// detectOpenShell() — with mocked execSync
// ---------------------------------------------------------------------------

describe("detectOpenShell()", () => {
  let restoreMock = null;

  // Clear module cache BEFORE each test so re-require picks up the mock
  beforeEach(() => {
    delete require.cache[DETECT_MOD];
    delete require.cache[UTILS_MOD];
  });

  afterEach(() => {
    if (restoreMock) {
      restoreMock.restore();
      restoreMock = null;
    }
    // Clear require cache after test to prevent cross-test contamination
    delete require.cache[DETECT_MOD];
    delete require.cache[UTILS_MOD];
  });

  it("should return docker_not_found when docker is not available", () => {
    // Mock: all commands fail (neither 'which docker' nor 'where docker' succeed)
    restoreMock = mockExecSync({});
    // Re-require after mock
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, false);
    assert.equal(result.reason, "docker_not_found");
    assert.equal(result.docker_available, false);
  });

  it("should return openshell_not_installed when docker exists but openshell does not", () => {
    restoreMock = mockExecSync({
      "which docker": "/usr/bin/docker",
      "where docker": "C:\\Program Files\\Docker\\docker.exe",
      // openshell commands not registered → will throw
    });
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, false);
    assert.equal(result.reason, "openshell_not_installed");
    assert.equal(result.docker_available, true);
  });

  it("should return container_not_running when sandbox is not active", () => {
    restoreMock = mockExecSync({
      "which docker": "/usr/bin/docker",
      "which openshell": "/usr/local/bin/openshell",
      "openshell --version": "openshell 0.0.14",
      "openshell sandbox list": "No active sandboxes",
      // curl not available → skip version fetch
    });
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, false);
    assert.equal(result.reason, "container_not_running");
    assert.equal(result.docker_available, true);
    assert.equal(result.container_running, false);
    assert.equal(result.version, "0.0.14");
  });

  it("should return available:true when all checks pass", () => {
    restoreMock = mockExecSync({
      "which docker": "/usr/bin/docker",
      "which openshell": "/usr/local/bin/openshell",
      "openshell --version": "openshell 0.0.14",
      "openshell sandbox list": "sandbox-001  running  2h ago",
      // curl available but returns error (skip version check gracefully)
      "which curl": "/usr/bin/curl",
      "curl ": '{"tag_name":"v0.0.14"}',
    });
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, true);
    assert.equal(result.version, "0.0.14");
    assert.equal(result.docker_available, true);
    assert.equal(result.container_running, true);
    assert.ok(result.detected_at, "should have detected_at timestamp");
  });

  it("should detect 'inactive' status as container not running", () => {
    restoreMock = mockExecSync({
      "which docker": "/usr/bin/docker",
      "which openshell": "/usr/local/bin/openshell",
      "openshell --version": "0.0.13",
      "openshell sandbox list": "sandbox-001  inactive  stopped 1h ago",
    });
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, false);
    assert.equal(result.container_running, false);
    assert.equal(result.reason, "container_not_running");
  });

  it("should handle version parsing failure gracefully", () => {
    restoreMock = mockExecSync({
      "which docker": "/usr/bin/docker",
      "which openshell": "/usr/local/bin/openshell",
      "openshell --version": "unknown format",
      "openshell sandbox list": "sandbox-001  running  active",
      "which curl": "/usr/bin/curl",
      "curl ": '{"tag_name":"v0.0.15"}',
    });
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    const result = detectOpenShell();

    assert.equal(result.available, true);
    assert.equal(result.version, null);
    assert.equal(result.container_running, true);
  });
});
