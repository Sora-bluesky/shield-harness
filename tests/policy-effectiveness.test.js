#!/usr/bin/env node
// policy-effectiveness.test.js — Verify generated policies cover THREAT_MODEL 7.2 residual risks
// Tests that permissions-spec.json deny rules address the four residual risk categories.
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const SPEC_PATH = path.join(".claude", "permissions-spec.json");

/**
 * Load deny rules from permissions-spec.json as plain strings.
 * @returns {string[]}
 */
function loadDenyRules() {
  const raw = JSON.parse(fs.readFileSync(SPEC_PATH, "utf8"));
  return raw.permissions.deny.map((entry) =>
    typeof entry === "string" ? entry : entry.rule,
  );
}

/**
 * Extract all Edit/Write target paths from deny rules.
 * @param {string[]} rules
 * @returns {string[]}
 */
function extractDenyWritePaths(rules) {
  return rules
    .filter((r) => r.startsWith("Edit(") || r.startsWith("Write("))
    .map((r) => r.replace(/^(Edit|Write)\(/, "").replace(/\)$/, ""));
}

/**
 * Extract all Read target paths from deny rules.
 * @param {string[]} rules
 * @returns {string[]}
 */
function extractDenyReadPaths(rules) {
  return rules
    .filter((r) => r.startsWith("Read("))
    .map((r) => r.replace(/^Read\(/, "").replace(/\)$/, ""));
}

/**
 * Extract all Bash deny commands from deny rules.
 * @param {string[]} rules
 * @returns {string[]}
 */
function extractBashDenyCommands(rules) {
  return rules
    .filter((r) => r.startsWith("Bash("))
    .map((r) => r.replace(/^Bash\(/, "").replace(/\)$/, ""));
}

// ---------------------------------------------------------------------------
// THREAT_MODEL 7.2 Residual Risk Coverage
// ---------------------------------------------------------------------------

describe("Policy effectiveness — THREAT_MODEL 7.2 residual risk coverage", () => {
  const denyRules = loadDenyRules();
  const readPaths = extractDenyReadPaths(denyRules);
  const writePaths = extractDenyWritePaths(denyRules);
  const bashCommands = extractBashDenyCommands(denyRules);

  // -----------------------------------------------------------------------
  // Risk 1: Pipe chain file access (child process file read via bash)
  // -----------------------------------------------------------------------

  describe("Pipe chain defense (child process file access)", () => {
    it("should deny Read access to ~/.ssh/**", () => {
      assert.ok(
        readPaths.some((p) => p.includes(".ssh")),
        "~/.ssh/** should be in deny Read rules",
      );
    });

    it("should deny Read access to ~/.aws/**", () => {
      assert.ok(
        readPaths.some((p) => p.includes(".aws")),
        "~/.aws/** should be in deny Read rules",
      );
    });

    it("should deny Bash cat of SSH keys", () => {
      assert.ok(
        bashCommands.some((c) => c.includes(".ssh") && c.includes("cat")),
        "cat */.ssh/* should be in deny Bash rules",
      );
    });
  });

  // -----------------------------------------------------------------------
  // Risk 2: Raw socket communication
  // -----------------------------------------------------------------------

  describe("Raw socket defense (network isolation)", () => {
    it("should deny Bash curl for data exfiltration", () => {
      assert.ok(
        bashCommands.some((c) => c.startsWith("curl")),
        "curl should be in deny Bash rules",
      );
    });

    it("should deny Bash wget for data exfiltration", () => {
      assert.ok(
        bashCommands.some((c) => c.startsWith("wget")),
        "wget should be in deny Bash rules",
      );
    });

    it("should deny Bash nc (netcat) for raw socket", () => {
      assert.ok(
        bashCommands.some((c) => c.startsWith("nc ")),
        "nc should be in deny Bash rules",
      );
    });

    it("should deny Bash ncat for raw socket", () => {
      assert.ok(
        bashCommands.some((c) => c.startsWith("ncat")),
        "ncat should be in deny Bash rules",
      );
    });

    it("should deny Bash nmap for network scanning", () => {
      assert.ok(
        bashCommands.some((c) => c.startsWith("nmap")),
        "nmap should be in deny Bash rules",
      );
    });

    it("should deny Windows Invoke-WebRequest", () => {
      assert.ok(
        bashCommands.some((c) => c.includes("Invoke-WebRequest")),
        "Invoke-WebRequest should be in deny Bash rules",
      );
    });
  });

  // -----------------------------------------------------------------------
  // Risk 3: Config tampering (.claude/hooks/**)
  // -----------------------------------------------------------------------

  describe("Config tampering defense (.claude/hooks/**)", () => {
    it("should deny Edit to .claude/hooks/**", () => {
      assert.ok(
        writePaths.includes(".claude/hooks/**"),
        ".claude/hooks/** should be in deny Edit/Write rules",
      );
    });

    it("should deny Write to .claude/hooks/**", () => {
      const writeOnly = denyRules
        .filter((r) => r.startsWith("Write("))
        .map((r) => r.replace(/^Write\(/, "").replace(/\)$/, ""));
      assert.ok(
        writeOnly.includes(".claude/hooks/**"),
        ".claude/hooks/** should be in deny Write rules",
      );
    });

    it("should deny Edit to .claude/settings.json", () => {
      assert.ok(
        writePaths.includes(".claude/settings.json"),
        ".claude/settings.json should be in deny Edit/Write rules",
      );
    });

    it("should deny Edit to .claude/rules/**", () => {
      assert.ok(
        writePaths.includes(".claude/rules/**"),
        ".claude/rules/** should be in deny Edit/Write rules",
      );
    });

    it("should deny Edit to .claude/patterns/**", () => {
      assert.ok(
        writePaths.includes(".claude/patterns/**"),
        ".claude/patterns/** should be in deny Edit/Write rules",
      );
    });
  });

  // -----------------------------------------------------------------------
  // Completeness: All Read deny paths from permissions-spec appear
  // -----------------------------------------------------------------------

  describe("Deny Read completeness", () => {
    it("should have deny Read rules for all sensitive paths", () => {
      const expectedReadPaths = [
        ".ssh",
        ".aws",
        ".gnupg",
        ".env",
        "credentials",
        ".pem",
        ".key",
        "secret",
        "gcloud",
      ];
      for (const expected of expectedReadPaths) {
        assert.ok(
          readPaths.some((p) => p.includes(expected)),
          `deny Read should cover path containing '${expected}'`,
        );
      }
    });
  });

  // -----------------------------------------------------------------------
  // Completeness: All Edit/Write deny paths from permissions-spec appear
  // -----------------------------------------------------------------------

  describe("Deny Write completeness", () => {
    it("should have deny Edit/Write rules for all protected config paths", () => {
      const expectedWritePaths = [
        ".claude/hooks/**",
        ".claude/rules/**",
        ".claude/skills/**",
        ".claude/settings.json",
        ".claude/permissions-spec.json",
        ".shield-harness/**",
        ".claude/patterns/**",
      ];
      for (const expected of expectedWritePaths) {
        assert.ok(
          writePaths.includes(expected),
          `deny Edit/Write should cover '${expected}'`,
        );
      }
    });
  });
});
