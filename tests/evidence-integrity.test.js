#!/usr/bin/env node
// evidence-integrity.test.js — Hash chain integrity tests for evidence-ledger
"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { createTempDir, cleanupTempDir } = require("./helpers/hook-test-utils");

// Module under test
const {
  sha256,
  appendEvidence,
  verifyHashChain,
  CHAIN_GENESIS_HASH,
  EVIDENCE_FILE,
  SH_DIR,
} = require("../.claude/hooks/lib/sh-utils");

describe("evidence-ledger hash chain integrity", () => {
  let tmpDir;
  let originalCwd;
  let ledgerPath;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = createTempDir();
    process.chdir(tmpDir);
    // Create the logs directory structure
    const logsDir = path.join(tmpDir, SH_DIR, "logs");
    fs.mkdirSync(logsDir, { recursive: true });
    ledgerPath = path.join(tmpDir, EVIDENCE_FILE);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    cleanupTempDir(tmpDir);
  });

  describe("appendEvidence hash chain", () => {
    it("should create first entry with genesis hash as prev_hash", () => {
      appendEvidence({ hook: "test", event: "allow", tool: "Bash" });
      const content = fs.readFileSync(ledgerPath, "utf8").trim();
      const entry = JSON.parse(content);
      assert.equal(entry.prev_hash, CHAIN_GENESIS_HASH);
      assert.ok(entry.hash, "entry should have a hash");
      assert.equal(entry.hash.length, 64, "hash should be 64 hex chars");
    });

    it("should chain entries correctly (entry N prev_hash = entry N-1 hash)", () => {
      appendEvidence({ hook: "test1", event: "allow", tool: "Bash" });
      appendEvidence({ hook: "test2", event: "deny", tool: "Edit" });
      appendEvidence({ hook: "test3", event: "allow", tool: "Write" });

      const lines = fs.readFileSync(ledgerPath, "utf8").trim().split("\n");
      assert.equal(lines.length, 3);

      const entries = lines.map((l) => JSON.parse(l));
      assert.equal(entries[0].prev_hash, CHAIN_GENESIS_HASH);
      assert.equal(entries[1].prev_hash, entries[0].hash);
      assert.equal(entries[2].prev_hash, entries[1].hash);
    });

    it("should produce unique hashes for different entries", () => {
      appendEvidence({ hook: "a", event: "allow", tool: "Bash" });
      appendEvidence({ hook: "b", event: "deny", tool: "Edit" });

      const lines = fs.readFileSync(ledgerPath, "utf8").trim().split("\n");
      const entries = lines.map((l) => JSON.parse(l));
      assert.notEqual(entries[0].hash, entries[1].hash);
    });
  });

  describe("verifyHashChain()", () => {
    it("should return valid for a correct chain", () => {
      appendEvidence({ hook: "a", event: "allow", tool: "Bash" });
      appendEvidence({ hook: "b", event: "deny", tool: "Edit" });
      appendEvidence({ hook: "c", event: "allow", tool: "Write" });

      const result = verifyHashChain(ledgerPath);
      assert.equal(result.valid, true);
      assert.equal(result.entries, 3);
    });

    it("should detect tampered entry (modified field)", () => {
      appendEvidence({ hook: "a", event: "allow", tool: "Bash" });
      appendEvidence({ hook: "b", event: "deny", tool: "Edit" });

      // Tamper: modify a field in the first entry
      const lines = fs.readFileSync(ledgerPath, "utf8").trim().split("\n");
      const entry0 = JSON.parse(lines[0]);
      entry0.hook = "TAMPERED";
      lines[0] = JSON.stringify(entry0);
      fs.writeFileSync(ledgerPath, lines.join("\n") + "\n");

      const result = verifyHashChain(ledgerPath);
      assert.equal(result.valid, false);
      assert.equal(result.brokenAt, 0);
      assert.equal(result.reason, "hash_mismatch");
    });

    it("should detect broken chain (deleted entry)", () => {
      appendEvidence({ hook: "a", event: "allow", tool: "Bash" });
      appendEvidence({ hook: "b", event: "deny", tool: "Edit" });
      appendEvidence({ hook: "c", event: "allow", tool: "Write" });

      // Remove the middle entry
      const lines = fs.readFileSync(ledgerPath, "utf8").trim().split("\n");
      const newContent = [lines[0], lines[2]].join("\n") + "\n";
      fs.writeFileSync(ledgerPath, newContent);

      const result = verifyHashChain(ledgerPath);
      assert.equal(result.valid, false);
      assert.equal(result.brokenAt, 1);
      assert.equal(result.reason, "prev_hash_mismatch");
    });

    it("should handle empty ledger file", () => {
      fs.writeFileSync(ledgerPath, "");
      const result = verifyHashChain(ledgerPath);
      assert.equal(result.valid, true);
      assert.equal(result.entries, 0);
    });

    it("should handle non-existent ledger file", () => {
      const result = verifyHashChain(path.join(tmpDir, "nonexistent.jsonl"));
      assert.equal(result.valid, true);
      assert.equal(result.entries, 0);
    });
  });
});
