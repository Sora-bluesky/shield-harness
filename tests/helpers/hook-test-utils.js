#!/usr/bin/env node
// hook-test-utils.js — Shared test utilities for Shield Harness hook tests
"use strict";

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

// --- HookExit: Custom error for mocked process.exit() ---

class HookExit extends Error {
  constructor(code) {
    super(`process.exit(${code})`);
    this.exitCode = code;
    this.name = "HookExit";
  }
}

// --- Mock process.exit() ---

/**
 * Replace process.exit with a function that throws HookExit.
 * MUST call restore() in afterEach to avoid leaking into other tests.
 * @returns {{ restore: Function, calls: number[] }}
 */
function mockProcessExit() {
  const originalExit = process.exit;
  const calls = [];
  process.exit = (code) => {
    calls.push(code);
    throw new HookExit(code);
  };
  return {
    restore: () => {
      process.exit = originalExit;
    },
    calls,
  };
}

// --- Mock process.stdout.write() ---

/**
 * Capture stdout output instead of writing to terminal.
 * @returns {{ restore: Function, getOutput: Function, getJSON: Function }}
 */
function mockStdout() {
  const chunks = [];
  const originalWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk) => {
    chunks.push(typeof chunk === "string" ? chunk : chunk.toString());
    return true;
  };
  return {
    restore: () => {
      process.stdout.write = originalWrite;
    },
    getOutput: () => chunks.join(""),
    getJSON: () => {
      const output = chunks.join("");
      if (!output) return {};
      return JSON.parse(output);
    },
  };
}

// --- Subprocess hook runner ---

/**
 * Run a hook script as a subprocess with JSON piped to stdin.
 * Used for integration/E2E tests.
 * @param {string} hookFile - Hook filename (e.g., "sh-gate.js")
 * @param {Object} inputJSON - JSON object to pipe to stdin
 * @param {Object} [options] - { cwd, timeout, env }
 * @returns {{ exitCode: number, stdout: string, json: Object|null }}
 */
function runHookProcess(hookFile, inputJSON, options = {}) {
  const hookPath = path.resolve(
    __dirname,
    "..",
    "..",
    ".claude",
    "hooks",
    hookFile,
  );
  const cwd = options.cwd || path.resolve(__dirname, "..", "..");
  const input = JSON.stringify(inputJSON);

  try {
    const stdout = execSync(`node "${hookPath}"`, {
      input,
      encoding: "utf8",
      cwd,
      timeout: options.timeout || 5000,
      env: { ...process.env, ...options.env },
    });
    return { exitCode: 0, stdout, json: safeParseJSON(stdout) };
  } catch (err) {
    return {
      exitCode: err.status || 1,
      stdout: err.stdout || "",
      json: safeParseJSON(err.stdout),
    };
  }
}

// --- Build hook input ---

/**
 * Generate a hook input JSON object for testing.
 * @param {Object} overrides
 * @returns {Object}
 */
function buildHookInput(overrides = {}) {
  return {
    hook_type: overrides.hookType || "PreToolUse",
    tool_name: overrides.toolName || "Bash",
    tool_input: overrides.toolInput || { command: "echo test" },
    tool_result: overrides.toolResult || "",
    session_id: overrides.sessionId || "test-session-001",
    timestamp: overrides.timestamp || new Date().toISOString(),
    ...(overrides.extra || {}),
  };
}

// --- Temp directory for filesystem-dependent tests ---

/**
 * Create a temporary directory with optional stub files.
 * @param {Object} [stubs] - { "relative/path": "content" }
 * @returns {string} Absolute path to temp directory
 */
function createTempDir(stubs = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-test-"));
  for (const [relPath, content] of Object.entries(stubs)) {
    const fullPath = path.join(tmpDir, relPath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(fullPath, content);
  }
  return tmpDir;
}

/**
 * Remove a temporary directory recursively.
 * @param {string} tmpDir
 */
function cleanupTempDir(tmpDir) {
  if (tmpDir && tmpDir.includes("sh-test-")) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// --- Mock child_process.execSync ---

/**
 * Mock child_process.execSync for testing modules that shell out.
 * Accepts a map of command prefix -> response (string or Error).
 * Matches commands by prefix (startsWith).
 * @param {Object.<string, string|Error>} responses - { "docker --version": "Docker 24.0.0", "openshell": new Error("not found") }
 * @returns {{ restore: Function }}
 */
function mockExecSync(responses) {
  const cp = require("child_process");
  const originalExecSync = cp.execSync;

  cp.execSync = (cmd, opts) => {
    const cmdStr = typeof cmd === "string" ? cmd : String(cmd);
    for (const [prefix, response] of Object.entries(responses)) {
      if (cmdStr.startsWith(prefix)) {
        if (response instanceof Error) {
          throw response;
        }
        return typeof response === "string" ? response : String(response);
      }
    }
    // No match — simulate command not found
    const err = new Error(`Command not found (mocked): ${cmdStr}`);
    err.status = 1;
    throw err;
  };

  return {
    restore: () => {
      cp.execSync = originalExecSync;
    },
  };
}

// --- Helpers ---

function safeParseJSON(str) {
  if (!str) return null;
  try {
    return JSON.parse(str.trim());
  } catch {
    return null;
  }
}

module.exports = {
  HookExit,
  mockProcessExit,
  mockStdout,
  mockExecSync,
  runHookProcess,
  buildHookInput,
  createTempDir,
  cleanupTempDir,
  safeParseJSON,
};
