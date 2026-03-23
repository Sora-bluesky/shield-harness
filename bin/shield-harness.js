#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const PROFILES = ["minimal", "standard", "strict"];
const DEFAULT_PROFILE = "standard";

// Source directories within the npm package
const PKG_ROOT = path.resolve(__dirname, "..");
const HOOK_SRC = path.join(PKG_ROOT, ".claude", "hooks");
const PATTERN_SRC = path.join(PKG_ROOT, ".claude", "patterns");
const RULES_SRC = path.join(PKG_ROOT, ".claude", "rules");

/**
 * Recursively copy a directory.
 * @param {string} src
 * @param {string} dest
 */
function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });

  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Main init command.
 * @param {string} profile
 */
function init(profile) {
  const targetDir = process.cwd();
  const claudeDir = path.join(targetDir, ".claude");
  const shieldHarnessDir = path.join(targetDir, ".shield-harness");

  // Check if already initialized
  if (fs.existsSync(path.join(claudeDir, "hooks", "sh-gate.js"))) {
    console.error("Shield Harness is already initialized in this directory.");
    console.error("To re-initialize, remove .claude/hooks/sh-*.js first.");
    process.exit(1);
  }

  console.log(`Initializing Shield Harness (profile: ${profile})...`);

  // Copy hooks
  copyDir(HOOK_SRC, path.join(claudeDir, "hooks"));
  console.log("  [OK] hooks/");

  // Copy patterns
  copyDir(PATTERN_SRC, path.join(claudeDir, "patterns"));
  console.log("  [OK] patterns/");

  // Copy rules
  copyDir(RULES_SRC, path.join(claudeDir, "rules"));
  console.log("  [OK] rules/");

  // Create .shield-harness runtime directories
  fs.mkdirSync(path.join(shieldHarnessDir, "config"), { recursive: true });
  fs.mkdirSync(path.join(shieldHarnessDir, "logs"), { recursive: true });
  fs.mkdirSync(path.join(shieldHarnessDir, "state"), { recursive: true });
  console.log("  [OK] .shield-harness/");

  // Create default pipeline config
  const pipelineConfig = {
    auto_commit: false,
    auto_push: false,
    auto_pr: false,
    auto_merge: false,
    auto_branch_cleanup: false,
    commit_message_format: "[{task_id}] STG{gate}: {intent}",
    pr_template: ".github/pull_request_template.md",
    protected_branches: ["main", "master"],
    approval_free: profile !== "strict",
    sync_views_on_commit: true,
    sync_views_on_session_start: true,
    auto_tag: false,
    version_bump: "patch",
    auto_pickup_next_task: false,
    auto_skip_blocked: false,
    blocked_notification_channel: null,
  };

  const configPath = path.join(
    shieldHarnessDir,
    "config",
    "pipeline-config.json",
  );
  if (!fs.existsSync(configPath)) {
    fs.writeFileSync(
      configPath,
      JSON.stringify(pipelineConfig, null, 2) + "\n",
    );
    console.log("  [OK] pipeline-config.json");
  }

  console.log("");
  console.log(`Shield Harness initialized successfully (profile: ${profile}).`);
  console.log("Run 'claude' to start a secured session.");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const command = args[0];

if (command === "init") {
  let profile = DEFAULT_PROFILE;
  const profileIdx = args.indexOf("--profile");
  if (profileIdx !== -1 && args[profileIdx + 1]) {
    profile = args[profileIdx + 1];
    if (!PROFILES.includes(profile)) {
      console.error(`Unknown profile: ${profile}`);
      console.error(`Available profiles: ${PROFILES.join(", ")}`);
      process.exit(1);
    }
  }
  init(profile);
} else {
  const pkg = require("../package.json");
  console.log(`Shield Harness v${pkg.version}`);
  console.log("");
  console.log("Usage:");
  console.log("  npx shield-harness init [--profile minimal|standard|strict]");
  console.log("");
  console.log("Profiles:");
  console.log("  minimal   — Minimal config, approval-free");
  console.log("  standard  — Recommended (default), approval-free");
  console.log("  strict    — Strict config, requires human approval");
}
