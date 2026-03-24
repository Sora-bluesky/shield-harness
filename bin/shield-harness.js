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

  // OpenShell setup guide (Layer 3b)
  printOpenShellGuide();
}

/**
 * Detect OpenShell status and print a setup guide.
 * fail-safe: never throws, prints basic guide on any error.
 */
function printOpenShellGuide() {
  console.log("");
  console.log("─── OpenShell Setup (Layer 3b: Sandbox Isolation) ───");
  console.log("");

  let status;
  try {
    const {
      detectOpenShell,
    } = require("../.claude/hooks/lib/openshell-detect");
    status = detectOpenShell();
  } catch {
    // Detection library not available — show basic guide
    printBasicGuide();
    return;
  }

  if (status.available) {
    // OpenShell is running
    console.log("  [OK] OpenShell detected and running");
    console.log(`       Version: ${status.version || "unknown"}`);
    if (status.update_available && status.latest_version) {
      console.log(
        `       Update available: ${status.version} -> ${status.latest_version}`,
      );
      console.log("       Run: openshell update");
    }
    console.log("");
    console.log("  Layer 3b sandbox isolation is active.");
    return;
  }

  // Not fully available — guide based on what's missing
  switch (status.reason) {
    case "docker_not_found":
      console.log("  [1/3] Install Docker Desktop:");
      console.log("        https://www.docker.com/products/docker-desktop/");
      console.log("");
      console.log("  [2/3] Install NVIDIA OpenShell:");
      console.log("        https://github.com/NVIDIA/OpenShell");
      console.log("        pip install openshell");
      console.log("");
      console.log("  [3/3] Start a sandbox:");
      console.log("        openshell sandbox start");
      break;

    case "openshell_not_installed":
      console.log("  [OK] Docker detected");
      console.log("");
      console.log("  [1/2] Install NVIDIA OpenShell:");
      console.log("        https://github.com/NVIDIA/OpenShell");
      console.log("        pip install openshell");
      console.log("");
      console.log("  [2/2] Start a sandbox:");
      console.log("        openshell sandbox start");
      break;

    case "container_not_running":
      console.log("  [OK] Docker detected");
      console.log(`  [OK] OpenShell installed (v${status.version || "?"})`);
      if (status.update_available && status.latest_version) {
        console.log(
          `       Update available: ${status.version} -> ${status.latest_version}`,
        );
      }
      console.log("");
      console.log("  [1/1] Start the sandbox:");
      console.log("        openshell sandbox start");
      break;

    default:
      printBasicGuide();
      return;
  }

  console.log("");
  console.log("  OpenShell adds container-level isolation to Shield Harness,");
  console.log("  limiting blast radius even if a hook bypass is found.");
}

/**
 * Fallback: print basic setup guide without detection.
 */
function printBasicGuide() {
  console.log("  For enhanced security, set up NVIDIA OpenShell:");
  console.log("  https://github.com/NVIDIA/OpenShell");
  console.log("");
  console.log("  Setup steps:");
  console.log("    1. Install Docker Desktop");
  console.log("    2. pip install openshell");
  console.log("    3. openshell sandbox start");
}

// ---------------------------------------------------------------------------
// generate-policy command
// ---------------------------------------------------------------------------

const POLICY_PROFILES = ["standard", "strict"];
const DEFAULT_POLICY_OUTPUT = path.join(
  ".claude",
  "policies",
  "openshell-generated.yaml",
);

/**
 * Generate OpenShell policy YAML from permissions-spec.json.
 * @param {string[]} args - CLI arguments (after "generate-policy")
 */
function generatePolicy(args) {
  // Parse --output
  let output = DEFAULT_POLICY_OUTPUT;
  const outputIdx = args.indexOf("--output");
  if (outputIdx !== -1 && args[outputIdx + 1]) {
    output = args[outputIdx + 1];
  }

  // Parse --profile
  let profile = "standard";
  const profileIdx = args.indexOf("--profile");
  if (profileIdx !== -1 && args[profileIdx + 1]) {
    profile = args[profileIdx + 1];
    if (!POLICY_PROFILES.includes(profile)) {
      console.error(`Unknown profile: ${profile}`);
      console.error(`Available profiles: ${POLICY_PROFILES.join(", ")}`);
      process.exit(1);
    }
  }

  // Read permissions-spec.json
  const specPath = path.join(process.cwd(), ".claude", "permissions-spec.json");
  if (!fs.existsSync(specPath)) {
    console.error("permissions-spec.json not found at: " + specPath);
    console.error("Run 'npx shield-harness init' first.");
    process.exit(1);
  }

  let spec;
  try {
    spec = JSON.parse(fs.readFileSync(specPath, "utf8"));
  } catch (err) {
    console.error("Failed to parse permissions-spec.json: " + err.message);
    process.exit(1);
  }

  // Generate YAML
  let yaml;
  try {
    const {
      generatePolicyYaml,
    } = require("../.claude/hooks/lib/tier-policy-gen");
    yaml = generatePolicyYaml(spec, { profile });
  } catch (err) {
    console.error("Failed to generate policy: " + err.message);
    process.exit(1);
  }

  // Write output
  const outputPath = path.resolve(process.cwd(), output);
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  fs.writeFileSync(outputPath, yaml);

  console.log(`Policy generated successfully (profile: ${profile}).`);
  console.log(`  Output: ${output}`);
  console.log("");
  console.log("Usage:");
  console.log(`  openshell sandbox create --policy ${output} -- claude`);
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
} else if (command === "generate-policy") {
  generatePolicy(args);
} else {
  const pkg = require("../package.json");
  console.log(`Shield Harness v${pkg.version}`);
  console.log("");
  console.log("Usage:");
  console.log("  npx shield-harness init [--profile minimal|standard|strict]");
  console.log(
    "  npx shield-harness generate-policy [--output <path>] [--profile standard|strict]",
  );
  console.log("");
  console.log("Profiles:");
  console.log("  minimal   — Minimal config, approval-free");
  console.log("  standard  — Recommended (default), approval-free");
  console.log("  strict    — Strict config, requires human approval");
}
