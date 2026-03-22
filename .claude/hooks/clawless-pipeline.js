#!/usr/bin/env node
// clawless-pipeline.js — STG gate-driven pipeline (Node.js port)
// Spec: DETAILED_DESIGN.md §8.1
// Event: TaskCompleted
// Execution order: after clawless-task-gate.js
// Target response time: < 30000ms
"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const {
  readHookInput,
  allow,
  deny,
  readSession,
  readYaml,
  appendEvidence,
  CLAWLESS_DIR,
} = require("./lib/clawless-utils");

const HOOK_NAME = "clawless-pipeline";
const PIPELINE_CONFIG = path.join(
  CLAWLESS_DIR,
  "config",
  "pipeline-config.json",
);
const BACKLOG_FILE = path.join("tasks", "backlog.yaml");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Load pipeline configuration.
 * @returns {Object|null}
 */
function loadPipelineConfig() {
  try {
    if (!fs.existsSync(PIPELINE_CONFIG)) return null;
    return JSON.parse(fs.readFileSync(PIPELINE_CONFIG, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Get task data from backlog.yaml.
 * @param {string} taskId
 * @returns {{ stage_status: string, intent: string, branch: string, pr_url: string }|null}
 */
function getTaskData(taskId) {
  try {
    const backlog = readYaml(BACKLOG_FILE);
    const tasks = backlog.tasks || [];
    const task = tasks.find((t) => t.id === taskId);
    if (!task) return null;
    return {
      stage_status: task.stage_status || null,
      intent: task.intent || "",
      branch: task.branch || "",
      pr_url: task.pr_url || "",
    };
  } catch {
    return null;
  }
}

/**
 * Execute a trusted git operation in a child process.
 * Uses CLAWLESS_PIPELINE=1 env to identify trusted operations.
 * @param {string} taskId
 * @param {string} command
 * @returns {string} stdout
 */
function executeTrusted(taskId, command) {
  return execSync(command, {
    encoding: "utf8",
    timeout: 30000,
    env: {
      ...process.env,
      CLAWLESS_PIPELINE: "1",
      CLAWLESS_TASK_ID: taskId,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

/**
 * Update backlog.yaml task fields via js-yaml.
 * @param {string} taskId
 * @param {Object} updates - key-value pairs to update
 */
function updateBacklog(taskId, updates) {
  let yaml;
  try {
    yaml = require("js-yaml");
  } catch {
    // js-yaml not available — skip backlog update
    return;
  }

  try {
    const content = fs.readFileSync(BACKLOG_FILE, "utf8");
    const backlog = yaml.load(content);
    const tasks = backlog.tasks || [];
    const task = tasks.find((t) => t.id === taskId);
    if (!task) return;

    // Apply updates
    for (const [key, value] of Object.entries(updates)) {
      if (key === "stg_history_push") {
        if (!Array.isArray(task.stg_history)) task.stg_history = [];
        task.stg_history.push(value);
      } else {
        task[key] = value;
      }
    }

    // Write back
    const output = yaml.dump(backlog, {
      lineWidth: -1,
      noRefs: true,
      quotingType: '"',
      forceQuotes: false,
    });
    fs.writeFileSync(BACKLOG_FILE, output);
  } catch {
    // Backlog update failure is non-critical for pipeline
  }
}

/**
 * Format commit message from template.
 * @param {string} template
 * @param {string} taskId
 * @param {string} gate
 * @param {string} intent
 * @returns {string}
 */
function formatCommitMsg(template, taskId, gate, intent) {
  return template
    .replace("{task_id}", taskId)
    .replace("{gate}", gate)
    .replace("{intent}", intent);
}

/**
 * Check if a command exists.
 * @param {string} cmd
 * @returns {boolean}
 */
function commandExists(cmd) {
  try {
    execSync(`which ${cmd}`, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

try {
  const input = readHookInput();

  // Step 0: Load pipeline config
  const config = loadPipelineConfig();
  if (!config || config.auto_commit !== true) {
    allow();
  }

  const autoCommit = config.auto_commit === true;
  const autoPush = config.auto_push === true;
  const autoPR = config.auto_pr === true;
  const autoMerge = config.auto_merge === true;
  const commitFmt =
    config.commit_message_format || "[{task_id}] STG{gate}: {intent}";

  // Step 1: Get active task
  const session = readSession();
  const taskId = session.active_task_id;
  if (!taskId) {
    allow();
  }

  // Step 2: Get stage status
  const taskData = getTaskData(taskId);
  if (!taskData) {
    allow();
  }

  const stageStatus = taskData.stage_status;
  if (!stageStatus) {
    allow();
  }

  // Step 3: STG gate progression
  let summary = "";
  const timestamp = new Date().toISOString();
  const today = timestamp.slice(0, 10);

  switch (stageStatus) {
    case null:
    case "stg0_passed":
    case "stg1_passed": {
      // STG2: Auto commit
      if (!autoCommit) break;

      const commitMsg = formatCommitMsg(
        commitFmt,
        taskId,
        "2",
        taskData.intent,
      );
      const branchName = `feature/${taskId}`;

      try {
        // Ensure feature branch
        try {
          executeTrusted(taskId, `git checkout -b "${branchName}"`);
        } catch {
          try {
            executeTrusted(taskId, `git checkout "${branchName}"`);
          } catch {
            // Already on the branch
          }
        }

        // Sync project views
        if (commandExists("pwsh")) {
          try {
            executeTrusted(taskId, "pwsh scripts/sync-project-views.ps1");
          } catch {
            // Non-critical
          }
        }

        // Update backlog
        updateBacklog(taskId, {
          stage_status: "stg2_passed",
          start_date: today,
          branch: branchName,
          stg_history_push: { gate: "stg2", passed_at: timestamp },
        });

        // Stage and commit
        executeTrusted(taskId, "git add -A");
        try {
          executeTrusted(taskId, `git commit -m "${commitMsg}"`);
        } catch {
          // No changes to commit
        }

        summary = `STG2 passed: auto-committed [${taskId}]`;
      } catch (err) {
        summary = `STG2 error: ${err.message}`;
      }
      break;
    }

    case "stg2_passed": {
      // STG3: Auto push
      if (!autoPush) break;

      const branchName = taskData.branch || `feature/${taskId}`;

      try {
        executeTrusted(taskId, `git push -u origin "${branchName}"`);

        updateBacklog(taskId, {
          stage_status: "stg3_passed",
          stg_history_push: { gate: "stg3", passed_at: timestamp },
        });

        // Commit backlog update
        executeTrusted(taskId, "git add tasks/backlog.yaml");
        try {
          executeTrusted(
            taskId,
            `git commit -m "[${taskId}] STG3: pushed to remote"`,
          );
        } catch {
          // No changes
        }

        summary = `STG3 passed: pushed to ${branchName}`;
      } catch (err) {
        summary = `STG3 error: ${err.message}`;
      }
      break;
    }

    case "stg3_passed":
    case "stg4_passed": {
      // STG5: Auto PR
      if (!autoPR) break;

      if (!commandExists("gh")) {
        summary = `gh CLI not found. Please create PR manually for feature/${taskId}`;
        break;
      }

      try {
        const prUrl = executeTrusted(
          taskId,
          `gh pr create --title "[${taskId}] ${taskData.intent}" --body "Auto-generated by clawless pipeline (ADR-031)"`,
        ).trim();

        if (prUrl) {
          updateBacklog(taskId, {
            stage_status: "stg5_passed",
            pr_url: prUrl,
            stg_history_push: { gate: "stg5", passed_at: timestamp },
          });

          executeTrusted(taskId, "git add tasks/backlog.yaml");
          try {
            executeTrusted(
              taskId,
              `git commit -m "[${taskId}] STG5: PR created"`,
            );
          } catch {
            // No changes
          }

          summary = `STG5 passed: PR created at ${prUrl}`;
        } else {
          summary = `STG5: PR creation failed for feature/${taskId}`;
        }
      } catch (err) {
        summary = `STG5 error: ${err.message}`;
      }
      break;
    }

    case "stg5_passed": {
      // STG6: Auto merge
      if (!autoMerge) break;

      if (!commandExists("gh")) {
        summary = "gh CLI not found. Please merge PR manually.";
        break;
      }

      try {
        const branchName = taskData.branch || `feature/${taskId}`;
        const prNumberStr = executeTrusted(
          taskId,
          `gh pr list --head "${branchName}" --json number -q ".[0].number"`,
        ).trim();

        if (!prNumberStr) {
          summary = `STG5: No PR found for ${branchName}`;
          break;
        }

        // Check CI status
        let failedCount;
        try {
          failedCount = executeTrusted(
            taskId,
            `gh pr checks ${prNumberStr} --json state -q '[.[] | select(.state != "SUCCESS")] | length'`,
          ).trim();
        } catch {
          failedCount = "unknown";
        }

        if (failedCount !== "0") {
          summary = `STG5: CI checks not passed yet (${failedCount} failing). Waiting...`;
          break;
        }

        // Merge
        executeTrusted(taskId, `gh pr merge ${prNumberStr} --squash`);
        executeTrusted(taskId, "git checkout main");
        executeTrusted(taskId, "git pull origin main");

        // Branch cleanup
        try {
          executeTrusted(taskId, `git branch -d "${branchName}"`);
        } catch {
          // Already deleted
        }
        try {
          executeTrusted(taskId, `git push origin --delete "${branchName}"`);
        } catch {
          // Already deleted remotely
        }

        // Update backlog to done
        updateBacklog(taskId, {
          status: "done",
          stage_status: "stg6_passed",
          completed_date: today,
          stg_history_push: { gate: "stg6", passed_at: timestamp },
        });

        // Sync views
        if (commandExists("pwsh")) {
          try {
            executeTrusted(taskId, "pwsh scripts/sync-project-views.ps1");
          } catch {
            // Non-critical
          }
        }

        // Final commit
        executeTrusted(taskId, "git add -A");
        try {
          executeTrusted(
            taskId,
            `git commit -m "[${taskId}] STG6: merged and completed"`,
          );
        } catch {
          // No changes
        }

        summary = `STG6 passed: PR #${prNumberStr} merged [${taskId}]`;
      } catch (err) {
        summary = `STG6 error: ${err.message}`;
      }
      break;
    }

    case "stg6_passed":
      summary = `Task ${taskId} already completed (stg6_passed)`;
      break;

    default:
      summary = `Unknown stage: ${stageStatus}`;
      break;
  }

  // Step 4: Output
  if (summary) {
    try {
      appendEvidence({
        hook: HOOK_NAME,
        event: "TaskCompleted",
        decision: "allow",
        task_id: taskId,
        stage: stageStatus,
        summary,
        session_id: input.sessionId,
      });
    } catch {
      // Non-blocking
    }

    allow(`[${HOOK_NAME}] ${summary}`);
  }

  allow();
} catch (_err) {
  // Pipeline is operational — fail-open
  allow();
}

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  loadPipelineConfig,
  getTaskData,
  executeTrusted,
  updateBacklog,
  formatCommitMsg,
  commandExists,
};
