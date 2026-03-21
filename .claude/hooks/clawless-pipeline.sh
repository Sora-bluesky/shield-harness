#!/usr/bin/env bash
# clawless-pipeline.sh — STG gate-driven pipeline (ADR-031)
# Hook event: TaskCompleted
# Execution order: after clawless-task-gate.sh
# Spec reference: DETAILED_DESIGN.md §8.1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/lib/clawless-utils.sh"

# fail-close: jq required
if ! command -v jq &>/dev/null; then
  deny "jq is not installed. Clawless requires jq 1.6+."
fi

read_hook_input
if [ -z "$HOOK_INPUT" ]; then
  deny "Empty hook input received."
fi

# --- Constants ---
PIPELINE_CONFIG=".clawless/config/pipeline-config.json"
BACKLOG_FILE="tasks/backlog.yaml"

# --- Step 0: Load pipeline config ---
if [ ! -f "$PIPELINE_CONFIG" ]; then
  allow
fi

AUTO_COMMIT=$(jq -r '.auto_commit // false' "$PIPELINE_CONFIG")
if [ "$AUTO_COMMIT" != "true" ]; then
  allow
fi

AUTO_PUSH=$(jq -r '.auto_push // false' "$PIPELINE_CONFIG")
AUTO_PR=$(jq -r '.auto_pr // false' "$PIPELINE_CONFIG")
AUTO_MERGE=$(jq -r '.auto_merge // false' "$PIPELINE_CONFIG")
COMMIT_MSG_FORMAT=$(jq -r '.commit_message_format // "[{task_id}] STG{gate}: {intent}"' "$PIPELINE_CONFIG")

# --- Step 1: Get active task from session ---
if [ ! -f "$SESSION_FILE" ]; then
  allow
fi

ACTIVE_TASK_ID=$(jq -r '.active_task_id // empty' "$SESSION_FILE")
if [ -z "$ACTIVE_TASK_ID" ]; then
  allow
fi

# --- Step 2: Get stage_status from backlog.yaml ---
if [ ! -f "$BACKLOG_FILE" ]; then
  allow
fi

if ! command -v yq &>/dev/null; then
  allow "yq is not installed. Pipeline stage tracking skipped."
fi

STAGE_STATUS=$(yq ".tasks[] | select(.id == \"${ACTIVE_TASK_ID}\") | .stage_status" "$BACKLOG_FILE" 2>/dev/null || echo "")
TASK_INTENT=$(yq ".tasks[] | select(.id == \"${ACTIVE_TASK_ID}\") | .intent" "$BACKLOG_FILE" 2>/dev/null || echo "")

if [ -z "$STAGE_STATUS" ] || [ "$STAGE_STATUS" = "null" ]; then
  allow
fi

# --- Trusted Operation (§8.1) ---
execute_trusted() {
  local task_id="$1"
  local commands="$2"

  # Validate: only pipeline script can call this
  local caller
  caller=$(basename "${BASH_SOURCE[1]}" 2>/dev/null)
  if [ "$caller" != "clawless-pipeline.sh" ]; then
    deny "Trusted operation called from unauthorized source: ${caller}"
  fi

  # Execute in child process with CLAWLESS_PIPELINE marker
  # This bypasses Claude Code's tool system entirely
  bash -c "
    export CLAWLESS_PIPELINE=1
    export CLAWLESS_TASK_ID='${task_id}'
    ${commands}
  "
}

# --- Helper: Format commit message ---
format_commit_message() {
  local task_id="$1"
  local gate="$2"
  local intent="$3"
  local msg="$COMMIT_MSG_FORMAT"
  msg="${msg//\{task_id\}/$task_id}"
  msg="${msg//\{gate\}/$gate}"
  msg="${msg//\{intent\}/$intent}"
  echo "$msg"
}

# --- Step 3: STG gate progression ---
PROGRESS_SUMMARY=""

case "$STAGE_STATUS" in
  null|stg0_passed|stg1_passed)
    # STG2: Auto commit
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    COMMIT_MSG=$(format_commit_message "$ACTIVE_TASK_ID" "2" "$TASK_INTENT")

    execute_trusted "$ACTIVE_TASK_ID" "
      # Ensure feature branch exists
      CURRENT_BRANCH=\$(git branch --show-current)
      if [ \"\$CURRENT_BRANCH\" != \"feature/${ACTIVE_TASK_ID}\" ]; then
        git checkout -b \"feature/${ACTIVE_TASK_ID}\" 2>/dev/null || git checkout \"feature/${ACTIVE_TASK_ID}\"
      fi

      # Regenerate project views
      if command -v pwsh &>/dev/null; then
        pwsh scripts/sync-project-views.ps1 2>/dev/null || true
      fi

      # Update backlog stage
      yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stage_status = \"stg2_passed\"' tasks/backlog.yaml
      yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).start_date = \"$(date -u +%Y-%m-%d)\"' tasks/backlog.yaml
      yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).branch = \"feature/${ACTIVE_TASK_ID}\"' tasks/backlog.yaml
      yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stg_history += [{\"gate\": \"stg2\", \"passed_at\": \"${TIMESTAMP}\"}]' tasks/backlog.yaml

      # Stage all and commit (skip if no changes)
      git add -A
      git diff --cached --quiet && echo 'No changes to commit' || git commit -m '${COMMIT_MSG}'
    "

    PROGRESS_SUMMARY="STG2 passed: auto-committed [${ACTIVE_TASK_ID}]"
    ;;

  stg2_passed)
    # STG3: Auto push
    if [ "$AUTO_PUSH" = "true" ]; then
      TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

      execute_trusted "$ACTIVE_TASK_ID" "
        git push -u origin \"feature/${ACTIVE_TASK_ID}\"

        yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stage_status = \"stg3_passed\"' tasks/backlog.yaml
        yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stg_history += [{\"gate\": \"stg3\", \"passed_at\": \"${TIMESTAMP}\"}]' tasks/backlog.yaml

        git add tasks/backlog.yaml
        git diff --cached --quiet || git commit -m '[${ACTIVE_TASK_ID}] STG3: pushed to remote'
      "

      PROGRESS_SUMMARY="STG3 passed: pushed to feature/${ACTIVE_TASK_ID}"
    fi
    ;;

  stg3_passed|stg4_passed)
    # STG5: Auto PR (stg4 = CI pass, auto-skipped if no CI)
    if [ "$AUTO_PR" = "true" ]; then
      if command -v gh &>/dev/null; then
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

        PR_URL=$(execute_trusted "$ACTIVE_TASK_ID" "
          gh pr create \
            --title '[${ACTIVE_TASK_ID}] ${TASK_INTENT}' \
            --body 'Auto-generated by clawless pipeline (ADR-031)' \
            2>/dev/null
        ") || PR_URL=""

        if [ -n "$PR_URL" ]; then
          execute_trusted "$ACTIVE_TASK_ID" "
            yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stage_status = \"stg5_passed\"' tasks/backlog.yaml
            yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).pr_url = \"${PR_URL}\"' tasks/backlog.yaml
            yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stg_history += [{\"gate\": \"stg5\", \"passed_at\": \"${TIMESTAMP}\"}]' tasks/backlog.yaml

            git add tasks/backlog.yaml
            git diff --cached --quiet || git commit -m '[${ACTIVE_TASK_ID}] STG5: PR created'
          "

          PROGRESS_SUMMARY="STG5 passed: PR created at ${PR_URL}"
        else
          PROGRESS_SUMMARY="STG5: PR creation failed for feature/${ACTIVE_TASK_ID}"
        fi
      else
        PROGRESS_SUMMARY="gh CLI not found. Please create PR manually for feature/${ACTIVE_TASK_ID}"
      fi
    fi
    ;;

  stg5_passed)
    # STG6: Auto merge
    if [ "$AUTO_MERGE" = "true" ]; then
      if command -v gh &>/dev/null; then
        PR_NUMBER=$(gh pr list --head "feature/${ACTIVE_TASK_ID}" --json number -q '.[0].number' 2>/dev/null || echo "")

        if [ -n "$PR_NUMBER" ]; then
          # Check CI status (0 = all passed)
          FAILED=$(gh pr checks "$PR_NUMBER" --json state -q '[.[] | select(.state != "SUCCESS")] | length' 2>/dev/null || echo "unknown")

          if [ "$FAILED" = "0" ]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            COMPLETED_DATE=$(date -u +"%Y-%m-%d")

            execute_trusted "$ACTIVE_TASK_ID" "
              gh pr merge ${PR_NUMBER} --squash
              git checkout main
              git pull origin main

              # Branch cleanup
              git branch -d \"feature/${ACTIVE_TASK_ID}\" 2>/dev/null || true
              git push origin --delete \"feature/${ACTIVE_TASK_ID}\" 2>/dev/null || true

              # Update backlog to done
              yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).status = \"done\"' tasks/backlog.yaml
              yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stage_status = \"stg6_passed\"' tasks/backlog.yaml
              yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).completed_date = \"${COMPLETED_DATE}\"' tasks/backlog.yaml
              yq -i '(.tasks[] | select(.id == \"${ACTIVE_TASK_ID}\")).stg_history += [{\"gate\": \"stg6\", \"passed_at\": \"${TIMESTAMP}\"}]' tasks/backlog.yaml

              # Regenerate project views (final state)
              if command -v pwsh &>/dev/null; then
                pwsh scripts/sync-project-views.ps1 2>/dev/null || true
              fi

              git add -A
              git diff --cached --quiet || git commit -m '[${ACTIVE_TASK_ID}] STG6: merged and completed'
            "

            PROGRESS_SUMMARY="STG6 passed: PR #${PR_NUMBER} merged [${ACTIVE_TASK_ID}]"
          else
            PROGRESS_SUMMARY="STG5: CI checks not passed yet (${FAILED} failing). Waiting..."
          fi
        else
          PROGRESS_SUMMARY="STG5: No PR found for feature/${ACTIVE_TASK_ID}"
        fi
      fi
    fi
    ;;

  stg6_passed)
    PROGRESS_SUMMARY="Task ${ACTIVE_TASK_ID} already completed (stg6_passed)"
    ;;
esac

# --- Step 4: Output progress summary ---
if [ -n "$PROGRESS_SUMMARY" ]; then
  allow "$PROGRESS_SUMMARY"
else
  allow
fi
