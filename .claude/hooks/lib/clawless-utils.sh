#!/usr/bin/env bash
# clawless-utils.sh — Shared utilities for all Clawless hooks

CLAWLESS_DIR=".clawless"
EVIDENCE_FILE="${CLAWLESS_DIR}/logs/evidence-ledger.jsonl"
SESSION_FILE="${CLAWLESS_DIR}/session.json"
PATTERNS_FILE=".claude/patterns/injection-patterns.json"

# Read JSON from stdin and cache it
read_hook_input() {
  HOOK_INPUT=$(cat)
  HOOK_TYPE=$(echo "$HOOK_INPUT" | jq -r '.hook_type // empty')
  TOOL_NAME=$(echo "$HOOK_INPUT" | jq -r '.tool_name // empty')
  TOOL_INPUT=$(echo "$HOOK_INPUT" | jq -r '.tool_input // empty')
  SESSION_ID=$(echo "$HOOK_INPUT" | jq -r '.session_id // empty')
}

# Output allow with optional additionalContext
allow() {
  local ctx="${1:-}"
  if [ -n "$ctx" ]; then
    echo "{\"additionalContext\":$(echo "$ctx" | jq -Rs .)}"
  else
    echo "{}"
  fi
  exit 0
}

# Output deny with reason (stdout, NOT stderr)
# printf fallback when jq is unavailable (breaks circular dependency with §2.3 fail-close)
deny() {
  local reason="$1"
  if command -v jq &>/dev/null; then
    echo "{\"reason\":$(echo "$reason" | jq -Rs .)}"
  else
    # Minimal JSON escape: backslash, double-quote, newline
    local escaped="${reason//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    escaped="${escaped//$'\n'/\\n}"
    printf '{"reason":"%s"}\n' "$escaped"
  fi
  exit 2
}

# Normalize path (resolve symlinks, 8.3 names, Windows backslashes)
normalize_path() {
  local path="$1"
  # Step 1: Convert Windows backslashes to forward slashes
  path="${path//\\//}"
  # Step 2: Resolve symlinks and canonical path
  if command -v realpath &>/dev/null; then
    realpath -m "$path" 2>/dev/null || echo "$path"
  elif command -v readlink &>/dev/null; then
    readlink -f "$path" 2>/dev/null || echo "$path"
  else
    echo "$path"
  fi
}

# Unicode NFKC normalization (requires Node.js)
# fail-close: if node is unavailable, deny (security-critical normalization)
nfkc_normalize() {
  local input="$1"
  local caller="${2:-unknown}"
  if command -v node &>/dev/null; then
    node -e "process.stdout.write(process.argv[1].normalize('NFKC'))" "$input"
  else
    # fail-close: cannot normalize = cannot guarantee safety
    deny "NFKC normalization unavailable (Node.js not found). Required by ${caller}."
  fi
}

# Compute SHA-256 hash
sha256() {
  if command -v sha256sum &>/dev/null; then
    echo -n "$1" | sha256sum | cut -d' ' -f1
  elif command -v shasum &>/dev/null; then
    echo -n "$1" | shasum -a 256 | cut -d' ' -f1
  fi
}
