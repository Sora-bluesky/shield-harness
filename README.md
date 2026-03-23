<div align="center">

# Clawless

**Security harness for Claude Code — zero-hassle, hooks-driven defense**

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](#)
[![日本語](https://img.shields.io/badge/lang-日本語-red?style=flat-square)](README.ja.md)

</div>

## What is Clawless

A security harness that governs Claude Code through multi-layered defense:
hooks + rules + permissions + settings deployed in the `.claude/` directory.

## Quick Start

```bash
npx clawless init [--profile minimal|standard|strict]
```

## Why Clawless

- **Hooks-driven defense**: 22 security hooks monitor every Claude Code operation
- **Approval-free mode**: Delegate all security decisions to hooks, eliminating human approval dialogs
- **fail-close principle**: Automatically stops when safety conditions cannot be verified
- **Evidence recording**: Tamper-proof SHA-256 hash chain records all allow/deny decisions

## Architecture Overview

3-layer defense model:

| Layer   | Defense            | Implementation                   |
| ------- | ------------------ | -------------------------------- |
| Layer 1 | Permission control | `settings.json` deny/allow rules |
| Layer 2 | Hook defense       | 22 Node.js hook scripts          |
| Layer 3 | Sandbox            | OS-level process isolation       |

## Profiles

| Profile      | Description    | Approval-free | Use case                                    |
| ------------ | -------------- | ------------- | ------------------------------------------- |
| **minimal**  | Minimal config | Enabled       | Low-risk tasks                              |
| **standard** | Recommended    | Enabled       | Normal development                          |
| **strict**   | Strict config  | Disabled      | When security audit requires human approval |

## Hook Catalog

| #   | Hook             | Event                 | Responsibility                                   |
| --- | ---------------- | --------------------- | ------------------------------------------------ |
| 1   | permission       | PreToolUse            | 4-category tool usage classification             |
| 2   | gate             | PreToolUse            | 7 attack vector inspection for Bash commands     |
| 3   | injection-guard  | PreToolUse            | 9-category 50+ pattern injection detection       |
| 4   | data-boundary    | PreToolUse            | Production data boundary + jurisdiction tracking |
| 5   | quiet-inject     | PreToolUse            | Auto-inject quiet flags                          |
| 6   | evidence         | PostToolUse           | SHA-256 hash chain evidence                      |
| 7   | output-control   | PostToolUse           | Output truncation + token budget                 |
| 8   | dep-audit        | PostToolUse           | Package install detection                        |
| 9   | lint-on-save     | PostToolUse           | Auto lint execution                              |
| 10  | session-start    | SessionStart          | Session init + integrity baseline                |
| 11  | session-end      | SessionEnd            | Cleanup + statistics                             |
| 12  | circuit-breaker  | Stop                  | Retry limit (3 attempts)                         |
| 13  | config-guard     | ConfigChange          | Settings change monitoring                       |
| 14  | user-prompt      | UserPromptSubmit      | User input injection scanning                    |
| 15  | permission-learn | PermissionRequest     | Permission learning guard                        |
| 16  | elicitation      | Elicitation           | Phishing + scope guard                           |
| 17  | subagent         | SubagentStart         | Subagent budget constraint (25%)                 |
| 18  | instructions     | InstructionsLoaded    | Rule file integrity monitoring                   |
| 19  | precompact       | PreCompact            | Pre-compaction backup                            |
| 20  | postcompact      | PostCompact           | Post-compaction restore + verify                 |
| 21  | worktree         | WorktreeCreate/Remove | Security propagation + evidence merge            |
| 22  | task-gate        | TaskCompleted         | Test gate                                        |

## Pipeline

STG gate-driven automation pipeline:

```
STG0 → STG1 → STG2 → STG3 → STG4 → STG5 → STG6
Reqs    Design  Impl    Verify  CI     Commit   PR/Merge
```

## Channel Integration

Supports Claude Code Channels (Telegram/Discord).
Channel-sourced messages automatically receive severity boost for enhanced security.

## System Requirements

| Tool         | Version            | Purpose                             | Required           |
| ------------ | ------------------ | ----------------------------------- | ------------------ |
| Git          | 2.x                | Version control                     | Required           |
| Git Bash     | (bundled with Git) | Hook script runtime                 | Required (Windows) |
| Node.js      | 18+                | Hook execution + NFKC normalization | Required           |
| jq           | 1.6+               | JSON processing in hooks            | Required           |
| yq           | v4+ (Go)           | backlog.yaml operations             | Required           |
| PowerShell 7 | 7.x (`pwsh`)       | Sync scripts                        | Recommended        |
| GitHub CLI   | 2.x (`gh`)         | PR creation/merge automation        | Optional           |

OS: Windows-native first (Git Bash), WSL2/Linux compatible.

## License

MIT
