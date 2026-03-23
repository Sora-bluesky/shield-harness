<div align="center">

# Shield Harness

**Auto-defense security harness for Claude Code — approval-free, safe autonomous development**

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](#)
[![日本語](https://img.shields.io/badge/lang-日本語-red?style=flat-square)](README.ja.md)

</div>

## What is Shield Harness

A security harness that governs Claude Code through multi-layered defense:
hooks + rules + permissions + settings deployed in the `.claude/` directory.

## Quick Start

```bash
npx shield-harness init [--profile minimal|standard|strict]
```

## Why Shield Harness

- **Hooks-driven defense**: 22 security hooks monitor every Claude Code operation
- **Approval-free mode**: Delegate all security decisions to hooks, eliminating human approval dialogs
- **fail-close principle**: Automatically stops when safety conditions cannot be verified
- **Evidence recording**: Tamper-proof SHA-256 hash chain records all allow/deny decisions

## Architecture Overview

3-layer defense model:

| Layer    | Defense            | Implementation                                     |
| -------- | ------------------ | -------------------------------------------------- |
| Layer 1  | Permission control | `settings.json` deny/allow rules                   |
| Layer 2  | Hook defense       | 22 Node.js hook scripts                            |
| Layer 3  | Sandbox            | Claude Code native sandbox (bubblewrap / Seatbelt) |
| Layer 3b | Container sandbox  | NVIDIA OpenShell (optional, Docker environments)   |

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

| STG0 |  STG1  | STG2 |  STG3  | STG4 |  STG5  |   STG6   |
| :--: | :----: | :--: | :----: | :--: | :----: | :------: |
| Reqs | Design | Impl | Verify |  CI  | Commit | PR/Merge |

## Layer 3: Sandbox (OS-Level Isolation)

Layer 3 relies on Claude Code's built-in sandbox. Shield Harness does not implement its own sandbox — it leverages Layers 1 & 2 to compensate when sandboxing is unavailable.

### Platform Support

| OS             | Sandbox       | Technology         | Status                                  |
| -------------- | ------------- | ------------------ | --------------------------------------- |
| macOS          | Supported     | Seatbelt           | Auto-enabled                            |
| Linux          | Supported     | bubblewrap + socat | `sudo apt-get install bubblewrap socat` |
| WSL2           | Supported     | bubblewrap + socat | Same as Linux                           |
| WSL1           | Not supported | —                  | Kernel features missing                 |
| Windows native | Not supported | —                  | Planned by Anthropic                    |

### Windows Native: Security Gap & Mitigation

On Windows native, Claude Code's sandbox features (`sandbox.filesystem.*`, `sandbox.network.*`, `sandbox.autoAllow`) do not function. Shield Harness compensates through:

- **Layer 1**: `permissions.deny` includes Windows-specific commands (`type`, `del`, `format`, `Invoke-WebRequest`)
- **Layer 2**: All 22 hooks operate normally — injection detection, evidence recording, and gate checks are fully functional
- **Limitation**: Child process file access cannot be restricted at the OS level; raw socket communication bypasses command pattern matching

For enterprise environments, supplementing with Windows Firewall outbound rules for process-level network control is recommended.

### Layer 3b: NVIDIA OpenShell (Optional)

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0) provides **kernel-level isolation** for AI agents via Docker:

| Mechanism    | Target     | Protection                |
| ------------ | ---------- | ------------------------- |
| Landlock LSM | Filesystem | denyWrite / denyRead      |
| Seccomp BPF  | Syscalls   | Socket / process restrict |
| Network NS   | Network    | Domain-level deny         |

Key benefits for Windows users:

- Policies exist **outside** the agent process — the agent cannot disable its own guardrails
- Runs on Docker Desktop + WSL2 backend (typical Windows dev setup)
- Reduces residual risk from 5% to <1%
- Freely removable — stop the container and Shield Harness falls back to Layer 1-2

> **Status**: Alpha integration (ADR-037). Detection + policy template + version tracking active. OpenShell is Alpha (v0.0.13) — APIs may change with future releases.

## Channel Integration

Supports Claude Code Channels (Telegram/Discord).
Channel-sourced messages automatically receive severity boost for enhanced security.

## System Requirements

| Tool         | Version            | Purpose                             | Required           |
| ------------ | ------------------ | ----------------------------------- | ------------------ |
| Git          | 2.x                | Version control                     | Required           |
| Git Bash     | (bundled with Git) | Hook script runtime                 | Required (Windows) |
| Node.js      | 18+                | Hook execution + NFKC normalization | Required           |
| PowerShell 7 | 7.x (`pwsh`)       | Sync scripts                        | Recommended        |
| GitHub CLI   | 2.x (`gh`)         | PR creation/merge automation        | Optional           |

OS: Windows-native first (Git Bash), WSL2/Linux compatible.

## References

Shield Harness was designed by surveying 40+ Claude Code security projects. Key references:

| Project                                                                      | Influence                                                                                                          |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| [claude-guardrails](https://github.com/dwarvesf/claude-guardrails)           | npx install pattern, 50+ injection patterns, deny rule catalog                                                     |
| [claude-warden](https://github.com/johnzfitch/claude-warden)                 | 3-tier profiles, token governance (quiet-inject, output-control), ConfigChange self-protection                     |
| [claude-hooks](https://github.com/lasso-security/claude-hooks)               | 5-category injection detection, YAML pattern definitions                                                           |
| [tobari](https://github.com/Sora-bluesky/tobari)                             | 22-hook architecture, SHA-256 hash chain evidence, STG gate pipeline, PermissionRequest adaptive learning          |
| [OpenClaw](https://github.com/openclaw/openclaw)                             | 18 CVE/security issue lessons (gateway auth, credential management, symlink traversal), channel integration design |
| [everything-claude-code](https://github.com/affaan-m/everything-claude-code) | AgentShield security integration (1,282 tests, 102 rules), comprehensive skill/agent catalog                       |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)                      | Layer 3b kernel-level sandbox (Landlock, Seccomp BPF, Network NS), declarative YAML policies                       |

## License

MIT
