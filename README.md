<div align="center">

# Shield Harness

**Hook-driven auto-defense security harness for Claude Code**

> **v0.5.0**: 22 hooks, 4-layer defense (L1 Permissions + L2 Hooks + L3 Sandbox + L3b OpenShell), 426 tests including 108 OWASP AITG attack simulations + 35 Auto Mode defense tests.

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
- **Automated security decisions**: Hooks handle all security judgments in real time — no manual approval bottleneck
- **fail-close principle**: Automatically stops when safety conditions cannot be verified
- **Evidence recording**: Tamper-proof SHA-256 hash chain records all allow/deny decisions

## Architecture Overview

4-layer defense model:

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

| #   | Hook             | Event                 | Responsibility                                                                       |
| --- | ---------------- | --------------------- | ------------------------------------------------------------------------------------ |
| 1   | permission       | PreToolUse            | 4-category tool usage classification                                                 |
| 2   | gate             | PreToolUse            | 7 attack vector inspection for Bash commands                                         |
| 3   | injection-guard  | PreToolUse            | 9-category 50+ pattern injection detection                                           |
| 4   | data-boundary    | PreToolUse            | Production data boundary + jurisdiction tracking                                     |
| 5   | quiet-inject     | PreToolUse            | Auto-inject quiet flags                                                              |
| 6   | evidence         | PostToolUse           | SHA-256 hash chain evidence                                                          |
| 7   | output-control   | PostToolUse           | Output truncation + token budget                                                     |
| 8   | dep-audit        | PostToolUse           | Package install detection                                                            |
| 9   | lint-on-save     | PostToolUse           | Auto lint execution                                                                  |
| 10  | session-start    | SessionStart          | Session init + integrity baseline                                                    |
| 11  | session-end      | SessionEnd            | Cleanup + statistics                                                                 |
| 12  | circuit-breaker  | Stop                  | Retry limit (3 attempts)                                                             |
| 13  | config-guard     | ConfigChange          | Settings change monitoring + OpenShell policy file protection + Auto Mode protection |
| 14  | user-prompt      | UserPromptSubmit      | User input injection scanning                                                        |
| 15  | permission-learn | PermissionRequest     | Permission learning guard                                                            |
| 16  | elicitation      | Elicitation           | Phishing + scope guard                                                               |
| 17  | subagent         | SubagentStart         | Subagent budget constraint (25%)                                                     |
| 18  | instructions     | InstructionsLoaded    | Rule file integrity monitoring                                                       |
| 19  | precompact       | PreCompact            | Pre-compaction backup                                                                |
| 20  | postcompact      | PostCompact           | Post-compaction restore + verify                                                     |
| 21  | worktree         | WorktreeCreate/Remove | Security propagation + evidence merge                                                |
| 22  | task-gate        | TaskCompleted         | Test gate                                                                            |

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

#### Why Layer 3b?

Layer 1 (permissions) and Layer 2 (hooks) inspect tool call inputs — the command text before execution. Once a command passes these checks, the **spawned child process runs freely at the OS level**.

```
Layer 1-2 (in-process):
  Claude Code → [Hook inspects input] → Command execution → [Child process is free]
                 ↑ Only controls this point

Layer 3b (out-of-process = kernel-level):
  Claude Code → Command execution → [Landlock: Filesystem access control]
                                     [Seccomp: Syscall control]
                                     [Network NS: Network isolation]
                ↑ Kernel controls ALL processes including children
```

| Attack Vector            | Layer 1-2 Defense           | Why It Bypasses                        | Layer 3b Defense                      |
| ------------------------ | --------------------------- | -------------------------------------- | ------------------------------------- |
| Pipe chain file access   | Pattern matching            | Indirect access via `awk`, `python -c` | Landlock LSM denies at kernel level   |
| Raw socket communication | `curl`/`wget` deny rules    | Direct socket via `python`/`node`      | Seccomp BPF blocks socket syscalls    |
| DNS tunneling            | sandbox.network (WSL2 only) | Data embedded in DNS queries           | Network Namespace isolates all DNS    |
| PowerShell sockets       | Pattern matching            | Encoding/obfuscation                   | Seccomp BPF + Network NS dual defense |

**Structural guarantee**: The agent **cannot** disable its own guardrails — policies exist outside the container and are locked at sandbox creation.

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0) provides **kernel-level isolation** for AI agents via Docker:

| Mechanism    | Target     | Protection                |
| ------------ | ---------- | ------------------------- |
| Landlock LSM | Filesystem | denyWrite / denyRead      |
| Seccomp BPF  | Syscalls   | Socket / process restrict |
| Network NS   | Network    | Domain-level deny         |

Key benefits for Windows users:

- Policies exist **outside** the agent process — the agent cannot disable its own guardrails
- Runs on Docker Desktop + WSL2 backend (typical Windows dev setup)
- Significantly reduces residual risk from Layer 1-2 pattern matching limitations
- Freely removable — stop the container and Shield Harness falls back to Layer 1-2

> **Note**: OpenShell is Alpha (v0.0.13) — APIs may change with future releases. Shield Harness GA Phase integration is complete (ADR-037): config guard policy file protection, policy drift check, and full documentation are ready.

#### Setup

**Prerequisites**: [Docker Desktop](https://www.docker.com/products/docker-desktop/) (WSL2 backend on Windows)

```bash
# 1. Install Docker Desktop and verify it is running
#    https://www.docker.com/products/docker-desktop/
docker --version

# 2. Install OpenShell CLI
pip install openshell

# 3. Generate policy from permissions-spec.json
#    Creates .claude/policies/openshell-generated.yaml
npx shield-harness policy generate

# 4. Start OpenShell container and run Claude Code inside it
#    Docker pulls the sandbox image automatically on first run
#    Kernel-level enforcement (Landlock/Seccomp/Network NS) is active inside the container
openshell run --policy .claude/policies/openshell-generated.yaml
```

Claude Code running inside the OpenShell container automatically receives Layer 3b kernel enforcement. Shield Harness detects this at session start (`sh-session-start.js`) — no additional configuration required.

Without OpenShell, Shield Harness falls back to Layer 1-2 defense (no degradation in hook protection).

Policy files are protected by:

- `permissions.deny`: `Edit/Write(.claude/policies/**)` blocks agent modification
- `sandbox.denyWrite`: `.claude/policies` in filesystem deny list
- `sh-config-guard.js`: Hash tracking detects policy file tampering or weakening
- `sh-session-start.js`: Drift check at session start verifies spec-policy alignment

## Testing

```bash
# Run all tests (426 tests including attack simulations)
npm test

# Run attack simulation tests only
node --test tests/attack-sim-*.test.js
```

| Test Suite                    | Category                               | Tests |
| ----------------------------- | -------------------------------------- | ----- |
| attack-sim-prompt-injection   | AITG-APP-01: Direct Prompt Injection   | 25    |
| attack-sim-indirect-injection | AITG-APP-02: Indirect Prompt Injection | 18    |
| attack-sim-data-leak          | AITG-APP-03: Sensitive Data Leak       | 20    |
| attack-sim-agentic-limits     | AITG-APP-06: Agentic Behavior Limits   | 18    |
| attack-sim-sandbox-escape     | NVIDIA 3-axis: Sandbox Escape          | 15    |
| attack-sim-defense-chain      | SAIF: Defense-in-depth Chain           | 12    |
| attack-sim-automode-bypass    | Auto Mode: soft_deny/soft_allow bypass | 15    |

## Auto Mode Awareness (v0.5.0)

Shield Harness detects Claude Code's Auto Mode (Research Preview) configuration at session start and protects against dangerous settings:

| Setting                | Risk                                                       | Shield Harness Response                                              |
| ---------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------- |
| `autoMode.soft_deny`   | **CRITICAL** — disables all classifier default protections | Config-guard blocks addition; session-start outputs CRITICAL warning |
| `autoMode.soft_allow`  | WARN — auto-approves specific tools                        | Config-guard blocks expansion; session-start outputs WARNING         |
| `autoMode.environment` | Safe — informational only                                  | Detected and recorded in session                                     |

All existing hooks (PreToolUse, PostToolUse) fire normally under Auto Mode — `permissions.deny` rules remain absolute. Auto Mode's classifier cannot override hook denials.

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

## Versioning

Shield Harness follows [Semantic Versioning](https://semver.org/):

| Bump    | Condition                                                      | Example                              |
| ------- | -------------------------------------------------------------- | ------------------------------------ |
| `patch` | Bug fixes, pattern updates, documentation fixes                | injection-patterns.json update       |
| `minor` | New features (backward compatible), Phase must-tasks completed | OCSF support, new hook, CLI option   |
| `major` | Breaking changes                                               | Schema incompatible, settings change |

**Release trigger**: `git tag vX.Y.Z && git push origin vX.Y.Z` triggers `release.yml` (automated npm publish + GitHub Release). Security fixes trigger an immediate patch release.

## References

Key references:

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
