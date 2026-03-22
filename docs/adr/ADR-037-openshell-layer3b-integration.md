# ADR-037: OpenShell Integration — Kernel-Level Sandbox for Defense Layer 3b

- **Status**: Accepted
- **Date**: 2026-03-22
- **Deciders**: Project owner (Sora) + Claude Code
- **Related ADRs**: ADR-012 (3-layer defense model), ADR-027 (hook bypass defense)

---

## Context

### Problem: Defense Layer 3 Gap on Windows Native

Clawless adopts a 3-layer defense model (ADR-012):

| Layer | Name                    | Scope             |
| ----- | ----------------------- | ----------------- |
| 1     | Claude Code Permissions | All OS            |
| 2     | Hook Chain (22 hooks)   | All OS            |
| 3     | OS Sandbox (bubblewrap) | WSL2 / Linux only |

On Windows native — the project's primary development environment — Layer 3 is unavailable. THREAT_MODEL.md §7.2 documents the resulting residual risks:

- Child process file access via piped chains / obfuscation
- Raw socket communication from Bash
- DNS tunneling for data exfiltration
- PowerShell socket operations (`[System.Net.Sockets.TcpClient]`)

The design principle (NFR-02-03) states: "Hooks cover 95% of attack vectors; the remaining 5% is documented as residual risk."

### Root Cause: In-Process Enforcement Limitation

Clawless hooks operate within Claude Code's hook engine. They inspect tool call inputs but **cannot control child process behavior at the OS level**. Once a Bash command passes Layer 1-2 checks, the spawned process has unrestricted filesystem and network access on Windows native.

### Opportunity: NVIDIA OpenShell

NVIDIA OpenShell (Apache 2.0, Alpha, released at GTC 2026-03-16) provides **out-of-process, kernel-level isolation** for AI agents:

| Mechanism         | Target         | Mutability                 |
| ----------------- | -------------- | -------------------------- |
| Landlock LSM      | Filesystem     | Locked at sandbox creation |
| Seccomp BPF       | System calls   | Locked at sandbox creation |
| Network Namespace | Network access | Hot-reloadable at runtime  |

Key properties:

- Policies exist **outside** the agent process — the agent cannot disable its own guardrails
- Claude Code is officially supported as a target agent
- Runs on Docker (Linux / macOS / WSL2 on Windows)
- Declarative YAML policy files

### Decision Drivers

1. The 5% residual risk on Windows native is a documented, acknowledged gap
2. OpenShell addresses this gap without requiring Clawless to implement OS-level isolation (out of scope per REQUIREMENTS.md §1.4)
3. OpenShell is complementary to hooks — different enforcement layers, not competing implementations
4. Docker Desktop + WSL2 backend is the typical Windows developer setup

---

## Decision

### D1: OpenShell as Defense Layer 3b (Optional Enhancement)

```
Layer 1: Claude Code Permissions (settings.json)  — All OS (unchanged)
Layer 2: Hook Chain (22 hooks)                     — All OS (unchanged)
Layer 3: Claude Code Native Sandbox (bubblewrap)   — WSL2/Linux (unchanged)
Layer 3b: OpenShell Container Sandbox              — Docker environments (new, optional)
```

OpenShell is a **complement** to Layer 3, not a replacement. Rationale:

- Native API first principle (ADR-018): bubblewrap is preferred where available
- OpenShell requires Docker — heavier than bubblewrap
- OpenShell's primary value is on Windows native where bubblewrap is unavailable

### D2: 95% Defense Baseline Is Unchanged

The sandbox-independent design principle (ADR-012) is preserved. Layer 1-2 alone provide 95% coverage. OpenShell is an additional safety margin, not a required dependency.

### D3: Phased Integration (Alpha → Beta → GA)

| Phase | Trigger               | Scope                                           |
| ----- | --------------------- | ----------------------------------------------- |
| Alpha | Now (OpenShell Alpha) | ADR + documentation updates only. No code.      |
| Beta  | OpenShell Beta stable | Detection module, policy templates, README      |
| GA    | OpenShell GA          | Config guard, evidence integration, drift check |

### D4: Dual Defense (deny Rules + Kernel Policy)

Clawless deny rules (Layer 1) and OpenShell kernel policies (Layer 3b) cover the **same protected resources** — creating defense-in-depth. Even if an attack bypasses Layer 1-2, OpenShell's kernel-level constraints catch it.

### D5: Freely Removable

OpenShell can be removed at any time:

- Stop the Docker container → Layer 3b automatically deactivates
- Clawless detects "OpenShell not found" → falls back to Layer 1-2 only
- No Clawless configuration changes needed

---

## Layer 3b Activation Logic

```
SessionStart
  │
  ├─ Is Docker available?
  │   No → Layer 3b = unavailable (no impact)
  │
  ├─ Is OpenShell CLI installed?
  │   No → Layer 3b = unavailable (no impact)
  │
  ├─ Is OpenShell container running?
  │   No → Layer 3b = unavailable (notify user)
  │
  └─ All checks pass
      → Layer 3b = active
      → Record in session.json
      → Notify via additionalContext
```

Detection runs **only at SessionStart** (not per tool call) to avoid performance impact. Result is cached in `session.json`.

---

## Residual Risk Reduction

| Residual Risk (§7.2)      | Current Defense         | With OpenShell (Layer 3b)       |
| ------------------------- | ----------------------- | ------------------------------- |
| Child process file access | Pattern matching        | Landlock LSM denyWrite/denyRead |
| Raw socket communication  | Firewall recommendation | Seccomp BPF socket deny         |
| DNS tunneling             | sandbox.network (WSL2)  | Network Namespace deny all      |
| PowerShell sockets        | Pattern matching        | Seccomp BPF + Network Namespace |

With OpenShell active: theoretical coverage improves from 95% to 99%+.

---

## Alternatives Considered

| Alternative                      | Decision | Reason                                                              |
| -------------------------------- | -------- | ------------------------------------------------------------------- |
| Replace Layer 3 with OpenShell   | Rejected | Violates native API first principle (ADR-018)                       |
| Implement custom Windows sandbox | Rejected | Kernel-level isolation is out of Clawless scope (REQUIREMENTS §1.4) |
| Ignore OpenShell                 | Rejected | Misses opportunity to reduce documented 5% residual risk            |
| Make OpenShell mandatory         | Rejected | Adds Docker dependency; conflicts with lightweight harness goal     |

---

## Risks and Mitigations

| Risk                        | Likelihood | Impact | Mitigation                                                              |
| --------------------------- | ---------- | ------ | ----------------------------------------------------------------------- |
| OpenShell project abandoned | Low        | None   | Layer 3b is optional; removal has zero impact on Clawless functionality |
| OpenShell API instability   | High       | Low    | Phase Alpha is docs-only; code integration deferred to Beta             |
| Docker dependency burden    | Medium     | Low    | Entirely optional; non-Docker environments unaffected                   |
| False sense of security     | Low        | Medium | Document that OpenShell is Alpha; maintain 95% baseline messaging       |

---

## Consequences

### Positive

- Addresses the documented 5% residual risk on Windows native
- Out-of-process enforcement — structurally impossible for agent to bypass
- No changes to existing hooks, permissions, or patterns
- Freely removable without any impact

### Negative

- Adds conceptual complexity (Layer 3 vs 3b distinction)
- OpenShell is Alpha — production readiness uncertain
- Docker requirement for full benefit on Windows

### Neutral

- Layer 1-2 defense design and 95% coverage target unchanged
- Phase Alpha is documentation-only — no runtime dependencies added
