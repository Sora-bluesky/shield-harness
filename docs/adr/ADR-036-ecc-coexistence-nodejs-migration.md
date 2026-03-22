# ADR-036: ECC Coexistence Architecture + Node.js Hook Migration

- **Status**: Accepted
- **Date**: 2026-03-22
- **Deciders**: Project owner (Sora) + Claude Code
- **Related ADRs**: ADR-014 (Governance Tier), ADR-031 (Pipeline), ADR-032 (Approval-free)

---

## Context

### Problem 1: ECC (everything-claude-code) Ecosystem

[everything-claude-code](https://github.com/affaan-m/everything-claude-code) (82K+ stars) has emerged as the de facto standard for Claude Code enhancement. It provides 116+ skills, 28 agents, 59+ commands, and a continuous-learning system. Clawless must define a clear coexistence strategy rather than competing with or ignoring ECC.

### Problem 2: Hook Language Fragmentation

The current DETAILED_DESIGN.md specifies all 22 hooks in bash + jq. This creates:

- **Windows compatibility issues**: `flock`, `grep -P`, path separators require constant workarounds
- **Maintenance burden**: bash string manipulation for JSON is fragile and hard to test
- **Divergence from ecosystem**: ECC has already unified all hooks to Node.js CommonJS
- **Redundant dependencies**: jq (JSON), yq (YAML) become unnecessary when Node.js handles both natively

### Decision Drivers

1. Windows-native-first constraint (Git Bash environment)
2. Millisecond response time requirement for hooks
3. ECC ecosystem alignment for future plugin interoperability
4. Testability (unit tests with standard frameworks like Jest/Vitest)

---

## Decision

### D1: ECC Coexistence — Selective Plugin Model

Clawless and ECC occupy **complementary, non-overlapping layers**:

| Layer | Owner | Components |
|-------|-------|------------|
| Security & Governance | **Clawless** | STG gates, evidence-ledger, injection-guard, fail-close hooks, deny-by-default permissions |
| Productivity & Skills | **ECC plugin** | 116+ skills, 28 agents, 59+ commands, continuous-learning |
| Rules | **Merged** | Clawless security rules + ECC coding rules (no conflict) |
| Hook Runtime | **Shared** | Both fire on same events; Clawless hooks execute **first** (security gate) |

**Plugin integration approach**:

- Import only the skills/agents/commands needed from ECC
- Maintain Clawless-specific `settings.json` and hook configuration
- ECC's `plugin.json` structure is used as-is for imported components
- No forking — reference ECC via npm package or git submodule

**Hook execution order**:

```
Event fires (e.g., PreToolUse)
  │
  ├─ 1. Clawless hooks (security gate)
  │     exit 2 → DENY (short-circuit, ECC hooks never fire)
  │     exit 0 → proceed
  │
  └─ 2. ECC hooks (productivity enhancement)
        Runs only if Clawless allows
```

This is enforced by hook registration order in `settings.json`. Clawless hooks are always listed before ECC hooks.

### D2: Node.js Hook Migration — Full Unification

**Scope**: All 22 hook scripts + clawless-utils + clawless-pipeline

**Runtime**: Node.js CommonJS (`.js` extension, `require()` syntax)

**Rationale for CommonJS over ESM**:

- Claude Code hook runner uses `child_process.execSync` / `spawn`
- CommonJS has zero startup overhead (no module resolution delay)
- ECC uses CommonJS — alignment for shared patterns
- No need for top-level await in hook scripts

### D3: Migration Strategy — Design Now, Implement in Phase C

The current bash+jq implementation (TASK-008) remains in production during Phase B. Node.js migration happens in Phase C (TASK-012 scope).

```
Phase B (current):
  ├─ ADR-036 design document (this ADR) ✓
  ├─ DETAILED_DESIGN.md §2 revision (Node.js spec)
  └─ Bash hooks continue to run

Phase C (implementation):
  ├─ clawless-utils.js (library rewrite)
  ├─ 22 hook scripts (.sh → .js)
  ├─ clawless-pipeline.js (TASK-008 redo)
  ├─ settings.json hook commands: bash → node
  ├─ Jest/Vitest test suite
  └─ System requirements update (jq/yq → optional)
```

---

## Node.js Hook Architecture

### File Structure (Phase C target)

```
.claude/hooks/
├─ clawless-permission.js
├─ clawless-permission-learn.js
├─ clawless-gate.js
├─ clawless-injection-guard.js
├─ clawless-user-prompt.js
├─ clawless-evidence.js
├─ clawless-output-control.js
├─ clawless-quiet-inject.js
├─ clawless-circuit-breaker.js
├─ clawless-task-gate.js
├─ clawless-precompact.js
├─ clawless-postcompact.js
├─ clawless-instructions.js
├─ clawless-session-start.js
├─ clawless-session-end.js
├─ clawless-config-guard.js
├─ clawless-subagent.js
├─ clawless-dependency-guard.js
├─ clawless-elicitation.js
├─ clawless-worktree.js
├─ clawless-data-boundary.js
├─ clawless-pipeline.js
└─ lib/
    └─ clawless-utils.js
```

### clawless-utils.js Core API

```javascript
// clawless-utils.js — Shared utilities for all Clawless hooks (Node.js)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CLAWLESS_DIR = '.clawless';
const EVIDENCE_FILE = path.join(CLAWLESS_DIR, 'logs', 'evidence-ledger.jsonl');
const SESSION_FILE = path.join(CLAWLESS_DIR, 'session.json');
const PATTERNS_FILE = path.join('.claude', 'patterns', 'injection-patterns.json');

/**
 * Read and parse hook input from stdin.
 * @returns {Object} Parsed hook input { hook_type, tool_name, tool_input, session_id, timestamp }
 */
function readHookInput() {
  const raw = fs.readFileSync('/dev/stdin', 'utf8');
  const input = JSON.parse(raw);
  return {
    raw,
    hookType: input.hook_type || '',
    toolName: input.tool_name || '',
    toolInput: input.tool_input || {},
    sessionId: input.session_id || '',
    timestamp: input.timestamp || '',
  };
}

/**
 * Output allow response and exit 0.
 * @param {string} [context] - Optional additionalContext message
 */
function allow(context) {
  if (context) {
    process.stdout.write(JSON.stringify({ additionalContext: context }));
  } else {
    process.stdout.write('{}');
  }
  process.exit(0);
}

/**
 * Output deny response and exit 2.
 * @param {string} reason - Denial reason (shown to agent)
 */
function deny(reason) {
  process.stdout.write(JSON.stringify({ reason }));
  process.exit(2);
}

/**
 * NFKC normalization (native Node.js — no external dependency).
 * @param {string} input - String to normalize
 * @returns {string} NFKC-normalized string
 */
function nfkcNormalize(input) {
  return input.normalize('NFKC');
}

/**
 * Compute SHA-256 hash.
 * @param {string} input - String to hash
 * @returns {string} Hex-encoded SHA-256 hash
 */
function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Normalize file path (resolve Windows backslashes, symlinks).
 * @param {string} filePath - Path to normalize
 * @returns {string} Normalized absolute path
 */
function normalizePath(filePath) {
  // Convert Windows backslashes
  const normalized = filePath.replace(/\\/g, '/');
  return path.resolve(normalized);
}

/**
 * Read session.json with fail-safe default.
 * @returns {Object} Session data or empty object
 */
function readSession() {
  try {
    return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
  } catch {
    return {};
  }
}

/**
 * Write session.json atomically (tmp + rename).
 * @param {Object} data - Session data to write
 */
function writeSession(data) {
  const tmp = `${SESSION_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, SESSION_FILE);
}

/**
 * Append evidence to ledger (JSONL format).
 * @param {Object} entry - Evidence entry
 */
function appendEvidence(entry) {
  const dir = path.dirname(EVIDENCE_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const line = JSON.stringify({
    ...entry,
    recorded_at: new Date().toISOString(),
  });
  fs.appendFileSync(EVIDENCE_FILE, line + '\n');
}

/**
 * Read YAML file using built-in JSON-compatible parsing.
 * For backlog.yaml: uses js-yaml (bundled) or falls back to simple parser.
 * @param {string} filePath - Path to YAML file
 * @returns {Object} Parsed YAML content
 */
function readYaml(filePath) {
  // Phase C: bundle js-yaml as dependency
  // For now, this is a design placeholder
  try {
    const yaml = require('js-yaml');
    return yaml.load(fs.readFileSync(filePath, 'utf8'));
  } catch {
    deny(`YAML parsing unavailable. Install js-yaml: npm install js-yaml`);
  }
}

module.exports = {
  CLAWLESS_DIR,
  EVIDENCE_FILE,
  SESSION_FILE,
  PATTERNS_FILE,
  readHookInput,
  allow,
  deny,
  nfkcNormalize,
  sha256,
  normalizePath,
  readSession,
  writeSession,
  appendEvidence,
  readYaml,
};
```

### Hook Script Template (Node.js)

```javascript
#!/usr/bin/env node
// clawless-{name}.js — {Description}
'use strict';

const { readHookInput, allow, deny } = require('./lib/clawless-utils');

// fail-close: wrap entire hook in try-catch
try {
  const input = readHookInput();

  // Hook-specific logic here
  // ...

  allow();
} catch (err) {
  // fail-close: any uncaught error = deny
  const reason = `Hook error (clawless-{name}): ${err.message}`;
  process.stdout.write(JSON.stringify({ reason }));
  process.exit(2);
}
```

### settings.json Hook Registration (Phase C)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|Read|WebFetch|MCP",
        "hooks": [
          {
            "type": "command",
            "command": "node .claude/hooks/clawless-permission.js"
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node .claude/hooks/clawless-gate.js"
          }
        ]
      }
    ]
  }
}
```

---

## ECC Plugin Integration Design

### plugin.json Structure

```json
{
  "name": "clawless-ecc-bridge",
  "version": "0.1.0",
  "description": "Selective ECC integration for Clawless",
  "components": {
    "skills": [],
    "agents": [],
    "commands": []
  },
  "hooks": {
    "note": "ECC hooks registered AFTER Clawless hooks in settings.json"
  }
}
```

### Import Criteria

ECC components are imported only when they meet ALL of:

1. **No security conflict**: Does not override or weaken Clawless deny rules
2. **No hook conflict**: Does not register on same event with conflicting logic
3. **Clear value-add**: Provides productivity benefit not covered by Clawless
4. **Maintainable**: Can be updated independently without breaking Clawless

### Phase D Scope (Future)

- Publish Clawless as npm package (`npx clawless init`)
- ECC bridge plugin for one-command integration
- Cursor / OpenCode / Windsurf editor support
- Community contribution guidelines for hook extensions

---

## Dependencies Eliminated by Migration

| Dependency | Current Role | Node.js Replacement | Status |
|------------|-------------|---------------------|--------|
| jq 1.6+ | JSON parsing in hooks | Native `JSON.parse()` | Eliminated |
| yq (Go) | YAML parsing in pipeline | `js-yaml` package | Eliminated |
| grep -P (PCRE) | Pattern matching | Native RegExp | Eliminated |
| flock | File locking | `fs.mkdirSync` lock pattern | Eliminated |
| realpath | Path resolution | `path.resolve()` | Eliminated |
| sha256sum | Hashing | `crypto.createHash()` | Eliminated |

**Remaining dependencies**:

| Dependency | Role | Required |
|------------|------|----------|
| Node.js 18+ | Hook runtime | Yes |
| pwsh (PowerShell 7) | Sync scripts | Yes (bash fallback) |
| gh (GitHub CLI) | PR automation | Optional |
| js-yaml | YAML parsing | Yes (npm install) |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Node.js not installed on target | Low | High | fail-close: settings.json hooks fail silently if node not found; `npx clawless init` checks prerequisites |
| ECC breaking changes | Medium | Medium | Pin ECC version; import components, not runtime |
| Performance regression (Node.js startup) | Low | Medium | Node.js CommonJS cold start ~30ms (within 50ms target); benchmark in Phase C |
| Migration introduces bugs | Medium | High | Phase C: migrate one hook at a time with A/B test against bash version |

---

## Consequences

### Positive

- Single language (JavaScript) for all hook logic
- Native Windows support without Git Bash workarounds
- Testable hooks (Jest/Vitest with mock stdin)
- ECC ecosystem alignment enables future plugin marketplace
- Reduced external dependency footprint

### Negative

- Phase C effort required to rewrite 22 hooks + utils
- Node.js becomes hard dependency (previously optional for NFKC only)
- js-yaml added as npm dependency for YAML operations

### Neutral

- Existing bash hooks remain operational until Phase C migration
- DETAILED_DESIGN.md §2 dual-spec period (bash current, Node.js target)
