# Session Handoff — Clawless Project Status

Updated: 2026-03-22 (Session 3)

## Completed (this session — Session 3)

| Item | Deliverable | Notes |
|------|------------|-------|
| TASK-016: ADR-036 ECC共存 + Node.js移行 | docs/adr/ADR-036-ecc-coexistence-nodejs-migration.md | Hook共存モデル、Node.js移行スコープ、段階的移行計画 |
| DETAILED_DESIGN.md §2 改訂 | §2.2b, §2.3b 追加 | Node.js版 clawless-utils.js + fail-close template (Phase C target) |
| TASK-009: ADR-032 承認レスモード | §8.5 + channel-security.md + pipeline-config.json | approval_free: true に更新、ask→allow 昇格ロジック設計 |
| backlog.yaml 整合 | TASK-008→done, TASK-016追加, TASK-009→in_progress | Python経由で更新 |

## Completed (previous sessions)

| Item | PR | Commit | Notes |
|------|----|--------|-------|
| Permanent fix: git rm --cached | Applied | — | .gitignore cleaned, security.md rule added |
| README system requirements | — | — | jq, yq, Node.js, pwsh, gh table added |
| TASK-008 (ADR-031 pipeline) | #6 | 33f6238 | clawless-utils.sh + clawless-pipeline.sh (bash+jq) |
| ECC research | — | — | Analysis complete, coexistence strategy proposed |
| TASK-007 (ADR-033 backlog) | #1 | — | backlog.yaml + sync-project-views.ps1 |

## Key Decisions Made

1. **Hook language: Node.js unified** — bash+jq から Node.js CommonJS に移行（ADR-036）。Phase C で実装
2. **ECC coexistence: selective plugin** — Clawless = security first, ECC = productivity。Hook 実行順で Clawless が先行
3. **Approval-free mode: enabled** — approval_free: true。全セキュリティ判定を hooks に委譲（ADR-032）
4. **deny() jq fallback** — Node.js移行で不要になるため、現行 bash 版への追加は不要

## Pending / Not Yet Started

- TASK-009: STG3以降（テスト、コミット、PR）— 実装は stg2_passed まで完了
- TASK-011 (ADR-035 bilingual README)
- TASK-013 (release tags)
- TASK-014 (tobari removal) — backlog 登録済み
- TASK-015 (channel design) — backlog 登録済み
- GPT-5.3-Codex-Spark code review flow — mentioned by user, not yet designed

## Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| Phase A (ADR-033) | DONE | PR #1 merged |
| Phase B | IN PROGRESS | TASK-008 done, TASK-009 stg2, TASK-016 stg2 |
| Phase C | NOT STARTED | 22 hooks Node.js 実装 (ADR-036) |
| Phase D (new) | PROPOSED | ECC plugin publish, Cursor/OpenCode support |

## Architecture Impact: Node.js Migration (ADR-036)

The decision to unify on Node.js affects:
- All 22 hook scripts (DETAILED_DESIGN.md now has dual spec: §2.2a bash, §2.2b Node.js)
- clawless-utils.sh → clawless-utils.js (library rewrite)
- clawless-pipeline.sh → clawless-pipeline.js (TASK-008 redo in Phase C)
- System requirements: jq/yq become optional (Node.js handles JSON/YAML natively)
- Dependencies eliminated: jq, yq, grep -P, flock, realpath, sha256sum
- Dependencies added: js-yaml (npm)

## ECC Coexistence Summary

| Layer | Owner | Components |
|-------|-------|------------|
| Security & Governance | Clawless | STG gates, evidence-ledger, injection-guard, fail-close hooks, deny-by-default permissions |
| Productivity & Skills | ECC plugin | 116+ skills, 28 agents, 59+ commands, continuous-learning |
| Rules | Merged | Clawless security rules + ECC coding rules |
| Hook Runtime | Shared | Both fire on same events; Clawless hooks execute first (security gate) |

## Files Modified This Session

- docs/adr/ADR-036-ecc-coexistence-nodejs-migration.md — NEW
- docs/DETAILED_DESIGN.md — §2.2b, §2.3b (Node.js), §8.5 (approval-free) added
- .claude/rules/channel-security.md — NEW
- .clawless/config/pipeline-config.json — approval_free: true
- tasks/backlog.yaml — TASK-008→done, TASK-016 added, TASK-009→in_progress
- HANDOFF-SESSION.md — updated
