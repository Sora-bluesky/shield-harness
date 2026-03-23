# Shield Harness — Claude Code Security Harness

> Claude Code の .claude/ ディレクトリ構造によるセキュリティハーネス。hooks + rules + permissions + sandbox の多層防御でエージェントを統制する。

## Workflow

```
ADR-033 → backlog.yaml + sync-project-views (基盤)
ADR-031 → sh-pipeline.sh (STG ゲート駆動パイプライン)
ADR-032 → 承認レスモード
ADR-034 → 自律タスクループ
ADR-035 → バイリンガルドキュメント
```

## Key Gotchas

- `DETAILED_DESIGN.md` が各フックの唯一の実装仕様書 — §番号を参照して実装する
- `tasks/backlog.yaml` は SoT — エージェントの直接編集は deny ルールで禁止
- Hook スクリプトは pure bash + jq が基本 — 複雑ロジックのみ Node.js CommonJS

## Rules

@.claude/rules/binding-governance.md
@.claude/rules/coding-principles.md
@.claude/rules/security.md
@.claude/rules/dev-environment.md
@.claude/rules/language.md
@.claude/rules/testing.md
@.claude/rules/implementation-context.md

---

## Language Protocol

- **思考・コード**: 英語
- **ユーザー対話**: 日本語
