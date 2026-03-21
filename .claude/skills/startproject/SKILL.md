---
name: startproject
description: |
  このスキルは /tobari に統合されました。/tobari <feature> を使用してください。
  claude-code-orchestra 互換のエイリアスとして維持されています。
metadata:
  short-description: Redirects to /tobari
---

# /startproject -> /tobari リダイレクト

**このスキルは `/tobari` に統合されました。**

`/tobari $ARGUMENTS` を実行してください。

tobari スキル（`.claude/skills/tobari/SKILL.md`）の全ステップに従い、
STG0 儀式を実行します。

## 背景

- Claude Code 専用設計への移行により、外部 CLI 依存を廃止
- 旧 startproject は外部 CLI に依存していたが、
  帳アーキテクチャでは Claude Code のみで STG0 儀式を完結する

## 移行先

| 旧コマンド        | 新コマンド                    |
| ----------------- | ----------------------------- |
| `/startproject`   | `/tobari`（STG0 儀式）        |
| `/team-implement` | `/team-implement`（変更なし） |
| `/team-review`    | `/team-review`（変更なし）    |
