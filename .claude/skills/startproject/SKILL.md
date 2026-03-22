---
name: startproject
description: プロジェクトの STG0（要件確認）を実行し、タスクを開始する。claude-code-orchestra 互換エイリアス。
---

# /startproject — STG0 ワークフロー開始

プロジェクトの STG0（要件確認）ゲートを通過し、タスクを開始する。

`$ARGUMENTS` をタスクの意図として受け取り、以下を実行します:

1. `tasks/backlog.yaml` から該当タスクを特定
2. 受入基準（DoD）を確認
3. STG0 ゲートを通過

## 移行先

| 旧コマンド        | 新コマンド                    |
| ----------------- | ----------------------------- |
| `/startproject`   | `/startproject`（STG0 儀式）  |
| `/team-implement` | `/team-implement`（変更なし） |
| `/team-review`    | `/team-review`（変更なし）    |
