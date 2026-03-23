<div align="center">

# Shield Harness

**Claude Code のセキュリティハーネス — 苦労なし、フック駆動の防御**

> くろうレス — 苦労レス — 苦労しない

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](README.md)
[![日本語](https://img.shields.io/badge/lang-日本語-red?style=flat-square)](#)

</div>

## Shield Harness とは

Claude Code が安全・再現可能に開発を進めるためのハーネス。
`.claude/` ディレクトリに展開される hooks + rules + permissions + settings の多層防御でエージェントを統制します。

## クイックスタート

```bash
npx shield-harness init [--profile minimal|standard|strict]
```

## なぜ Shield Harness なのか

- **フック駆動の防御**: 22 のセキュリティフックが Claude Code の全操作を監視
- **承認レスモード**: hooks に全セキュリティ判定を委譲し、人間の承認ダイアログを排除
- **fail-close 原則**: 安全条件を確認できない場合は自動的に停止
- **証跡記録**: SHA-256 ハッシュチェーンで全 allow/deny 決定を改ざん不能な形で記録

## アーキテクチャ概要

3 層防御モデル:

| 層      | 防御           | 実装                                 |
| ------- | -------------- | ------------------------------------ |
| Layer 1 | 権限制御       | `settings.json` の deny/allow ルール |
| Layer 2 | フック防御     | 22 の Node.js フックスクリプト       |
| Layer 3 | サンドボックス | OS レベルのプロセス隔離              |

## プロファイル

| プロファイル | 説明     | 承認レス | 用途                         |
| ------------ | -------- | -------- | ---------------------------- |
| **minimal**  | 最小構成 | 有効     | 低リスクタスク               |
| **standard** | 推奨構成 | 有効     | 通常の開発                   |
| **strict**   | 厳格構成 | 無効     | セキュリティ監査が必要な場合 |

## フックカタログ

| #   | フック           | イベント              | 責務                                          |
| --- | ---------------- | --------------------- | --------------------------------------------- |
| 1   | permission       | PreToolUse            | ツール使用の 4 カテゴリ分類                   |
| 2   | gate             | PreToolUse            | Bash コマンドの 7 攻撃ベクトル検査            |
| 3   | injection-guard  | PreToolUse            | 9 カテゴリ 50+ パターンのインジェクション検出 |
| 4   | data-boundary    | PreToolUse            | 本番データ境界 + 管轄追跡                     |
| 5   | quiet-inject     | PreToolUse            | quiet フラグ自動注入                          |
| 6   | evidence         | PostToolUse           | SHA-256 ハッシュチェーン証跡                  |
| 7   | output-control   | PostToolUse           | 出力トランケーション + トークン予算           |
| 8   | dep-audit        | PostToolUse           | パッケージインストール検出                    |
| 9   | lint-on-save     | PostToolUse           | 自動 lint 実行                                |
| 10  | session-start    | SessionStart          | セッション初期化 + 整合性ベースライン         |
| 11  | session-end      | SessionEnd            | クリーンアップ + 統計                         |
| 12  | circuit-breaker  | Stop                  | リトライ上限 (3 回)                           |
| 13  | config-guard     | ConfigChange          | 設定変更の監視                                |
| 14  | user-prompt      | UserPromptSubmit      | ユーザー入力のインジェクション検査            |
| 15  | permission-learn | PermissionRequest     | 権限学習ガード                                |
| 16  | elicitation      | Elicitation           | フィッシング + スコープガード                 |
| 17  | subagent         | SubagentStart         | サブエージェント予算制約 (25%)                |
| 18  | instructions     | InstructionsLoaded    | ルールファイル整合性監視                      |
| 19  | precompact       | PreCompact            | コンパクション前バックアップ                  |
| 20  | postcompact      | PostCompact           | コンパクション後復元 + 検証                   |
| 21  | worktree         | WorktreeCreate/Remove | セキュリティ伝播 + 証跡マージ                 |
| 22  | task-gate        | TaskCompleted         | テストゲート                                  |

## パイプライン

STG ゲート駆動の自動化パイプライン:

```
STG0 → STG1 → STG2 → STG3 → STG4 → STG5 → STG6
要件    設計    実装    検証    CI     コミット  PR/マージ
```

## チャンネル連携

Claude Code Channels (Telegram/Discord) との連携をサポート。
チャンネル経由のメッセージには自動的に severity boost が適用されます。

## システム要件

| ツール       | バージョン   | 用途                     | 必須/任意      |
| ------------ | ------------ | ------------------------ | -------------- |
| Git          | 2.x          | バージョン管理           | 必須           |
| Git Bash     | (Git 同梱)   | フックスクリプト実行環境 | 必須 (Windows) |
| Node.js      | 18+          | フック実行 + NFKC 正規化 | 必須           |
| jq           | 1.6+         | フック内 JSON 処理       | 必須           |
| yq           | v4+ (Go版)   | backlog.yaml 操作        | 必須           |
| PowerShell 7 | 7.x (`pwsh`) | sync スクリプト          | 推奨           |
| GitHub CLI   | 2.x (`gh`)   | PR 作成・マージ自動化    | 任意           |

OS: Windows ネイティブファースト（Git Bash 環境）、WSL2/Linux 互換。

## ライセンス

MIT
