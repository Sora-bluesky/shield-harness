<div align="center">

# Shield Harness

**Claude Code の全操作を自動防御するセキュリティハーネス**

> 承認ダイアログなしで安全な自律開発を実現

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](README.md)
[![日本語](https://img.shields.io/badge/lang-日本語-red?style=flat-square)](#)

</div>

## Shield Harness とは

Claude Code の全操作を自動防御するセキュリティハーネス。
承認ダイアログなしで安全な自律開発を実現します。`.claude/` ディレクトリに展開される hooks + rules + permissions による多層防御でエージェントを統制します。

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

| 層       | 防御                   | 実装                                                          |
| -------- | ---------------------- | ------------------------------------------------------------- |
| Layer 1  | 権限制御               | `settings.json` の deny/allow ルール                          |
| Layer 2  | フック防御             | 22 の Node.js フックスクリプト                                |
| Layer 3  | サンドボックス         | Claude Code ネイティブサンドボックス（bubblewrap / Seatbelt） |
| Layer 3b | コンテナサンドボックス | NVIDIA OpenShell（オプション、Docker 環境）                   |

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

| STG0 | STG1 | STG2 | STG3 | STG4 |   STG5   |   STG6    |
| :--: | :--: | :--: | :--: | :--: | :------: | :-------: |
| 要件 | 設計 | 実装 | 検証 |  CI  | コミット | PR/マージ |

## Layer 3: サンドボックス（OS レベル隔離）

Layer 3 は Claude Code 組み込みのサンドボックスに依存します。Shield Harness は独自のサンドボックスを実装せず、サンドボックスが利用できない環境では Layer 1・2 で補填します。

### プラットフォーム対応状況

| OS                 | サンドボックス | 技術               | 状態                                    |
| ------------------ | -------------- | ------------------ | --------------------------------------- |
| macOS              | 対応           | Seatbelt           | 自動有効化                              |
| Linux              | 対応           | bubblewrap + socat | `sudo apt-get install bubblewrap socat` |
| WSL2               | 対応           | bubblewrap + socat | Linux と同一                            |
| WSL1               | 非対応         | —                  | カーネル機能不足                        |
| Windows ネイティブ | 非対応         | —                  | Anthropic 側で対応予定                  |

### Windows ネイティブ: セキュリティギャップと補填策

Windows ネイティブでは Claude Code のサンドボックス機能（`sandbox.filesystem.*`、`sandbox.network.*`、`sandbox.autoAllow`）が動作しません。Shield Harness は以下で補填します:

- **Layer 1**: `permissions.deny` に Windows 固有コマンド（`type`、`del`、`format`、`Invoke-WebRequest`）を追加
- **Layer 2**: 22 フック全てが正常動作 — インジェクション検出、証跡記録、ゲートチェックは完全に機能
- **制約**: 子プロセスのファイルアクセスを OS レベルで制限できず、raw ソケット通信はコマンドパターンマッチをバイパス可能

エンタープライズ環境では Windows Firewall の送信規則によるプロセスレベルのネットワーク制御を推奨します。

### Layer 3b: NVIDIA OpenShell（オプション）

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)（Apache 2.0）は Docker 上で AI エージェントに**カーネルレベルの隔離**を提供します:

| メカニズム   | 対象             | 保護内容                |
| ------------ | ---------------- | ----------------------- |
| Landlock LSM | ファイルシステム | denyWrite / denyRead    |
| Seccomp BPF  | システムコール   | ソケット / プロセス制限 |
| Network NS   | ネットワーク     | ドメインレベルの deny   |

Windows ユーザーにとっての主なメリット:

- ポリシーがエージェントプロセスの**外部**に存在 — エージェント自身がガードレールを無効化できない
- Docker Desktop + WSL2 バックエンド（一般的な Windows 開発環境）で動作
- 残余リスクを 5% から 1% 未満に低減
- 自由に取り外し可能 — コンテナを停止すれば Shield Harness は Layer 1-2 にフォールバック

> **注意**: OpenShell は Alpha（v0.0.13）— API は将来変更の可能性があります。

## チャンネル連携

Claude Code Channels (Telegram/Discord) との連携をサポート。
チャンネル経由のメッセージには自動的に severity boost が適用されます。

## システム要件

| ツール       | バージョン   | 用途                     | 必須/任意      |
| ------------ | ------------ | ------------------------ | -------------- |
| Git          | 2.x          | バージョン管理           | 必須           |
| Git Bash     | (Git 同梱)   | フックスクリプト実行環境 | 必須 (Windows) |
| Node.js      | 18+          | フック実行 + NFKC 正規化 | 必須           |
| PowerShell 7 | 7.x (`pwsh`) | sync スクリプト          | 推奨           |
| GitHub CLI   | 2.x (`gh`)   | PR 作成・マージ自動化    | 任意           |

OS: Windows ネイティブファースト（Git Bash 環境）、WSL2/Linux 互換。

## バージョニング

Shield Harness は [Semantic Versioning](https://semver.org/) に準拠します:

| バンプ  | 条件                                             | 例                                          |
| ------- | ------------------------------------------------ | ------------------------------------------- |
| `patch` | バグ修正、パターン更新、ドキュメント修正         | injection-patterns.json 更新                |
| `minor` | 新機能（後方互換）、Phase 内 must タスク全完了時 | OCSF 対応、新フック追加、CLI オプション追加 |
| `major` | 破壊的変更                                       | スキーマ非互換変更、settings 構造変更       |

**リリーストリガー**: `git tag v1.x.x && git push origin v1.x.x` で `release.yml` が自動実行（npm publish + GitHub Release）。セキュリティ修正は即座に patch リリース。

## 参考プロジェクト

Shield Harness は 40 以上の Claude Code セキュリティプロジェクトを調査して設計されました。主な参考:

| プロジェクト                                                                 | 影響を受けた点                                                                                                       |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| [claude-guardrails](https://github.com/dwarvesf/claude-guardrails)           | npx install パターン、50+ インジェクションパターン、deny ルールカタログ                                              |
| [claude-warden](https://github.com/johnzfitch/claude-warden)                 | 3 段階プロファイル、トークンガバナンス（quiet-inject、output-control）、ConfigChange 自己保護                        |
| [claude-hooks](https://github.com/lasso-security/claude-hooks)               | 5 カテゴリインジェクション検出、YAML パターン定義                                                                    |
| [tobari](https://github.com/Sora-bluesky/tobari)                             | 22 フックアーキテクチャ、SHA-256 ハッシュチェーン証跡、STG ゲートパイプライン、PermissionRequest 適応学習            |
| [OpenClaw](https://github.com/openclaw/openclaw)                             | 18 件の CVE/セキュリティ問題からの教訓（ゲートウェイ認証、認証情報管理、シムリンクトラバーサル）、チャンネル連携設計 |
| [everything-claude-code](https://github.com/affaan-m/everything-claude-code) | AgentShield セキュリティ統合（1,282 テスト、102 ルール）、包括的スキル/エージェントカタログ                          |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)                      | Layer 3b カーネルレベルサンドボックス（Landlock、Seccomp BPF、Network NS）、宣言的 YAML ポリシー                     |

## ライセンス

MIT
