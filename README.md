# Clawless

> くろうレス — 苦労レス — 苦労しない

Claude Code が安全・再現可能に開発を進めるためのハーネス。
`.claude/` ディレクトリに展開される hooks + rules + skills + settings の総体。

## システム要件

| ツール       | バージョン   | 用途                                 | 必須/任意      |
| ------------ | ------------ | ------------------------------------ | -------------- |
| Git          | 2.x          | バージョン管理                       | 必須           |
| Git Bash     | (Git 同梱)   | フックスクリプト実行環境             | 必須 (Windows) |
| jq           | 1.6+         | フック内 JSON 処理                   | 必須           |
| yq           | v4+ (Go版)   | backlog.yaml 操作                    | 必須           |
| Node.js      | 18+          | NFKC 正規化 (不在時は fail-close)    | 必須           |
| PowerShell 7 | 7.x (`pwsh`) | sync スクリプト (bash fallback あり) | 推奨           |
| GitHub CLI   | 2.x (`gh`)   | PR 作成・マージ自動化                | 任意           |

OS: Windows ネイティブファースト（Git Bash 環境）、WSL2/Linux 互換。

## セットアップ

```bash
npx clawless init [--profile minimal|standard|strict]
```

## ディレクトリ構成（リポジトリ初期化後の目標）

```
clawless/
├── .claude/              ← Claude Code 設定（hooks, rules, skills, settings）
├── .clawless/            ← Clawless ランタイム（証跡, セッション, パターン）
├── .reference/           ← 設計参照資料（.gitignore 対象）
├── src/                  ← ソースコード
├── tests/                ← テスト
├── CLAUDE.md             ← 最上位ルール（28 項目）
├── HANDOFF.md            ← プロジェクト定義
├── ARCHITECTURE.md       ← 設計判断記録
├── .gitignore
└── package.json
```

## 設計参照資料

`.reference/` に格納。Git 対象外。Claude Code が設計判断に迷った際に参照する。

- `CLAWLESS_ADR_REDESIGN_PROPOSAL.md` — ADR 再設計提案 v5.1（29 ADR）
- `research/` — 調査レポート 5 本（OSS 比較, フック回避攻撃, Changelog 分析, OpenClaw 教訓, Windows サンドボックス）

## ライセンス

MIT
