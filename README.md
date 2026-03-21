# Clawless

> くろうレス — 苦労レス — 苦労しない

Claude Code が安全・再現可能に開発を進めるためのハーネス。
`.claude/` ディレクトリに展開される hooks + rules + skills + settings の総体。

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
