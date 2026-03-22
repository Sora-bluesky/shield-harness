# Clawless 基本設計書

作成日: 2026-03-21
階層: What（構造）
根拠: REQUIREMENTS.md（FR/NFR）、THREAT_MODEL.md、ADR 設計提案（35 ADR）

---

## 1. 本書の位置づけ

4 層ドキュメント階層における What（構造）層。REQUIREMENTS.md（何を守るか）と THREAT_MODEL.md（誰から守るか）の要件を、実装可能なコンポーネント構成とデータフローに落とし込む。

| 階層             | 資料                        | 問い               | 状態 |
| ---------------- | --------------------------- | ------------------ | ---- |
| Why（戦略）      | REQUIREMENTS.md             | 何を実現するか     | 完成 |
| Why（戦略）      | THREAT_MODEL.md             | 誰から守るか       | 完成 |
| **What（構造）** | **ARCHITECTURE.md（本書）** | **どう構成するか** | 本書 |
| What（構造）     | CLAUDE_MD_SPEC.md           | 28 ルールの実体    | 完成 |
| How（詳細）      | DETAILED_DESIGN.md          | 個々のフック仕様   | 後続 |
| Run（運用）      | 各種運用ドキュメント        | どう運用するか     | 後続 |

---

## 2. システム概観

Clawless は Claude Code の `.claude/` ディレクトリに展開される**セキュリティハーネス**である。独立プロセスではなく、Claude Code のネイティブフック機構に組み込まれることで、全ツール呼び出しを傍受・検査・制御する。

### 2.1 信頼境界

```
┌─ 信頼境界（Clawless が制御可能な範囲）────────────────────────────┐
│                                                                   │
│  Claude Code Runtime                                              │
│  ├─ Hooks Engine → Clawless フックスクリプト群                     │
│  ├─ Permissions Engine → settings.json deny/ask/allow              │
│  ├─ Sandbox Engine → OS 隔離（対応環境のみ）                       │
│  └─ Tools: Bash, Edit, Write, Read, WebFetch, MCP                 │
│                                                                   │
│  .claude/ ディレクトリ（Clawless マネージド）                       │
│  .clawless/ ディレクトリ（ランタイム状態）                          │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ ホスト OS      │  │ 外部ネットワーク   │  │ メッセージング API     │
│ ファイルシステム│  │ (制御外)           │  │ (Telegram/Discord/    │
│ (部分的制御)   │  │                    │  │  Telegram/Discord)    │
└──────────────┘  └──────────────────┘  └──────────────────────┘
  信頼境界の外側: Clawless はツール呼び出しを検査できるが、
  子プロセスの OS レベル動作は制御できない（Windows ネイティブ）
```

### 2.2 コンポーネント俯瞰

```
┌─────────────────────────────────────────────────────────────────────┐
│  VS Code Claude Code Extension Panel（唯一のユーザー IF）            │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────────┐
│  Claude Code Runtime                                                │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Hooks Engine（30+ フックイベント）                            │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Clawless Hook Scripts（.claude/hooks/clawless-*.sh）   │  │   │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │   │
│  │  │  │Permission│ │   Gate   │ │Injection │ │ Evidence │  │  │   │
│  │  │  │  Guard   │ │  Guard   │ │  Guard   │ │  Ledger  │  │  │   │
│  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │   │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │   │
│  │  │  │ Circuit  │ │  Output  │ │  Config  │ │ Session  │  │  │   │
│  │  │  │ Breaker  │ │ Control  │ │  Guard   │ │  Start   │  │  │   │
│  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Permissions   │  │   Sandbox    │  │    Tools                 │  │
│  │ deny/ask/allow│  │ (OS 依存)    │  │  Bash/Edit/Write/Read/…  │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼─────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
│  Host Filesystem   │ │  External Network  │ │  Channel Gateway   │
│  (保護対象 A-01〜03)│ │  (保護対象 A-06)   │ │  (保護対象 A-07)   │
└───────────────────┘ └───────────────────┘ └───────────────────┘
```

### 2.3 設計原則

| 原則                      | 説明                                                                                                   | 根拠               |
| ------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------ |
| サンドボックス非依存設計  | Defense Layer 1-2（permissions + hooks）だけで 95% の攻撃を防御する。OS サンドボックスはオプション強化 | ADR-012, C-01      |
| ネイティブ API ファースト | Claude Code の hooks / permissions / sandbox をそのまま使う。独自フック基盤は作らない                  | ADR-018            |
| 将来は今                  | Phase 1 で全 35 ADR を実装する。段階リリースは行わない（--channels Phase 2 を除く）                    | C-07               |
| fail-close                | 安全条件が満たされない場合は実行を停止する。フックの exit code 2 で deny                               | 全 ADR 共通        |
| 正直な限界記載            | 防げないものを明文化し、残存リスクをドキュメント化する                                                 | THREAT_MODEL.md §7 |

---

## 3. 防御アーキテクチャ

### 3.1 3 層防御モデル（Defense Layer）

Claude Code がツールを実行する際、3 層の防御を順に通過する。各層は独立しており、1 つの層が突破されても次の層で防御される。

```
ユーザー操作 / チャンネルメッセージ
        │
        ▼
┌─────────────────────────────────────────────┐
│ Defense Layer 1: Claude Code Permissions      │
│ (settings.json — Windows / WSL2 / Linux)      │
│                                               │
│  deny ルール群 → 静的ブロック                   │
│  ask ルール群  → ユーザー確認                   │
│  allow ルール群 → 自動許可                     │
│                                               │
│  評価順: deny → ask → allow                   │
│  deny にマッチ → 即座にブロック（フック未到達）   │
└────────────────────┬────────────────────────┘
                     │ deny を通過
                     ▼
┌─────────────────────────────────────────────┐
│ Defense Layer 2: PreToolUse フック群            │
│ (Windows / WSL2 / Linux)                       │
│                                               │
│  clawless-permission.sh  → 4 カテゴリ動的評価   │
│  clawless-gate.sh        → 破壊的コマンド検出   │
│  clawless-injection-guard.sh → インジェクション  │
│  clawless-data-boundary.sh → 本番データ境界     │
│  clawless-quiet-inject.sh  → quiet フラグ注入   │
│                                               │
│  exit 2 → deny                                │
│  exit 0 + updatedInput → 入力書換え後に許可     │
└────────────────────┬────────────────────────┘
                     │ 全フック通過
                     ▼
┌─────────────────────────────────────────────┐
│ Defense Layer 3: OS サンドボックス              │
│ (WSL2 / Linux のみ。Windows ネイティブは未対応) │
│                                               │
│  filesystem: denyWrite / denyRead              │
│  network: allowedDomains                       │
│                                               │
│  Windows ネイティブ → Layer 1-2 のみで防御      │
│  macOS → スコープ外（将来対応候補）              │
├─────────────────────────────────────────────┤
│ Defense Layer 3b: OpenShell（オプション）       │
│ (Docker 環境。ADR-037)                         │
│                                               │
│  Landlock LSM: ファイルシステム隔離             │
│  Seccomp BPF: システムコール制限               │
│  Network Namespace: ネットワーク隔離           │
│                                               │
│  エージェントプロセスの外側で強制               │
│  → エージェントによるガードレール無効化が不可能  │
│  ※ 未インストール時は自動スキップ（fail-safe）   │
└────────────────────┬────────────────────────┘
                     │
                     ▼
              ツール実行（Bash / Edit / Write / Read / …）
                     │
                     ▼
┌─────────────────────────────────────────────┐
│ PostToolUse フック群                           │
│  clawless-evidence.sh     → 証跡記録           │
│  clawless-output-control.sh → 出力トランケーション│
│  clawless-dep-audit.sh    → 依存パッケージ検査  │
└─────────────────────────────────────────────┘
```

### 3.2 防御番号体系

3 つの独立した番号体系が異なる観点で防御を分類する。混同を避けるため、明確に区別する。

| 体系            | 名前                 | 範囲 | 用途                                              |
| --------------- | -------------------- | ---- | ------------------------------------------------- |
| Defense Layer   | 防御層               | 1〜3 | ツール実行に対する物理的な防御の順序（ADR-012）   |
| Governance Tier | ガバナンス階層       | 1〜3 | Permission 評価の論理的な段階（ADR-014）          |
| Injection Stage | インジェクション段階 | 1〜4 | インジェクション検出のパイプライン段階（ADR-020） |

### 3.3 ガバナンスフレームワーク（Governance Tier）

Permission の評価は 3 段階で行われる。

| Tier   | 名前       | 実装                                              | 動作                                                                           |
| ------ | ---------- | ------------------------------------------------- | ------------------------------------------------------------------------------ |
| Tier 1 | 静的ルール | settings.json permissions                         | プロファイル（minimal/standard/strict）から生成。deny/ask/allow の固定ルール群 |
| Tier 2 | 動的評価   | clawless-permission.sh（PreToolUse）              | 4 カテゴリ分類（Read-only / Agent spawn / Execution / Write）による実行時判定  |
| Tier 3 | 適応学習   | clawless-permission-learn.sh（PermissionRequest） | ユーザーの "Yes, don't ask again" を学習し、settings.local.json に永続化       |

### 3.4 インジェクション防御パイプライン（Injection Stage）

4 段階のパイプラインで多層検出する。

| Stage   | タイミング               | 実装                        | 検出対象                                           |
| ------- | ------------------------ | --------------------------- | -------------------------------------------------- |
| Stage 1 | UserPromptSubmit         | clawless-user-prompt.sh     | ユーザー入力のバイパスパターン                     |
| Stage 2 | PreToolUse               | clawless-injection-guard.sh | 9 カテゴリ 50+ パターン（injection-patterns.json） |
| Stage 3 | PreToolUse (type: agent) | clawless-intent-audit       | 高リスク操作の意図検証（サブエージェント）         |
| Stage 4 | PostToolUse              | clawless-evidence.sh        | 出力のデータ漏洩パターン                           |

### 3.5 2 段階設計パターン（bash → additionalContext → エージェント）

フックスクリプトは bash で高速に実行される（command タイプ）が、一部の処理は Claude Code エージェント自身の能力が必要になる。これを解決するのが 2 段階設計パターン。

| Stage   | 実行者                                             | 速度   | 能力                                    |
| ------- | -------------------------------------------------- | ------ | --------------------------------------- |
| Stage 1 | bash + jq（フック内）                              | ミリ秒 | パターンマッチ、JSON 操作、ハッシュ計算 |
| Stage 2 | Claude Code エージェント（additionalContext 経由） | 秒単位 | WebFetch、推論、コード分析              |

適用箇所:

| 機能                          | Stage 1（bash）                         | Stage 2（additionalContext で注入）              |
| ----------------------------- | --------------------------------------- | ------------------------------------------------ |
| バージョンチェック（ADR-029） | バージョン差分を検知                    | WebFetch で changelog 取得、影響分析             |
| 意図検出（ADR-027）           | 高リスクコマンドを検出                  | agent タイプフックでサブエージェントが意図を検証 |
| 依存パッケージ警告（ADR-023） | install コマンドを検出 + npm audit 実行 | critical 脆弱性の詳細をエージェントに通知        |

bash フックから Claude Code のツール（WebFetch, Read 等）は直接呼べない。これは制約であり設計上の前提である（C-02）。

### 3.6 フック回避防御（7 攻撃ベクトル）

AI エージェントが制約を回避する 7 つの確認済み攻撃に対する防御設計。clawless-gate.sh を中心に実装。

| #   | 攻撃名                   | 防御コンポーネント                  | 防御手法                                                    |
| --- | ------------------------ | ----------------------------------- | ----------------------------------------------------------- |
| E-1 | ツールスイッチング       | clawless-gate.sh                    | sed -i, python -c, echo > 等のファイル操作を検出            |
| E-2 | パス難読化               | clawless-gate.sh                    | realpath 解決後に deny 照合。8.3 短縮名、NTFS Junction 対応 |
| E-3 | 動的リンカ直接実行       | permissions.deny + clawless-gate.sh | ld-linux, rundll32 パターンをブロック                       |
| E-4 | sed 危険修飾子           | clawless-gate.sh                    | e（実行）、w（書込）修飾子を検出                            |
| E-5 | 自己設定変更             | 3 重防御                            | permissions.deny + PreToolUse + ConfigChange                |
| E-6 | サンドボックス自己無効化 | permissions.deny + ConfigChange     | sandbox 設定変更をブロック                                  |
| E-7 | Unicode/ゼロ幅文字       | clawless-injection-guard.sh         | NFKC 正規化後にパターンマッチ                               |

防御カバレッジ目標: 7/7（100%）— NFR-02-04

---

## 4. コンポーネントカタログ

### 4.1 フックスクリプト群（.claude/hooks/）

全 22 スクリプト。各スクリプトは単一のセキュリティドメインを担当する（NFR-04-03）。

| #   | スクリプト                   | フックイベント                                                                | セキュリティドメイン                | 根拠 ADR         | 出自                  |
| --- | ---------------------------- | ----------------------------------------------------------------------------- | ----------------------------------- | ---------------- | --------------------- |
| 1   | clawless-permission.sh       | PreToolUse                                                                    | ツールガバナンス（4 カテゴリ分類）  | ADR-014          | warden + clawless     |
| 2   | clawless-permission-learn.sh | PermissionRequest                                                             | 適応的承認制御                      | ADR-019          | clawless              |
| 3   | clawless-gate.sh             | PreToolUse                                                                    | 破壊的コマンド + フック回避防御     | ADR-027          | guardrails            |
| 4   | clawless-injection-guard.sh  | PreToolUse                                                                    | インジェクション検出（9 カテゴリ）  | ADR-020          | guardrails + clawless |
| 5   | clawless-user-prompt.sh      | UserPromptSubmit                                                              | ユーザー入力インジェクション        | ADR-020          | clawless              |
| 6   | clawless-evidence.sh         | PostToolUse, PostToolUseFailure, ElicitationResult, TeammateIdle, StopFailure | 証跡記録（SHA-256 hash chain）      | ADR-013          | clawless              |
| 7   | clawless-output-control.sh   | PostToolUse                                                                   | 出力トランケーション + 予算追跡     | ADR-024          | warden                |
| 8   | clawless-quiet-inject.sh     | PreToolUse                                                                    | quiet フラグ自動注入                | ADR-024          | warden                |
| 9   | clawless-circuit-breaker.sh  | Stop                                                                          | リトライ上限管理                    | ADR-016          | clawless              |
| 10  | clawless-task-gate.sh        | TaskCompleted                                                                 | テスト通過ゲート                    | ADR-016          | clawless              |
| 11  | clawless-precompact.sh       | PreCompact                                                                    | コンテキストバックアップ            | ADR-015          | clawless              |
| 12  | clawless-postcompact.sh      | PostCompact                                                                   | 状態復元 + SHA-256 検証             | ADR-015          | clawless              |
| 13  | clawless-instructions.sh     | InstructionsLoaded                                                            | ルールファイル改竄検知              | ADR-015          | clawless              |
| 14  | clawless-session-start.sh    | SessionStart                                                                  | セッション初期化（モジュール分割）  | ADR-028, ADR-029 | clawless              |
| 15  | clawless-session-end.sh      | SessionEnd                                                                    | セッション終了 + 証跡ファイナライズ | ADR-018          | clawless              |
| 16  | clawless-config-guard.sh     | ConfigChange                                                                  | 設定変更監視 + 不正変更ブロック     | ADR-025          | warden                |
| 17  | clawless-subagent.sh         | SubagentStart                                                                 | スコープ + 予算注入                 | ADR-016          | clawless + warden     |
| 18  | clawless-dep-audit.sh        | PostToolUse                                                                   | 依存パッケージ検査                  | ADR-023          | Clawless 独自         |
| 19  | clawless-elicitation.sh      | Elicitation                                                                   | MCP Elicitation 検査                | ADR-015          | Clawless 独自         |
| 20  | clawless-worktree.sh         | WorktreeCreate, WorktreeRemove                                                | ワークツリー管理                    | ADR-018          | Clawless 独自         |
| 21  | clawless-data-boundary.sh    | PreToolUse                                                                    | 本番データ境界 + 法域追跡           | ADR-026, ADR-022 | Clawless 独自         |
| 22  | clawless-pipeline.sh         | TaskCompleted                                                                 | STG ゲート駆動パイプライン          | ADR-031          | Clawless 独自         |

### 4.2 SessionStart モジュール群（.claude/hooks/session-modules/）

clawless-session-start.sh は起動時間最適化のため、モジュールに分割する（NFR-04-04）。

| モジュール        | 責務                                                             | 根拠 ADR                  |
| ----------------- | ---------------------------------------------------------------- | ------------------------- |
| gate-check.sh     | CLAUDE.md SHA-256 検証、settings.json 整合性、必須ルール存在確認 | ADR-028                   |
| env-check.sh      | OS 検出、sandbox 利用可否、TTL チェック、トークン予算初期化      | ADR-012, ADR-024, ADR-026 |
| openclaw-check.sh | 認証設定、Keychain 連携、dmScope、フック回避防御の有効性確認     | ADR-028                   |
| version-check.sh  | Claude Code バージョン変化検知、機能プローブ（週 1 回）          | ADR-029                   |

### 4.3 パターンファイル群（.claude/patterns/）

| ファイル                | 形式 | 内容                                    | 根拠 ADR |
| ----------------------- | ---- | --------------------------------------- | -------- |
| injection-patterns.json | JSON | 9 カテゴリ 50+ インジェクションパターン | ADR-020  |

パターンのカテゴリ構成:

| カテゴリ                 | 出自               | severity | 検出対象                              |
| ------------------------ | ------------------ | -------- | ------------------------------------- |
| 1. instruction_override  | claude-guardrails  | high     | "ignore all previous instructions" 等 |
| 2. role_playing          | claude-guardrails  | high     | "you are now DAN" 等                  |
| 3. encoding_obfuscation  | claude-guardrails  | medium   | base64, Unicode エスケープ            |
| 4. context_manipulation  | claude-guardrails  | high     | 偽 System Message, [INST] タグ        |
| 5. instruction_smuggling | claude-guardrails  | medium   | HTML コメント内の命令                 |
| 6. cjk_encoding_attack   | clawless           | high     | CJK 全角文字による命令注入            |
| 7. zero_width_hidden     | clawless           | high     | ゼロ幅文字、ホモグリフ                |
| 8. ntfs_ads              | Clawless (Windows) | critical | NTFS 代替データストリーム             |
| 9. unc_path              | Clawless (Windows) | critical | UNC パスによる外部アクセス            |

### 4.4 設定ファイル群

| ファイル                    | 管理者                 | 役割                                                |
| --------------------------- | ---------------------- | --------------------------------------------------- |
| .claude/settings.json       | Clawless（マネージド） | permissions（deny/ask/allow）+ sandbox + hooks 登録 |
| .claude/settings.local.json | ユーザー（学習結果）   | PermissionRequest 経由の学習済み allow ルール       |
| CLAUDE.md                   | Clawless（マネージド） | 28 ルール + プロジェクト固有ルール                  |
| .claude/rules/\*.md         | Clawless / ユーザー    | 補助ルールファイル                                  |

### 4.5 ランタイム状態ファイル群

| ファイル                                | 形式  | 役割                                               | 永続性                       |
| --------------------------------------- | ----- | -------------------------------------------------- | ---------------------------- |
| .clawless/session.json                  | JSON  | セッション状態、トークン予算追跡、リトライカウンタ | セッション単位               |
| .clawless/logs/evidence-ledger.jsonl    | JSONL | append-only 証跡（SHA-256 hash chain）             | 永続（ローテーション 100MB） |
| .clawless/logs/instructions-hashes.json | JSON  | CLAUDE.md / rules のベースライン SHA-256           | 永続                         |
| .clawless/state/last-known-version.txt  | text  | Claude Code バージョン記録                         | 永続                         |
| .clawless/state/last-probe.txt          | text  | 最終プローブ日時                                   | 永続                         |
| .clawless/state/probe-result.json       | JSON  | 機能プローブ結果                                   | 永続                         |
| .clawless/state/health-report.json      | JSON  | 自己診断結果                                       | 永続                         |

### 4.6 証跡システム（Evidence Layer）

2 層構成で改竄検知と可視化を両立する。

| 層               | 名前               | 必須/任意 | 実装                                                  | 根拠 ADR |
| ---------------- | ------------------ | --------- | ----------------------------------------------------- | -------- |
| Evidence Layer 1 | SHA-256 hash chain | 必須      | clawless-evidence.sh → evidence-ledger.jsonl          | ADR-013  |
| Evidence Layer 2 | OTEL 統合          | 任意      | Docker Compose（Loki + Prometheus + Tempo + Grafana） | ADR-013  |

証跡エントリ構造:

```json
{
  "timestamp": "2026-03-21T10:00:00.000Z",
  "event": "PostToolUse",
  "tool": "Bash",
  "input_hash": "sha256:abc...",
  "output_hash": "sha256:def...",
  "decision": "allow",
  "hook": "clawless-evidence.sh",
  "prev_hash": "sha256:012...",
  "session_id": "sess-xxx"
}
```

---

## 5. チャンネルアーキテクチャ

### 5.1 Phase 1: OpenClaw 方式（Gateway + Bot API）

24/7 メッセージングアプリ連携を実現する。Claude Code の --channels が VS Code に対応するまでの橋渡し。

```
┌──────────────────────────────────────────────────┐
│  外部メッセージングプラットフォーム                    │
│  ┌────────┐ ┌────────┐                            │
│  │Telegram│ │Discord │                            │
│  └───┬────┘ └───┬────┘                            │
│      │ Webhook  │ Webhook                          │
└──────┼──────────┼──────────────────────────────────┘
       │          │
┌──────▼──────────▼──────────────────────────────────┐
│  Cloudflare Tunnel（HTTPS 強制）                    │
└──────────────────────┬────────────────────────────┘
                       │
┌──────────────────────▼────────────────────────────┐
│  Channel Gateway（Node.js HTTP サーバー）            │
│  127.0.0.1 バインド（loopback only）                 │
│                                                    │
│  ┌──────────────┐  ┌──────────────┐               │
│  │ 認証          │  │ Rate Limit    │               │
│  │ パスワード必須 │  │ 送信者ごと    │               │
│  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                        │
│  ┌──────▼─────────────────▼───────┐               │
│  │ sender allowlist 照合            │               │
│  │ → 許可された送信者のみ通過        │               │
│  └──────────────┬─────────────────┘               │
│                 │                                  │
│  ┌──────────────▼─────────────────┐               │
│  │ DM セッション分離                │               │
│  │ dmScope: per-channel-peer       │               │
│  └──────────────┬─────────────────┘               │
└─────────────────┼──────────────────────────────────┘
                  │
┌─────────────────▼──────────────────────────────────┐
│  Clawless フック群（全フック適用）                     │
│  → clawless-injection-guard.sh                      │
│  → clawless-user-prompt.sh                          │
│  → その他全フック                                    │
└─────────────────┬──────────────────────────────────┘
                  │
┌─────────────────▼──────────────────────────────────┐
│  Claude Code Runtime                                │
└────────────────────────────────────────────────────┘
```

### 5.2 Phase 2: --channels ネイティブ移行

ADR-029（自己進化）の SessionStart バージョンチェックが --channels の VS Code 対応を検知した時点で、`npx clawless channels migrate` による自動移行を提案する。

| 項目               | Phase 1（OpenClaw 方式） | Phase 2（--channels）                    |
| ------------------ | ------------------------ | ---------------------------------------- |
| メッセージ受信     | Webhook → Gateway        | --channels プッシュ                      |
| 送信者認証         | sender allowlist（独自） | sender allowlist + pairing（ネイティブ） |
| セッション分離     | Clawless dmScope 強制    | --channels セッション紐付け              |
| セキュリティフック | 全フック適用             | 全フック適用（変更なし）                 |

フックは Phase 1 / Phase 2 で完全互換。セキュリティモデルに断絶なし。

---

## 6. ディレクトリ構造

`npx clawless init --profile standard` が生成する完全なディレクトリ構造。

```
project-root/
├── CLAUDE.md                              ← 28 ルール + プロジェクト固有ルール
├── .claude/
│   ├── settings.json                      ← permissions + sandbox + hooks 登録
│   ├── settings.local.json                ← ユーザー学習済みルール（空で初期化）
│   ├── hooks/
│   │   ├── clawless-permission.sh         ← PreToolUse: ツールガバナンス
│   │   ├── clawless-permission-learn.sh   ← PermissionRequest: 適応学習
│   │   ├── clawless-gate.sh              ← PreToolUse: 破壊的コマンド + 回避防御
│   │   ├── clawless-injection-guard.sh   ← PreToolUse: インジェクション検出
│   │   ├── clawless-user-prompt.sh       ← UserPromptSubmit: 入力検査
│   │   ├── clawless-evidence.sh          ← PostToolUse/Failure: 証跡記録
│   │   ├── clawless-output-control.sh    ← PostToolUse: 出力トランケーション
│   │   ├── clawless-quiet-inject.sh      ← PreToolUse: quiet フラグ注入
│   │   ├── clawless-circuit-breaker.sh   ← Stop: リトライ上限
│   │   ├── clawless-task-gate.sh         ← TaskCompleted: テスト通過ゲート
│   │   ├── clawless-precompact.sh        ← PreCompact: コンテキスト保護
│   │   ├── clawless-postcompact.sh       ← PostCompact: 状態復元
│   │   ├── clawless-instructions.sh      ← InstructionsLoaded: 改竄検知
│   │   ├── clawless-session-start.sh     ← SessionStart: 初期化
│   │   ├── clawless-session-end.sh       ← SessionEnd: 終了処理
│   │   ├── clawless-config-guard.sh      ← ConfigChange: 設定保護
│   │   ├── clawless-subagent.sh          ← SubagentStart: 予算注入
│   │   ├── clawless-dep-audit.sh         ← PostToolUse: 依存パッケージ検査
│   │   ├── clawless-elicitation.sh       ← Elicitation: MCP 検査
│   │   ├── clawless-worktree.sh          ← WorktreeCreate/Remove
│   │   ├── clawless-data-boundary.sh     ← PreToolUse: 本番データ + 法域
│   │   ├── clawless-pipeline.sh          ← TaskCompleted: STG ゲート駆動パイプライン
│   │   ├── lib/
│   │   │   └── clawless-utils.sh         ← 共通ユーティリティ関数
│   │   └── session-modules/
│   │       ├── gate-check.sh             ← 設定整合性チェック
│   │       ├── env-check.sh              ← 環境チェック
│   │       ├── openclaw-check.sh         ← OpenClaw 教訓チェック
│   │       └── version-check.sh          ← バージョン + 機能プローブ
│   ├── patterns/
│   │   └── injection-patterns.json       ← 9 カテゴリ 50+ パターン
│   ├── rules/
│   │   ├── security.md                   ← セキュリティルール
│   │   ├── coding-principles.md          ← コーディング原則
│   │   └── channel-security.md           ← チャンネルセキュリティ
│   └── skills/
│       └── (Clawless 提供スキル)
├── .clawless/
│   ├── session.json                       ← セッション状態
│   ├── config/
│   │   ├── allowed-jurisdictions.json     ← 許可法域リスト
│   │   └── pipeline-config.json           ← パイプライン自動化設定（ADR-031〜034）
│   ├── logs/
│   │   ├── evidence-ledger.jsonl          ← 証跡（hash chain）
│   │   └── instructions-hashes.json       ← ルールファイル SHA-256
│   ├── state/
│   │   ├── last-known-version.txt         ← Claude Code バージョン
│   │   ├── last-probe.txt                 ← 最終プローブ日時
│   │   ├── probe-result.json              ← プローブ結果
│   │   ├── health-report.json             ← 自己診断結果
│   │   └── upgrade-history.jsonl          ← アップグレード履歴
│   ├── channel-plugins/                   ← Phase 1 チャンネルプラグイン
│   └── otel/                              ← OTEL 設定（オプション）
│       └── docker-compose.yml
├── tasks/
│   └── backlog.yaml                       ← プロジェクト状態 SoT（ADR-033）
├── scripts/
│   ├── sync-project-views.ps1             ← backlog.yaml → 4 .md 生成（ADR-033）
│   └── sync-readme.ps1                   ← README ドリフト検知（ADR-035）
└── docs/
    ├── REQUIREMENTS.md
    ├── THREAT_MODEL.md
    ├── ARCHITECTURE.md                    ← 本書
    ├── project/                           ← 自動生成 .md ビュー（ADR-033）
    │   ├── ROADMAP.md
    │   ├── WBS.md
    │   ├── GANTT.md
    │   └── MILESTONES.md
    └── diagrams/
```

---

## 7. データフロー

### 7.1 ツール実行フロー（正常系）

```
1. ユーザー操作（VS Code パネル）
   │
2. Claude Code がツール呼び出しを決定
   │
3. Defense Layer 1: permissions 評価
   │  deny マッチ → ブロック（フック未到達）
   │  ask マッチ  → ユーザー確認ダイアログ
   │  allow マッチ → 通過
   │
4. Defense Layer 2: PreToolUse フック群（順序実行）
   │  4a. clawless-permission.sh → 4 カテゴリ分類
   │  4b. clawless-gate.sh → 破壊的コマンド + 回避検出
   │  4c. clawless-injection-guard.sh → パターンマッチ
   │  4d. clawless-data-boundary.sh → 本番データ + 法域
   │  4e. clawless-quiet-inject.sh → quiet フラグ注入
   │  いずれかが exit 2 → deny
   │
5. Defense Layer 3: OS サンドボックス（対応環境のみ）
   │  filesystem / network 制限を適用
   │
6. ツール実行（Bash / Edit / Write / Read / …）
   │
7. PostToolUse フック群
   │  7a. clawless-evidence.sh → 証跡記録
   │  7b. clawless-output-control.sh → 出力サイズ制御
   │  7c. clawless-dep-audit.sh → install 検出時スキャン
   │
8. 結果を Claude Code に返却
```

### 7.2 セッションライフサイクル

```
SessionStart
├── gate-check.sh    → CLAUDE.md 整合性、必須設定確認
├── env-check.sh     → OS 検出、sandbox、TTL、予算初期化
├── openclaw-check.sh → 認証、Keychain、dmScope 確認
└── version-check.sh → バージョン変化、週次プローブ
    │
    ▼
通常運用ループ
├── UserPromptSubmit → clawless-user-prompt.sh
├── PreToolUse → permission / gate / injection / data-boundary / quiet
├── ツール実行
├── PostToolUse → evidence / output-control / dep-audit
├── PermissionRequest → clawless-permission-learn.sh（学習）
├── Stop → clawless-circuit-breaker.sh（リトライ管理）
├── TaskCompleted → clawless-task-gate.sh（テスト通過確認）
├── ConfigChange → clawless-config-guard.sh（設定保護）
├── Elicitation → clawless-elicitation.sh（MCP 検査）
└── PreCompact / PostCompact → バックアップ / 復元
    │
    ▼
SessionEnd
└── clawless-session-end.sh → 証跡ファイナライズ
```

---

## 8. OS 別動作マトリクス

| 機能                          | Windows ネイティブ     | WSL2               | Linux              | macOS             |
| ----------------------------- | ---------------------- | ------------------ | ------------------ | ----------------- |
| Defense Layer 1 (permissions) | 動作                   | 動作               | 動作               | スコープ外        |
| Defense Layer 2 (hooks)       | 動作                   | 動作               | 動作               | スコープ外        |
| Defense Layer 3 (sandbox)     | 未対応（planned）      | 動作（bubblewrap） | 動作（bubblewrap） | スコープ外        |
| Defense Layer 3b (OpenShell)  | Docker 利用時動作      | Docker 利用時動作  | Docker 利用時動作  | Docker 利用時動作 |
| NTFS ADS / Junction 検出      | 動作                   | N/A                | N/A                | N/A               |
| UNC パス検出                  | 動作                   | 動作               | N/A                | N/A               |
| bash 実行環境                 | Git Bash               | /bin/bash          | /bin/bash          | N/A               |
| Channel Gateway               | 動作                   | 動作               | 動作               | スコープ外        |
| OTEL 統合                     | 動作（Docker Desktop） | 動作               | 動作               | スコープ外        |

Windows ネイティブの残存リスク（Defense Layer 3 不在）:

| リスク                       | 緩和策                                                             | OpenShell 緩和（Layer 3b, ADR-037） |
| ---------------------------- | ------------------------------------------------------------------ | ----------------------------------- |
| 子プロセスのファイルアクセス | PreToolUse パターンマッチで大半を検出                              | Landlock LSM denyWrite / denyRead   |
| raw ソケット通信             | エンタープライズ: Windows Firewall 送信規則を推奨                  | Seccomp BPF socket deny             |
| DNS トンネリング             | sandbox.network のみ（WSL2/Linux）。Windows ネイティブでは検出困難 | Network Namespace deny_all_other    |
| PowerShell ソケット          | パターンマッチで既知パターンを検出                                 | Seccomp BPF + Network Namespace     |

---

## 9. CLI インターフェース

`npx clawless` が提供するコマンド群。

| コマンド                        | 機能                                                         | 根拠 ADR         |
| ------------------------------- | ------------------------------------------------------------ | ---------------- |
| `npx clawless init [--profile]` | .claude/ ディレクトリ構造を生成（merge インストール）        | ADR-001, ADR-014 |
| `npx clawless health`           | 全フック動作確認 + 設定整合性 + セキュリティギャップレポート | ADR-029          |
| `npx clawless patterns update`  | injection-patterns.json を最新に更新                         | ADR-029          |
| `npx clawless upgrade`          | Clawless 自体のアップグレード（カスタマイズ保持）            | ADR-029          |
| `npx clawless probe`            | OS 検出 + 未使用フック検出 + パターン鮮度チェック            | ADR-029          |
| `npx clawless channels migrate` | Phase 1 → Phase 2（--channels）への移行                      | ADR-021          |
| `npx clawless env create`       | エンタープライズ環境の作成（TTL、用途、同期頻度）            | ADR-026          |
| `npx clawless env diff`         | サンドボックスと本番の設定差分                               | ADR-026          |
| `npx clawless data generate`    | テスト用フェイクデータ生成                                   | ADR-026          |

---

## 10. 外部依存関係

| 依存先                  | バージョン   | 必須/任意 | 用途                                             |
| ----------------------- | ------------ | --------- | ------------------------------------------------ |
| Claude Code             | v2.1.45 以降 | 必須      | hooks / permissions / sandbox のホストランタイム |
| bash                    | 4.0 以降     | 必須      | フックスクリプト実行。Windows: Git Bash          |
| jq                      | 1.6 以降     | 必須      | JSON 処理（patterns, evidence, session state）   |
| Node.js                 | 18 以降      | 必須      | npx clawless CLI、Gateway（Phase 1）             |
| Docker + Docker Compose | 最新安定版   | 任意      | OTEL 統合（Loki + Prometheus + Tempo + Grafana） |
| Cloudflare Tunnel       | 最新安定版   | 任意      | チャンネル外部公開                               |

---

## 11. プロファイルシステム

`npx clawless init --profile` で選択する 3 段階。

| プロファイル     | deny ルール数          | 自動 allow                                   | 用途                                    |
| ---------------- | ---------------------- | -------------------------------------------- | --------------------------------------- |
| minimal          | 15（機密ファイルのみ） | なし                                         | 手動で settings.json を管理するユーザー |
| standard（推奨） | 28 + Clawless 独自     | git read-only, search, inspection 等 40 操作 | 通常開発                                |
| strict           | 40+                    | 19 操作のみ                                  | 本番環境、高セキュリティ                |

全プロファイル共通:

- 22 フックスクリプト全てが登録される
- injection-patterns.json が配置される
- CLAUDE.md 28 ルールが生成される
- evidence-ledger.jsonl が初期化される

プロファイル間の差異は permissions（deny/ask/allow のルール数）と sandbox 設定の厳格度のみ。フックによる防御は全プロファイル同一。

エンタープライズ環境では Managed settings による組織統制が可能:

| 設定                            | 効果                                                                     |
| ------------------------------- | ------------------------------------------------------------------------ |
| allowManagedPermissionRulesOnly | 組織が定義した permission ルールのみ有効。ユーザーによる deny 解除を禁止 |
| allowManagedHooksOnly           | 組織が定義したフックのみ実行。ユーザーによるフック追加・削除を禁止       |

---

## 12. 横断的関心事

### 12.1 パフォーマンス

| コンポーネント                                | 目標値     | 実装方針                                           |
| --------------------------------------------- | ---------- | -------------------------------------------------- |
| PreToolUse フック（単体）                     | 50ms 以下  | bash + jq。重い処理は避ける                        |
| PreToolUse フック（合計: 最大 5 スクリプト）  | 250ms 以下 | 各フックが順序実行。合計予算 = 個別上限 × フック数 |
| SessionStart（全モジュール合計）              | 500ms 以下 | モジュール分割、並列実行可能な設計                 |
| PostToolUse 証跡記録                          | 30ms 以下  | append-only JSONL（seek 不要）                     |
| PostToolUse フック（合計: 最大 3 スクリプト） | 90ms 以下  | evidence + output-control + dep-audit              |
| agent タイプフック                            | 5 秒以下   | 高リスク操作のみ使用。通常のツール実行には不使用   |

PreToolUse の 5 フック（permission, gate, injection-guard, data-boundary, quiet-inject）は Claude Code のフックエンジンにより順序実行される。ツール呼び出し 1 回あたりの合計オーバーヘッドは最大 250ms + PostToolUse 90ms = 340ms。ユーザー体感への影響は軽微（Claude Code 自体の API 応答時間は秒単位）。

### 12.2 フック実装言語の選択基準

| 条件                    | 言語             | 根拠                                      |
| ----------------------- | ---------------- | ----------------------------------------- |
| デフォルト              | bash + jq        | ミリ秒レベル実行。Claude-warden 実績      |
| JSON スキーマ検証が必要 | Node.js CommonJS | jq では複雑なスキーマ検証が困難           |
| 暗号処理が必要          | Node.js CommonJS | bash の sha256sum より柔軟                |
| 外部 API 呼び出しが必要 | Node.js CommonJS | bash から curl は permissions.deny で禁止 |

### 12.3 settings.json フック登録形式

settings.json の hooks セクションにフックを登録する形式。Claude Code ネイティブの仕様に準拠。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|Read|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/clawless-permission.sh"
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/clawless-gate.sh"
          },
          {
            "type": "command",
            "command": "bash .claude/hooks/clawless-quiet-inject.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/clawless-evidence.sh"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/clawless-session-start.sh"
          }
        ]
      }
    ]
  }
}
```

matcher が空文字列の場合は全ツールにマッチする。agent タイプフック（意図検出）は高リスク操作のみに限定し、通常の Bash 実行には適用しない。

### 12.4 エラーハンドリング

全フックの exit code 規約:

| exit code | 意味                                            | 動作                                       |
| --------- | ----------------------------------------------- | ------------------------------------------ |
| 0         | 許可（additionalContext / updatedInput 付与可） | ツール実行を続行                           |
| 2         | 拒否                                            | ツール実行をブロック。理由を stderr に出力 |
| その他    | フックエラー                                    | Claude Code がエラーハンドリング           |

fail-close 原則: フックスクリプト自体がエラーで失敗した場合、安全側（deny）に倒す設計。

### 12.5 劣化モード（Degraded Mode）

外部依存が欠落した場合の動作。fail-close 原則に基づき、安全側に倒す。

| 状況                         | 検知タイミング                | 動作                                                                                                     |
| ---------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| jq 未インストール            | SessionStart（env-check）     | additionalContext で警告。JSON パターンマッチが不可のため、インジェクション検出は正規表現のみに縮退      |
| bash 4.0 未満                | SessionStart（env-check）     | 一部の bash 拡張構文が使えない。警告を出し、基本パターンマッチのみで動作                                 |
| Git Bash 未検出（Windows）   | SessionStart（env-check）     | フック実行不可。additionalContext で「Git Bash をインストールしてください」と通知。deny ルールのみで防御 |
| Node.js 18 未満              | npx clawless init             | init 自体が失敗。エラーメッセージを表示                                                                  |
| injection-patterns.json 破損 | PreToolUse（injection-guard） | パターンファイル読み込み失敗 → exit 2（deny）。安全側に倒す                                              |

### 12.6 アップグレード戦略

`npx clawless upgrade` はマネージド部分のみ更新し、ユーザーカスタマイズを保持する。

```
ファイル先頭の # CLAWLESS-MANAGED コメント有無で判定:
  MANAGED → 新バージョンで上書き
  コメントなし（ユーザーカスタム）→ 保持、diff を表示
```

---

## 13. ADR トレーサビリティ

各 ADR がアーキテクチャのどのコンポーネントに実装されるかの一覧。

| ADR          | 名称                       | 実装コンポーネント                                                    |
| ------------ | -------------------------- | --------------------------------------------------------------------- |
| ADR-001      | Runtime                    | CLI（npx clawless）、フック言語選択                                   |
| ADR-002〜011 | 基盤 ADR                   | settings.json, CLAUDE.md ルール群                                     |
| ADR-012      | エージェント実行防御       | 3 層防御モデル全体                                                    |
| ADR-013      | 証跡記録                   | clawless-evidence.sh, Evidence Layer 1-2                              |
| ADR-014      | ツールガバナンス           | clawless-permission.sh, プロファイルシステム                          |
| ADR-015      | コンテキスト安全性         | clawless-precompact/postcompact/instructions/elicitation.sh           |
| ADR-016      | サーキットブレーカー       | clawless-circuit-breaker/task-gate/subagent.sh                        |
| ADR-017      | ネットワーク隔離           | permissions.deny + sandbox.network                                    |
| ADR-018      | フック基盤                 | 22 フックスクリプト + settings.json hooks セクション                  |
| ADR-019      | 適応的承認制御             | clawless-permission-learn.sh                                          |
| ADR-020      | インジェクション防御       | 4 層パイプライン + injection-patterns.json                            |
| ADR-021      | チャンネルセキュリティ     | Channel Gateway + Phase 2 移行                                        |
| ADR-022      | 法域追跡                   | clawless-data-boundary.sh + allowed-jurisdictions.json                |
| ADR-023      | 依存パッケージ保護         | clawless-dep-audit.sh                                                 |
| ADR-024      | トークン制御               | clawless-output-control/quiet-inject.sh + 予算管理                    |
| ADR-025      | 自己保護                   | clawless-config-guard.sh + permissions.deny + PreToolUse 3 重防御     |
| ADR-026      | エンタープライズガバナンス | clawless-data-boundary.sh + env 管理 CLI                              |
| ADR-027      | フック回避防御             | clawless-gate.sh（7 攻撃ベクトル対策）                                |
| ADR-028      | CLAUDE.md ルール強制       | 横断的: 28 ルール全てに最低 1 フック強制。全コンポーネントに影響      |
| ADR-029      | 自己進化                   | version-check.sh + npx clawless health/upgrade/probe/patterns         |
| ADR-030      | Scheduled Tasks 連携       | npx clawless schedule init（クラウド定期タスクによる非同期監視）      |
| ADR-031      | STG ゲート駆動パイプライン | clawless-pipeline.sh（commit → push → PR → merge 自動化）             |
| ADR-032      | 承認レスモード             | hooks 委譲による ask 排除。approval_free: true                        |
| ADR-033      | プロジェクト管理 SoT       | backlog.yaml スキーマ + sync-project-views.ps1 → 4 .md ビュー自動生成 |
| ADR-034      | 自律タスクループ           | auto-pickup + チャンネル連携 + ブロック通知フィードバック             |
| ADR-035      | バイリンガルドキュメント   | README.md（英語）+ README.ja.md（日本語）+ sync-readme.ps1            |

---

## 14. 脅威→コンポーネント逆引きマッピング

THREAT_MODEL.md の各脅威カテゴリに対して、アーキテクチャのどのコンポーネントが防御を担当するか。

| 脅威 ID | 脅威名           | 主要防御コンポーネント                                                                                 | 補助防御                                         |
| ------- | ---------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| TH-01   | フック回避       | clawless-gate.sh（E-1〜E-4）、clawless-config-guard.sh（E-5〜E-6）、clawless-injection-guard.sh（E-7） | permissions.deny（静的ブロック）                 |
| TH-02   | インジェクション | 4 層パイプライン: user-prompt.sh → injection-guard.sh → intent-audit → evidence.sh                     | injection-patterns.json                          |
| TH-03   | チャンネル攻撃   | Channel Gateway（認証、rate limit、sender allowlist）                                                  | clawless-session-start.sh（openclaw-check）      |
| TH-04   | 認証情報漏洩     | permissions.deny（機密ファイル deny）                                                                  | clawless-evidence.sh（PostToolUse パターン検出） |
| TH-05   | コマンド安全性   | clawless-gate.sh（絶対パス、env -S、symlink）                                                          | permissions.deny                                 |
| TH-06   | データ流出       | clawless-data-boundary.sh + permissions.deny（curl/wget）                                              | sandbox.network（対応 OS のみ）                  |
| TH-07   | サプライチェーン | clawless-dep-audit.sh（install 検出 + スキャン）                                                       | injection-guard.sh（Skill 検査）                 |
| TH-08   | サービス拒否     | clawless-circuit-breaker.sh + clawless-output-control.sh                                               | clawless-subagent.sh（予算注入）                 |
| TH-09   | コンテキスト汚染 | clawless-precompact/postcompact/instructions.sh                                                        | clawless-elicitation.sh（MCP 検査）              |

---

## 15. 本書と後続資料の境界

| 範囲                    | 本書（ARCHITECTURE.md）                  | DETAILED_DESIGN.md（How 層）                             |
| ----------------------- | ---------------------------------------- | -------------------------------------------------------- |
| フックスクリプト        | コンポーネント名、担当ドメイン、根拠 ADR | 各スクリプトの入出力仕様、正規表現パターン、分岐ロジック |
| settings.json           | 登録形式、プロファイル概要               | 全 deny/ask/allow ルールの完全リスト                     |
| injection-patterns.json | カテゴリ構成、severity 定義              | 全パターンの正規表現と検出根拠                           |
| Channel Gateway         | アーキテクチャ、メッセージフロー         | API エンドポイント仕様、認証フロー詳細                   |
| CLI コマンド            | コマンド名と概要                         | 引数仕様、エラーメッセージ、テストケース                 |

本書は「何がどこにあるか」を示す地図。DETAILED_DESIGN.md は「各コンポーネントがどう動くか」を示す仕様書。

---

## 次の資料

本基本設計書（What 層）の次は以下を作成する:

- **④ CLAUDE.md**（What 層）: 28 ルールの実ファイル
- **⑤ DETAILED_DESIGN.md**（How 層）: 各フックスクリプトの詳細仕様
