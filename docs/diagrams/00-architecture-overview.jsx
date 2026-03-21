import { useState } from "react";
import {
  Shield,
  Lock,
  Eye,
  Zap,
  AlertTriangle,
  CheckCircle,
  Layers,
  Activity,
} from "lucide-react";

const colors = {
  bg: "#0f172a",
  card: "#1e293b",
  cardHover: "#334155",
  green: "#22c55e",
  greenBg: "#22c55e20",
  orange: "#f97316",
  orangeBg: "#f9731620",
  red: "#ef4444",
  redBg: "#ef444420",
  blue: "#3b82f6",
  blueBg: "#3b82f620",
  purple: "#a855f7",
  purpleBg: "#a855f720",
  text: "#f8fafc",
  textMuted: "#94a3b8",
  border: "#334155",
};

const MetricCard = ({ icon: Icon, value, label, color, colorBg }) => (
  <div
    style={{
      background: colors.card,
      borderRadius: 12,
      padding: "20px 24px",
      border: `1px solid ${colors.border}`,
      display: "flex",
      alignItems: "center",
      gap: 16,
      transition: "background 0.2s",
    }}
  >
    <div
      style={{
        background: colorBg,
        borderRadius: 10,
        padding: 10,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Icon size={22} color={color} />
    </div>
    <div>
      <div style={{ fontSize: 24, fontWeight: 700, color: colors.text }}>
        {value}
      </div>
      <div style={{ fontSize: 13, color: colors.textMuted, marginTop: 2 }}>
        {label}
      </div>
    </div>
  </div>
);

const DefenseLayer = ({
  number,
  name,
  nameJa,
  description,
  color,
  colorBg,
  os,
  hooks,
}) => {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      style={{
        background: colorBg,
        border: `1px solid ${color}40`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 10,
        padding: "16px 20px",
        cursor: hooks ? "pointer" : "default",
      }}
      onClick={() => hooks && setExpanded(!expanded)}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              background: color,
              color: "#fff",
              borderRadius: 8,
              width: 32,
              height: 32,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: 14,
            }}
          >
            {number}
          </div>
          <div>
            <div style={{ color: colors.text, fontWeight: 600, fontSize: 15 }}>
              {name}{" "}
              <span style={{ color: colors.textMuted, fontWeight: 400 }}>
                — {nameJa}
              </span>
            </div>
            <div
              style={{ color: colors.textMuted, fontSize: 13, marginTop: 2 }}
            >
              {description}
            </div>
          </div>
        </div>
        <div
          style={{
            background: `${color}30`,
            color: color,
            padding: "4px 10px",
            borderRadius: 6,
            fontSize: 12,
            fontWeight: 600,
            whiteSpace: "nowrap",
          }}
        >
          {os}
        </div>
      </div>
      {expanded && hooks && (
        <div
          style={{
            marginTop: 12,
            paddingTop: 12,
            borderTop: `1px solid ${color}30`,
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: 8,
          }}
        >
          {hooks.map((h, i) => (
            <div
              key={i}
              style={{
                background: `${color}10`,
                borderRadius: 6,
                padding: "6px 10px",
                fontSize: 12,
                color: colors.textMuted,
                fontFamily: "monospace",
              }}
            >
              <span style={{ color }}>{h.event}</span> → {h.name}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const HookStep = ({ label, sublabel, color, isLast }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
    <div
      style={{
        background: `${color}20`,
        border: `1px solid ${color}50`,
        borderRadius: 8,
        padding: "8px 14px",
        textAlign: "center",
        minWidth: 100,
      }}
    >
      <div style={{ fontSize: 12, fontWeight: 600, color }}>{label}</div>
      {sublabel && (
        <div style={{ fontSize: 10, color: colors.textMuted, marginTop: 2 }}>
          {sublabel}
        </div>
      )}
    </div>
    {!isLast && (
      <div style={{ color: colors.textMuted, padding: "0 4px", fontSize: 16 }}>
        →
      </div>
    )}
  </div>
);

export default function ClawlessArchitecture() {
  return (
    <div
      style={{
        background: colors.bg,
        minHeight: "100vh",
        padding: 32,
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      }}
    >
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            marginBottom: 8,
          }}
        >
          <Shield size={28} color={colors.blue} />
          <h1
            style={{
              color: colors.text,
              fontSize: 28,
              fontWeight: 700,
              margin: 0,
            }}
          >
            Clawless
          </h1>
        </div>
        <p style={{ color: colors.textMuted, fontSize: 15, margin: 0 }}>
          くろうレス — Claude Code セキュリティハーネス — Security Architecture
          Overview
        </p>
      </div>

      {/* Metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: 12,
          marginBottom: 32,
        }}
      >
        <MetricCard
          icon={CheckCircle}
          value="28"
          label="CLAUDE.md ルール"
          color={colors.green}
          colorBg={colors.greenBg}
        />
        <MetricCard
          icon={Shield}
          value="18/18"
          label="OpenClaw 問題解決"
          color={colors.blue}
          colorBg={colors.blueBg}
        />
        <MetricCard
          icon={Eye}
          value="50+"
          label="インジェクションパターン（9カテゴリ）"
          color={colors.purple}
          colorBg={colors.purpleBg}
        />
        <MetricCard
          icon={AlertTriangle}
          value="7/7"
          label="フック回避攻撃防御"
          color={colors.orange}
          colorBg={colors.orangeBg}
        />
        <MetricCard
          icon={Zap}
          value="50ms"
          label="PreToolUse 目標レイテンシ"
          color={colors.green}
          colorBg={colors.greenBg}
        />
        <MetricCard
          icon={Layers}
          value="95%"
          label="Windows ネイティブ防御カバレッジ"
          color={colors.red}
          colorBg={colors.redBg}
        />
      </div>

      {/* Defense Layers */}
      <div style={{ marginBottom: 32 }}>
        <h2
          style={{
            color: colors.text,
            fontSize: 18,
            fontWeight: 600,
            marginBottom: 16,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Layers size={20} color={colors.blue} />
          3層防御モデル（Defense Layers）
        </h2>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <DefenseLayer
            number="1"
            name="Permissions"
            nameJa="静的ルール"
            description="settings.json の deny > ask > allow 体系。機密ファイル・危険コマンドを静的にブロック"
            color={colors.green}
            colorBg={colors.greenBg}
            os="Windows / WSL2 / Linux"
          />
          <DefenseLayer
            number="2"
            name="Hook Chain"
            nameJa="動的フック群"
            description="PreToolUse / PostToolUse / Lifecycle — bash + jq によるリアルタイム検査（クリックで展開）"
            color={colors.orange}
            colorBg={colors.orangeBg}
            os="Windows / WSL2 / Linux"
            hooks={[
              { event: "PreToolUse", name: "clawless-permission.sh" },
              { event: "PreToolUse", name: "clawless-injection-guard.sh" },
              { event: "PreToolUse", name: "clawless-evasion-guard.sh" },
              { event: "PreToolUse", name: "clawless-quiet-inject.sh" },
              { event: "PreToolUse", name: "clawless-data-boundary.sh" },
              { event: "PostToolUse", name: "clawless-evidence.sh" },
              { event: "PostToolUse", name: "clawless-exfil-guard.sh" },
              { event: "PostToolUse", name: "clawless-dep-audit.sh" },
              { event: "SessionStart", name: "clawless-session-start.sh" },
              { event: "PreCompact", name: "clawless-compact.sh" },
              { event: "Stop", name: "clawless-circuit-breaker.sh" },
              { event: "ConfigChange", name: "clawless-config-guard.sh" },
            ]}
          />
          <DefenseLayer
            number="3"
            name="OS Sandbox"
            nameJa="OS レベル隔離"
            description="bubblewrap (Linux/WSL2) によるファイルシステム・ネットワーク隔離。Windows ネイティブは未対応（planned）"
            color={colors.red}
            colorBg={colors.redBg}
            os="WSL2 / Linux のみ"
          />
        </div>
      </div>

      {/* Hook Flow */}
      <div style={{ marginBottom: 32 }}>
        <h2
          style={{
            color: colors.text,
            fontSize: 18,
            fontWeight: 600,
            marginBottom: 16,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Activity size={20} color={colors.blue} />
          フック処理フロー（Hook Processing Flow）
        </h2>
        <div
          style={{
            background: colors.card,
            borderRadius: 12,
            padding: 20,
            border: `1px solid ${colors.border}`,
            overflowX: "auto",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 4,
            }}
          >
            <HookStep
              label="User Prompt"
              sublabel="VS Code"
              color={colors.blue}
            />
            <HookStep
              label="Claude Code"
              sublabel="Agent"
              color={colors.purple}
            />
            <HookStep
              label="Permission"
              sublabel="4-category"
              color={colors.green}
            />
            <HookStep
              label="Injection"
              sublabel="50+ patterns"
              color={colors.orange}
            />
            <HookStep
              label="Evasion"
              sublabel="7 vectors"
              color={colors.orange}
            />
            <HookStep
              label="Token"
              sublabel="quiet flags"
              color={colors.orange}
            />
            <HookStep
              label="Data Boundary"
              sublabel="jurisdiction"
              color={colors.orange}
            />
            <HookStep
              label="Tool Exec"
              sublabel="Bash/Edit/..."
              color={colors.purple}
            />
            <HookStep
              label="Evidence"
              sublabel="SHA-256 chain"
              color={colors.green}
            />
            <HookStep
              label="Exfil Guard"
              sublabel="leak check"
              color={colors.green}
            />
            <HookStep
              label="Dep Audit"
              sublabel="if install"
              color={colors.green}
            />
            <HookStep
              label="Result"
              sublabel="to user"
              color={colors.blue}
              isLast
            />
          </div>
          <div
            style={{ marginTop: 12, display: "flex", gap: 16, fontSize: 12 }}
          >
            <span style={{ color: colors.orange }}>■ PreToolUse</span>
            <span style={{ color: colors.purple }}>■ Agent</span>
            <span style={{ color: colors.green }}>■ PostToolUse</span>
            <span style={{ color: colors.blue }}>■ User</span>
          </div>
        </div>
      </div>

      {/* Windows Note */}
      <div
        style={{
          background: `${colors.orange}10`,
          border: `1px solid ${colors.orange}30`,
          borderRadius: 10,
          padding: 16,
          display: "flex",
          alignItems: "flex-start",
          gap: 12,
        }}
      >
        <AlertTriangle
          size={20}
          color={colors.orange}
          style={{ flexShrink: 0, marginTop: 2 }}
        />
        <div>
          <div
            style={{
              color: colors.orange,
              fontWeight: 600,
              fontSize: 14,
              marginBottom: 4,
            }}
          >
            Windows ネイティブファースト設計
          </div>
          <div
            style={{ color: colors.textMuted, fontSize: 13, lineHeight: 1.6 }}
          >
            Windows ネイティブでは OS サンドボックス（Defense Layer
            3）が利用不可。 Layer 1（Permissions）+ Layer 2（Hook
            Chain）の組み合わせで主要攻撃ベクトルの 95% をカバー。 WSL2
            への切り替えは強制しない。Mac は現時点でスコープ外。
          </div>
        </div>
      </div>
    </div>
  );
}
