# Channel Security Rules

## Approval-Free Mode (ADR-032)

When `approval_free: true` in pipeline-config.json:

- All security decisions are delegated to hooks (no human approval dialogs)
- `permissions.deny` rules remain absolute — hooks cannot override them
- `permissions.ask` rules are promoted to `allow` at SessionStart
- All hook-based defenses (gate, injection-guard, permission) run at 100%

## Security Invariants

These guarantees hold regardless of approval_free setting:

1. **deny is absolute**: No hook, agent, or automation can override a deny rule
2. **fail-close**: If a hook cannot determine safety, it denies (exit 2)
3. **evidence required**: All allow/deny decisions are recorded in evidence-ledger
4. **no silent bypass**: Hook errors result in deny, not silent allow

## Channel Input Validation (Phase 2)

When channel integration (Telegram/Discord) is enabled:

- All channel messages pass through clawless-user-prompt hook
- Task additions via channel require STG0 gate validation
- Channel authentication is verified before processing commands
- Rate limiting prevents channel-based DoS attacks
