# Development Environment

## Script Execution

- **PowerShell 7** (`pwsh`) for all automation scripts
- Scripts are located in `scripts/` directory

## Pre-commit Security

- Git hooks in `.githooks/` (pre-commit, pre-push)
- `git-guard-scan.sh` blocks secrets, private paths, and sensitive data
- Configured via `git config core.hooksPath .githooks`

## Linting (Future)

- PowerShell: PSScriptAnalyzer (`Invoke-ScriptAnalyzer`)
- Markdown: markdownlint (optional)
- Currently: manual review + git-guard-scan

## Testing (Future)

- PowerShell: Pester 5.0+ (`Invoke-Pester -Verbose`)
- Currently: manual verification + git-guard checks

## Task Management

- **SoT**: `tasks/backlog.yaml`

## Important Commands

```powershell
# Verify tobari setup
pwsh ./scripts/verify-tobari-setup.ps1

# Git guard (manual scan)
bash .githooks/pre-commit
```
