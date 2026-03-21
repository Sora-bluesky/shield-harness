---
name: docs-sync
description: |
  ドキュメントとコード実装の整合性を監査する。
  コード変更後に「ドキュメント確認」「docs-sync」「整合性チェック」で呼び出される。
  Hook 実装と設計ドキュメントの乖離、README の記述の古さ、
  マニフェストとファイル構成のずれを検出して修正案を提示する。
metadata:
  short-description: ドキュメント/コード整合性チェック
---

# /docs-sync -- Document-Code Consistency Audit

$ARGUMENTS (optional: specific area to check, e.g., "hooks", "readme", "manifest")

## Overview

Checks that documentation accurately reflects the current codebase. Detects drift between docs and implementation.

## Workflow

### Step 1: Scope Detection

- If $ARGUMENTS specified, check only that area
- If no arguments, check all areas below

### Step 2: Hook Implementation vs Design Docs

- Read `.claude/hooks/*.js` and extract actual functionality
- Compare with design document descriptions
- Report: missing hooks, undocumented features, stale descriptions

### Step 3: README Accuracy

- Check section completeness (Prerequisites, Quick Start, Architecture, etc.)
- Verify version references match package.json
- Check hook count matches actual hook files

### Step 4: Manifest Consistency

- Read `integration/manifest.yaml`
- Verify all listed files exist
- Check for files that should be listed but aren't
- Verify boundary-classification.yaml entries

### Step 5: Report

Output a summary table:

| Area      | Status     | Issues  |
| --------- | ---------- | ------- |
| Hook docs | OK / DRIFT | details |
| README    | OK / DRIFT | details |
| Manifest  | OK / DRIFT | details |

For each DRIFT item, provide a specific fix suggestion.

## Notes

- This skill is READ-ONLY. It does not modify files -- it reports findings.
- Use `/auto-fix` or manual editing to apply fixes.
