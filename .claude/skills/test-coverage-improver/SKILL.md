---
name: test-coverage-improver
description: |
  テストカバレッジを分析し、最もインパクトの大きいテスト追加を提案する。
  「テスト改善」「カバレッジ」「test-coverage」で呼び出される。
  モジュールごとのカバレッジ分析、未テストのエッジケース検出、
  テストスケルトンの自動生成を行う。
metadata:
  short-description: テストカバレッジ改善提案
---

# /test-coverage-improver -- Test Coverage Analysis & Improvement

$ARGUMENTS (optional: specific module or file to analyze)

## Overview

Analyzes existing tests, identifies coverage gaps, and suggests the most impactful tests to add. Generates test skeletons for quick implementation.

## Workflow

### Step 1: Test Inventory

- Scan `tests/` directory for all test files
- Count test cases per module/hook
- Build a coverage map: which source files have tests, which don't

### Step 2: Gap Analysis

- Identify source files with NO corresponding tests
- For tested files, check coverage of:
  - Happy path (normal input, expected output)
  - Boundary values (min, max, empty, zero)
  - Error cases (invalid input, error conditions)
  - Edge cases (null, empty string, special characters)
- Prioritize gaps by risk level (security hooks > utility modules)

### Step 3: Impact Ranking

Rank suggested tests by impact:

| Priority | Criteria                                                               |
| -------- | ---------------------------------------------------------------------- |
| HIGH     | Security-related hooks (gate, injection-guard) without edge case tests |
| HIGH     | Core modules (session, stage) with missing error path tests            |
| MEDIUM   | Utility modules with partial coverage                                  |
| LOW      | Already well-tested modules needing only edge cases                    |

### Step 4: Skeleton Generation

For each HIGH priority gap, generate a test skeleton:

```javascript
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

describe("{module} - {scenario}", () => {
  it("should {expected behavior}", () => {
    // Arrange
    // Act
    // Assert
    assert.ok(false, "TODO: implement");
  });
});
```

### Step 5: Report

Output:

1. Coverage summary table (module / test count / coverage level / priority)
2. Top 5 recommended tests to add (with skeletons)
3. Estimated effort (LOW / MEDIUM / HIGH per test)

## Notes

- Uses `node:test` runner (tobari standard)
- Test naming convention: `test_{subject}_{condition}_{expected_result}`
- Run tests with: `node --test --test-concurrency=1 tests/`
- This skill generates suggestions and skeletons -- actual implementation is manual or via `/tdd`
