#!/usr/bin/env node
// gate-evasion.test.js — Adversarial security tests for sh-gate.js
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

// Module under test
const gate = require("../.claude/hooks/sh-gate.js");
const { matchPatterns, nfkcNormalize } = (() => {
  const { matchPatterns } = gate;
  const { nfkcNormalize } = require("../.claude/hooks/lib/sh-utils");
  return { matchPatterns, nfkcNormalize };
})();

// Helper: check if any pattern array in sh-gate detects the command
function shouldDeny(command) {
  const normalized = nfkcNormalize(command);

  // Split on pipe chain separators and check each segment
  // Use matchAllPatterns which handles pipe-chain splitting, sudo, prefix
  const allPatterns = [
    gate.DESTRUCTIVE_PATTERNS,
    gate.TOOL_SWITCHING_PATTERNS,
    gate.DYNAMIC_LINKER_PATTERNS,
    gate.SED_DANGER_PATTERNS,
    gate.CONFIG_MODIFY_PATTERNS,
    gate.PATH_HIJACK_PATTERNS,
    gate.WINDOWS_PATTERNS,
    gate.PIPELINE_SPOOFING_PATTERNS,
    gate.PATH_OBFUSCATION_PATTERNS,
    gate.GIT_BYPASS_PATTERNS,
    gate.VARIABLE_EXPANSION_PATTERNS,
  ];

  return gate.matchAllPatterns(normalized, allPatterns) !== null;
}

function shouldAllow(command) {
  return !shouldDeny(command);
}

// ============================================================================
// Tests: Commands that SHOULD already be detected (existing patterns)
// ============================================================================

describe("sh-gate.js — existing pattern verification", () => {
  it("should deny rm -rf / (basic destructive)", () => {
    assert.ok(shouldDeny("rm -rf /"), "rm -rf / should be denied");
  });

  it("should deny rm -rf ~ (home destruction)", () => {
    assert.ok(shouldDeny("rm -rf ~"), "rm -rf ~ should be denied");
  });

  it("should deny sed -i (in-place edit)", () => {
    assert.ok(shouldDeny("sed -i 's/a/b/' file"), "sed -i should be denied");
  });

  it("should deny LD_PRELOAD= (dynamic linker)", () => {
    assert.ok(
      shouldDeny("LD_PRELOAD=/tmp/evil.so ls"),
      "LD_PRELOAD should be denied",
    );
  });

  it("should allow ls -la (safe command)", () => {
    assert.ok(shouldAllow("ls -la"), "ls -la should be allowed");
  });

  it("should allow git status (safe command)", () => {
    assert.ok(shouldAllow("git status"), "git status should be allowed");
  });
});

// ============================================================================
// Tests: Adversarial evasion attacks (expect RED initially)
// ============================================================================

describe("sh-gate.js — flag separation evasion", () => {
  it("should deny rm -f -r / (separated flags)", () => {
    assert.ok(shouldDeny("rm -f -r /"), "rm -f -r / should be denied");
  });

  it("should deny rm -rf ./ (relative path root)", () => {
    assert.ok(shouldDeny("rm -rf ./"), "rm -rf ./ should be denied");
  });
});

describe("sh-gate.js — alternative destructors", () => {
  it("should deny find / -delete", () => {
    assert.ok(shouldDeny("find / -delete"), "find -delete should be denied");
  });

  it("should deny shred /etc/passwd", () => {
    assert.ok(shouldDeny("shred /etc/passwd"), "shred should be denied");
  });
});

describe("sh-gate.js — uncovered scripting languages", () => {
  it("should deny lua -e 'os.execute(\"rm -rf /\")'", () => {
    assert.ok(
      shouldDeny("lua -e 'os.execute(\"rm -rf /\")'"),
      "lua -e should be denied",
    );
  });

  it("should deny php -r 'system(\"rm -rf /\")'", () => {
    assert.ok(
      shouldDeny("php -r 'system(\"rm -rf /\")'"),
      "php -r should be denied",
    );
  });

  it("should deny awk '{system(\"rm -rf /\")}'", () => {
    assert.ok(
      shouldDeny("awk '{system(\"rm -rf /\")}'"),
      "awk system should be denied",
    );
  });

  it('should deny bash -c "rm -rf /"', () => {
    assert.ok(shouldDeny('bash -c "rm -rf /"'), "bash -c should be denied");
  });

  it("should deny node -e 'require(\"child_process\")'", () => {
    assert.ok(
      shouldDeny('node -e \'require("child_process").execSync("rm -rf /")\''),
      "node -e child_process should be denied",
    );
  });
});

describe("sh-gate.js — redirect without space", () => {
  it('should deny echo "data">"file" (no space redirect)', () => {
    assert.ok(
      shouldDeny('echo "data">"file"'),
      "redirect without space should be denied",
    );
  });
});

describe("sh-gate.js — pipe chain evasion", () => {
  it("should deny cat file ; rm -rf /", () => {
    assert.ok(
      shouldDeny("cat file ; rm -rf /"),
      "semicolon chain with rm should be denied",
    );
  });

  it("should deny cat file && rm -rf /", () => {
    assert.ok(
      shouldDeny("cat file && rm -rf /"),
      "&& chain with rm should be denied",
    );
  });

  it("should deny cat file || rm -rf /", () => {
    assert.ok(
      shouldDeny("cat file || rm -rf /"),
      "|| chain with rm should be denied",
    );
  });
});

describe("sh-gate.js — builtin prefix evasion", () => {
  it("should deny command rm -rf /", () => {
    assert.ok(
      shouldDeny("command rm -rf /"),
      "command prefix should be stripped and denied",
    );
  });

  it("should deny builtin rm -rf /", () => {
    assert.ok(
      shouldDeny("builtin rm -rf /"),
      "builtin prefix should be stripped and denied",
    );
  });
});

describe("sh-gate.js — git hooks bypass", () => {
  it("should deny git --no-verify commit", () => {
    assert.ok(
      shouldDeny("git commit --no-verify"),
      "git --no-verify should be denied",
    );
  });

  it("should deny git config core.hooksPath /dev/null", () => {
    assert.ok(
      shouldDeny("git config core.hooksPath /dev/null"),
      "git config core.hooksPath should be denied",
    );
  });
});

describe("sh-gate.js — environment manipulation", () => {
  it("should deny NODE_OPTIONS='--require evil.js'", () => {
    assert.ok(
      shouldDeny("NODE_OPTIONS='--require /tmp/evil.js' node app.js"),
      "NODE_OPTIONS should be denied",
    );
  });
});

describe("sh-gate.js — variable expansion", () => {
  it("should deny $(rm -rf /)", () => {
    assert.ok(
      shouldDeny("echo $(rm -rf /)"),
      "command substitution should be denied",
    );
  });

  it("should deny ${cmd} expansion", () => {
    assert.ok(shouldDeny("${cmd}"), "variable expansion should be denied");
  });
});

describe("sh-gate.js — sudo stripping", () => {
  it("should deny sudo rm -rf /", () => {
    assert.ok(shouldDeny("sudo rm -rf /"), "sudo rm -rf should be denied");
  });

  it("should deny sudo -u root rm -rf /", () => {
    assert.ok(
      shouldDeny("sudo -u root rm -rf /"),
      "sudo -u root rm -rf should be denied",
    );
  });
});

describe("sh-gate.js — Windows case-insensitive extensions", () => {
  it("should deny .CMD extension (uppercase)", () => {
    assert.ok(
      shouldDeny("malware.CMD"),
      ".CMD should be denied (case insensitive)",
    );
  });

  it("should deny .BAT extension (uppercase)", () => {
    assert.ok(
      shouldDeny("script.BAT"),
      ".BAT should be denied (case insensitive)",
    );
  });
});

// ============================================================================
// Sanity: safe commands must not be blocked
// ============================================================================

describe("sh-gate.js — false positive prevention", () => {
  it("should allow npm test", () => {
    assert.ok(shouldAllow("npm test"), "npm test should be allowed");
  });

  it("should allow cat README.md", () => {
    assert.ok(shouldAllow("cat README.md"), "cat should be allowed");
  });

  it("should allow grep -r pattern .", () => {
    assert.ok(shouldAllow("grep -r pattern ."), "grep should be allowed");
  });

  it("should allow node --version", () => {
    assert.ok(
      shouldAllow("node --version"),
      "node --version should be allowed",
    );
  });
});
