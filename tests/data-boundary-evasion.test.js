#!/usr/bin/env node
// data-boundary-evasion.test.js — Adversarial security tests for sh-data-boundary.js
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

// Module under test
const boundary = require("../.claude/hooks/sh-data-boundary.js");
const { extractHostsFromCommand, extractHostFromUrl, isInternalHost } =
  boundary;

// ============================================================================
// Tests: SSRF / Cloud metadata endpoint detection
// ============================================================================

describe("sh-data-boundary.js -- SSRF cloud metadata endpoints", () => {
  it("should detect AWS metadata endpoint 169.254.169.254", () => {
    const hosts = extractHostsFromCommand(
      "curl http://169.254.169.254/latest/meta-data/",
    );
    assert.ok(hosts.length > 0, "should extract host from curl command");
    assert.ok(
      isInternalHost(hosts[0]),
      "169.254.169.254 should be detected as internal",
    );
  });

  it("should detect GCP metadata endpoint metadata.google.internal", () => {
    const hosts = extractHostsFromCommand(
      "curl http://metadata.google.internal/computeMetadata/v1/",
    );
    assert.ok(hosts.length > 0, "should extract host from curl command");
    assert.ok(
      isInternalHost(hosts[0]),
      "metadata.google.internal should be detected as internal",
    );
  });

  it("should detect Alibaba Cloud metadata endpoint 100.100.100.200", () => {
    assert.ok(
      isInternalHost("100.100.100.200"),
      "100.100.100.200 should be detected as internal",
    );
  });
});

// ============================================================================
// Tests: Localhost aliases
// ============================================================================

describe("sh-data-boundary.js -- localhost alias detection", () => {
  it("should detect 127.0.0.1 as internal", () => {
    assert.ok(
      isInternalHost("127.0.0.1"),
      "127.0.0.1 should be detected as internal",
    );
  });

  it("should detect 0.0.0.0 as internal", () => {
    assert.ok(
      isInternalHost("0.0.0.0"),
      "0.0.0.0 should be detected as internal",
    );
  });

  it("should detect [::1] as internal", () => {
    assert.ok(isInternalHost("[::1]"), "[::1] should be detected as internal");
  });

  it("should detect ::1 as internal", () => {
    assert.ok(isInternalHost("::1"), "::1 should be detected as internal");
  });

  it("should detect localhost as internal", () => {
    assert.ok(
      isInternalHost("localhost"),
      "localhost should be detected as internal",
    );
  });
});

// ============================================================================
// Tests: Private IP ranges (RFC 1918)
// ============================================================================

describe("sh-data-boundary.js -- private IP range detection", () => {
  it("should detect 10.0.0.1 as internal (10.x.x.x)", () => {
    assert.ok(
      isInternalHost("10.0.0.1"),
      "10.0.0.1 should be detected as internal",
    );
  });

  it("should detect 172.16.0.1 as internal (172.16-31.x.x)", () => {
    assert.ok(
      isInternalHost("172.16.0.1"),
      "172.16.0.1 should be detected as internal",
    );
  });

  it("should detect 172.31.255.255 as internal (172.16-31.x.x upper bound)", () => {
    assert.ok(
      isInternalHost("172.31.255.255"),
      "172.31.255.255 should be detected as internal",
    );
  });

  it("should NOT detect 172.15.0.1 as internal (below range)", () => {
    assert.ok(
      !isInternalHost("172.15.0.1"),
      "172.15.0.1 should NOT be detected as internal",
    );
  });

  it("should NOT detect 172.32.0.1 as internal (above range)", () => {
    assert.ok(
      !isInternalHost("172.32.0.1"),
      "172.32.0.1 should NOT be detected as internal",
    );
  });

  it("should detect 192.168.1.1 as internal (192.168.x.x)", () => {
    assert.ok(
      isInternalHost("192.168.1.1"),
      "192.168.1.1 should be detected as internal",
    );
  });
});

// ============================================================================
// Tests: extractHostsFromCommand and extractHostFromUrl (basic GREEN)
// ============================================================================

describe("sh-data-boundary.js -- host extraction", () => {
  it("should extract host from curl command", () => {
    const hosts = extractHostsFromCommand("curl https://example.com/api/data");
    assert.ok(hosts.includes("example.com"), "should extract example.com");
  });

  it("should extract host from wget command", () => {
    const hosts = extractHostsFromCommand(
      "wget http://downloads.example.org/file.tar.gz",
    );
    assert.ok(
      hosts.includes("downloads.example.org"),
      "should extract downloads.example.org",
    );
  });

  it("should extract host from URL via extractHostFromUrl", () => {
    const host = extractHostFromUrl("https://api.github.com/repos");
    assert.equal(host, "api.github.com");
  });

  it("should return null for invalid URL", () => {
    const host = extractHostFromUrl("not-a-url");
    assert.equal(host, null);
  });

  it("should extract host from ssh command", () => {
    const hosts = extractHostsFromCommand("ssh user@prod-server.example.com");
    assert.ok(
      hosts.includes("prod-server.example.com"),
      "should extract prod-server.example.com",
    );
  });
});

// ============================================================================
// Tests: Edge cases
// ============================================================================

describe("sh-data-boundary.js -- edge cases", () => {
  it("should detect URL-encoded localhost via extractHostFromUrl", () => {
    // %6C%6F%63%61%6C%68%6F%73%74 = localhost
    const host = extractHostFromUrl("http://%6C%6F%63%61%6C%68%6F%73%74/admin");
    assert.ok(
      host !== null && isInternalHost(host),
      "URL-encoded localhost should be detected as internal",
    );
  });

  it("should detect URL-encoded 169.254.169.254 via extractHostFromUrl", () => {
    // %31%36%39%2E%32%35%34%2E%31%36%39%2E%32%35%34 = 169.254.169.254
    const host = extractHostFromUrl(
      "http://%31%36%39%2E%32%35%34%2E%31%36%39%2E%32%35%34/latest/meta-data/",
    );
    assert.ok(
      host !== null && isInternalHost(host),
      "URL-encoded metadata IP should be detected as internal",
    );
  });

  it("should NOT detect external hosts as internal", () => {
    assert.ok(
      !isInternalHost("example.com"),
      "example.com should NOT be internal",
    );
    assert.ok(!isInternalHost("8.8.8.8"), "8.8.8.8 should NOT be internal");
    assert.ok(
      !isInternalHost("api.github.com"),
      "api.github.com should NOT be internal",
    );
  });
});
