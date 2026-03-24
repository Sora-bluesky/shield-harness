#!/usr/bin/env bash
# OpenShell Defense Integration Test
# Requires: Docker + OpenShell CLI + running sandbox
# Run: bash tests/integration/openshell-defense.sh
# NOTE: OpenShell Alpha v0.0.13+ expected. API may change.
#
# This script is for MANUAL testing only — NOT for CI.
# It validates that OpenShell sandbox policies correctly restrict:
#   1. File access (deny_read / deny_write)
#   2. Network access (deny-all + allowlist)
#   3. Raw socket restrictions
#
# Exit codes:
#   0 = all tests passed
#   1 = one or more tests failed
#   2 = prerequisites not met

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() {
  echo -e "  ${GREEN}PASS${NC}: $1"
  ((PASS++))
}

fail() {
  echo -e "  ${RED}FAIL${NC}: $1"
  ((FAIL++))
}

skip() {
  echo -e "  ${YELLOW}SKIP${NC}: $1"
  ((SKIP++))
}

# --- Prerequisites ---
echo "=== OpenShell Defense Integration Test ==="
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
  echo -e "${RED}ERROR: Docker CLI not found. Install Docker first.${NC}"
  exit 2
fi

# Check OpenShell CLI
if ! command -v openshell &>/dev/null; then
  echo -e "${RED}ERROR: OpenShell CLI not found. Install openshell first.${NC}"
  exit 2
fi

# Check running sandbox
SANDBOX_STATUS=$(openshell sandbox list 2>/dev/null || echo "")
if ! echo "$SANDBOX_STATUS" | grep -qi "running"; then
  echo -e "${RED}ERROR: No running OpenShell sandbox found.${NC}"
  echo "  Start one with: openshell sandbox start"
  exit 2
fi

echo "Prerequisites OK: Docker + OpenShell CLI + running sandbox"
echo ""

# --- Test 1: File Access Restrictions ---
echo "--- Test Group 1: File Access ---"

# Test 1.1: Reading ~/.ssh should be blocked
echo "Test 1.1: Read ~/.ssh/id_rsa (should be denied)"
if openshell exec -- cat ~/.ssh/id_rsa 2>&1 | grep -qi "denied\|permission\|blocked\|error"; then
  pass "~/.ssh/id_rsa read was blocked"
else
  fail "~/.ssh/id_rsa read was NOT blocked"
fi

# Test 1.2: Writing to .claude/hooks/ should be blocked
echo "Test 1.2: Write to .claude/hooks/ (should be denied)"
if openshell exec -- touch .claude/hooks/test-write 2>&1 | grep -qi "denied\|permission\|blocked\|read-only\|error"; then
  pass ".claude/hooks/ write was blocked"
else
  fail ".claude/hooks/ write was NOT blocked"
fi

# Test 1.3: Reading normal project files should be allowed
echo "Test 1.3: Read package.json (should be allowed)"
if openshell exec -- cat package.json 2>&1 | grep -qi "name\|version"; then
  pass "package.json read was allowed"
else
  skip "package.json may not exist in sandbox context"
fi

# Test 1.4: Reading .env files should be blocked
echo "Test 1.4: Read .env (should be denied)"
if openshell exec -- cat .env 2>&1 | grep -qi "denied\|permission\|blocked\|error\|no such"; then
  pass ".env read was blocked or not found"
else
  fail ".env read was NOT blocked"
fi

echo ""

# --- Test 2: Network Restrictions ---
echo "--- Test Group 2: Network Access ---"

# Test 2.1: External curl should be blocked
echo "Test 2.1: curl to external URL (should be denied)"
if openshell exec -- curl -s --connect-timeout 3 https://example.com 2>&1 | grep -qi "denied\|blocked\|refused\|timeout\|error"; then
  pass "External curl was blocked"
else
  fail "External curl was NOT blocked"
fi

# Test 2.2: wget should be blocked
echo "Test 2.2: wget to external URL (should be denied)"
if openshell exec -- wget -q --timeout=3 https://example.com -O /dev/null 2>&1 | grep -qi "denied\|blocked\|refused\|timeout\|error"; then
  pass "External wget was blocked"
else
  fail "External wget was NOT blocked"
fi

# Test 2.3: DNS should still work (if needed for allowlisted services)
echo "Test 2.3: DNS resolution (informational)"
if openshell exec -- nslookup example.com 2>&1 | grep -qi "address"; then
  echo -e "  ${YELLOW}INFO${NC}: DNS resolution works (check if allowlisted only)"
else
  echo -e "  ${YELLOW}INFO${NC}: DNS resolution blocked (strict network policy)"
fi

echo ""

# --- Test 3: Raw Socket Restrictions ---
echo "--- Test Group 3: Raw Socket ---"

# Test 3.1: nc (netcat) should be blocked
echo "Test 3.1: netcat connection (should be denied)"
if openshell exec -- nc -z -w 1 example.com 80 2>&1 | grep -qi "denied\|blocked\|refused\|timeout\|error"; then
  pass "netcat was blocked"
elif ! openshell exec -- which nc &>/dev/null; then
  skip "nc not available in sandbox"
else
  fail "netcat was NOT blocked"
fi

# Test 3.2: Python raw socket should be blocked
echo "Test 3.2: Python socket connect (should be denied)"
PYTHON_SOCKET_CMD='import socket; s=socket.socket(); s.settimeout(2); s.connect(("example.com",80))'
if openshell exec -- python3 -c "$PYTHON_SOCKET_CMD" 2>&1 | grep -qi "denied\|blocked\|refused\|timeout\|error\|errno"; then
  pass "Python raw socket was blocked"
elif ! openshell exec -- which python3 &>/dev/null; then
  skip "python3 not available in sandbox"
else
  fail "Python raw socket was NOT blocked"
fi

echo ""

# --- Summary ---
echo "=== Summary ==="
echo -e "  ${GREEN}PASS${NC}: $PASS"
echo -e "  ${RED}FAIL${NC}: $FAIL"
echo -e "  ${YELLOW}SKIP${NC}: $SKIP"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}Some tests failed. Review sandbox policy configuration.${NC}"
  exit 1
else
  echo -e "${GREEN}All executed tests passed.${NC}"
  exit 0
fi
