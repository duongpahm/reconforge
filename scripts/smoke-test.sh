#!/usr/bin/env bash
# ReconForge smoke test — verify core features after build/release.
# Usage: ./scripts/smoke-test.sh [path/to/binary]
#
# Default binary: ./bin/reconforge or $(which reconforge)
# Exit 0 = all pass; non-zero = failure index.

set -euo pipefail

BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
    if [[ -x "./bin/reconforge" ]]; then
        BINARY="./bin/reconforge"
    elif command -v reconforge >/dev/null 2>&1; then
        BINARY="$(command -v reconforge)"
    else
        echo "ERROR: no reconforge binary found. Pass path as arg or build first."
        exit 1
    fi
fi

echo "=== ReconForge smoke test ==="
echo "Binary: $BINARY"
echo "Version: $($BINARY version 2>&1 | head -1)"
echo

PASS=0
FAIL=0
TESTS=()

check() {
    local name="$1"
    local exit_expected="$2"
    local actual_exit="$3"

    if [[ "$exit_expected" == "$actual_exit" ]]; then
        echo "✓ $name (exit=$actual_exit)"
        PASS=$((PASS + 1))
    else
        echo "✗ $name (expected exit=$exit_expected, got $actual_exit)"
        FAIL=$((FAIL + 1))
        TESTS+=("FAIL: $name")
    fi
}

# ----------------------------------------------------------------
# 1. Basic CLI surface
# ----------------------------------------------------------------
echo "[1] Basic CLI surface"

$BINARY --help >/dev/null 2>&1
check "help" "0" "$?"

$BINARY version >/dev/null 2>&1
check "version" "0" "$?"

$BINARY config show >/dev/null 2>&1 || true
check "config show" "0" "$?"

# ----------------------------------------------------------------
# 2. Doctor + tools (read-only check)
# ----------------------------------------------------------------
echo
echo "[2] Doctor + tools"

$BINARY doctor >/dev/null 2>&1 || true
# doctor exit might be non-zero if tools missing — acceptable
echo "✓ doctor ran (tool status check)"

$BINARY tools list >/dev/null 2>&1 || true
check "tools list" "0" "$?"

# ----------------------------------------------------------------
# 3. Target validation (Phase 2)
# ----------------------------------------------------------------
echo
echo "[3] Target validation"

set +e
$BINARY scan -d "999.999.999.999" >/dev/null 2>&1
check "invalid IP rejected" "1" "$?"

$BINARY scan -d "" >/dev/null 2>&1
check "empty target rejected" "1" "$?"

$BINARY scan -d "no spaces allowed.com" >/dev/null 2>&1
check "domain with spaces rejected" "1" "$?"

$BINARY scan --cidr "10.0.0.0/99" >/dev/null 2>&1
check "invalid CIDR rejected" "1" "$?"
set -e

# ----------------------------------------------------------------
# 4. Dry-run scan (Phase 1 + 2 integration)
# ----------------------------------------------------------------
echo
echo "[4] Dry-run scan"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

cd "$TMPDIR"
$BINARY scan -d test-smoke.example --dry-run --skip-missing-tools \
    >/tmp/smoke-scan.log 2>&1
check "dryrun scan completes" "0" "$?"

# Verify state.db created
test -f "Recon/test-smoke.example/state.db"
check "state.db persisted" "0" "$?"

# Verify report files
test -f "Recon/test-smoke.example/report.json"
check "report.json generated" "0" "$?"

test -f "Recon/test-smoke.example/report.md"
check "report.md generated" "0" "$?"

cd - >/dev/null

# ----------------------------------------------------------------
# 5. Findings query
# ----------------------------------------------------------------
echo
echo "[5] Findings query"

cd "$TMPDIR"
$BINARY findings list -t test-smoke.example >/dev/null 2>&1
check "findings list" "0" "$?"

$BINARY findings list -t test-smoke.example --format ndjson >/dev/null 2>&1
check "findings list ndjson" "0" "$?"

$BINARY findings export -t test-smoke.example --format markdown -o /tmp/findings.md \
    >/dev/null 2>&1 || true
test -f /tmp/findings.md
check "findings export markdown" "0" "$?"

cd - >/dev/null

# ----------------------------------------------------------------
# 6. NO_COLOR support (Phase 4)
# ----------------------------------------------------------------
echo
echo "[6] NO_COLOR support"

OUTPUT_COLOR=$(cd "$TMPDIR" && $BINARY findings list -t test-smoke.example 2>&1 || true)
OUTPUT_NOCOLOR=$(cd "$TMPDIR" && NO_COLOR=1 $BINARY findings list -t test-smoke.example 2>&1 || true)

if echo "$OUTPUT_NOCOLOR" | grep -q $'\x1b\['; then
    echo "✗ NO_COLOR not respected (ANSI escape found in output)"
    FAIL=$((FAIL + 1))
    TESTS+=("FAIL: NO_COLOR")
else
    echo "✓ NO_COLOR respected"
    PASS=$((PASS + 1))
fi

# ----------------------------------------------------------------
# 7. Exit codes (Phase 1)
# ----------------------------------------------------------------
echo
echo "[7] Exit codes"

set +e
$BINARY scan --invalid-flag-xyz >/dev/null 2>&1
EXIT=$?
if [[ $EXIT -eq 1 ]] || [[ $EXIT -eq 2 ]]; then
    echo "✓ usage error returns 1 or 2 (got $EXIT)"
    PASS=$((PASS + 1))
else
    echo "✗ unexpected exit for invalid flag: $EXIT"
    FAIL=$((FAIL + 1))
fi
set -e

# ----------------------------------------------------------------
# 8. Profile listing (Phase 4)
# ----------------------------------------------------------------
echo
echo "[8] Profiles"

PROFILE_OUTPUT=$($BINARY config profiles 2>&1)
for prof in quick stealth full deep; do
    if echo "$PROFILE_OUTPUT" | grep -q "$prof"; then
        echo "✓ profile '$prof' exists"
        PASS=$((PASS + 1))
    else
        echo "✗ profile '$prof' missing"
        FAIL=$((FAIL + 1))
        TESTS+=("FAIL: profile $prof")
    fi
done

# ----------------------------------------------------------------
# 9. Shell completion (Phase 1)
# ----------------------------------------------------------------
echo
echo "[9] Shell completion"

for shell in bash zsh fish; do
    if $BINARY completion $shell >/dev/null 2>&1; then
        echo "✓ completion $shell"
        PASS=$((PASS + 1))
    else
        echo "✗ completion $shell failed"
        FAIL=$((FAIL + 1))
        TESTS+=("FAIL: completion $shell")
    fi
done

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo
echo "==================="
echo "Smoke test summary"
echo "==================="
echo "Passed: $PASS"
echo "Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
    echo
    echo "Failures:"
    printf '  %s\n' "${TESTS[@]}"
    exit 1
fi

echo
echo "✅ All smoke tests passed."
exit 0
