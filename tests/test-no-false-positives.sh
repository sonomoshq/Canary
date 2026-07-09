#!/usr/bin/env bash
# test-no-false-positives.sh — Verify code samples and documentation don't trigger detectors.
# Usage: bash tests/test-no-false-positives.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECTORS="$SCRIPT_DIR/canary/scripts/detectors.sh"

PASS=0
FAIL=0

assert_no_detect() {
  local label="$1"
  local input="$2"

  local output
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)

  if [[ -z "$output" ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label (no false positive)"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (false positive detected)"
    echo "        input: $input"
    echo "        output: $output"
  fi
}

# For cases where the input legitimately produces SOME hit (e.g. a MAC
# address correctly firing mac_address) but a specific type must be
# absent from the output (e.g. that same value must not ALSO be reported
# as ipv6). Plain assert_no_detect can't express this since it requires
# zero output.
assert_type_absent() {
  local label="$1"
  local input="$2"
  local absent_type="$3"

  local output
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)

  if echo "$output" | grep -q "\"type\":\"$absent_type\""; then
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (type '$absent_type' should not have appeared)"
    echo "        input: $input"
    echo "        output: $output"
  else
    PASS=$((PASS + 1))
    echo "  PASS: $label (no false positive)"
  fi
}

echo "=== Code Variable Names ==="
assert_no_detect "Variable email" 'email_address = "placeholder"'
assert_no_detect "Function name" "def validate_credit_card(number):"
assert_no_detect "Config key" "AWS_ACCESS_KEY_ID="

echo ""
echo "=== Documentation Text ==="
assert_no_detect "SSN format description" "SSN format is XXX-XX-XXXX"
assert_no_detect "Example placeholder" "Enter your email: user@example.com"
assert_no_detect "IP documentation range" "10.0.0.1 is a private network address"
assert_no_detect "Localhost reference" "Connect to 127.0.0.1:8080"

echo ""
echo "=== Common Non-PII Patterns ==="
assert_no_detect "Version number" "v2.1.0"
assert_no_detect "Date string" "2026-04-14"
assert_no_detect "UUID" "550e8400-e29b-41d4-a716-446655440000"
assert_no_detect "Short number" "12345"
assert_no_detect "Noreply email" "noreply@service.com"

echo ""
echo "=== Private/Reserved IPs ==="
assert_no_detect "Private 192.168" "192.168.1.100"
assert_no_detect "Private 10.x" "10.0.0.50"
assert_no_detect "Loopback" "127.0.0.1"

echo ""
echo "=== Clock Times / MAC Addresses vs IPv6 (bug #4) ==="
assert_no_detect "Plain clock time HH:MM:SS" "the meeting is at 10:30:45"
assert_no_detect "Clock time in a sentence" "please arrive by 09:15:00 sharp"
assert_type_absent "MAC address is not also reported as ipv6" \
  "device mac aa:bb:cc:dd:ee:ff is connected" "ipv6"

echo ""
echo "=== Bare Numeric Collisions (bugs #5 and #6) ==="
assert_no_detect "Bare 9-digit order number, no ssn/routing keyword" "about order 513653999 thanks"
assert_no_detect "Bare 9-digit invoice number, no keyword" "invoice number 123456780 is overdue"

echo ""
echo "=== URL Credentials False Positives (bug #7) ==="
assert_no_detect "Port number is not userinfo" "https://github.com:443/a/b@main"
assert_no_detect "Port + path + trailing @ segment" "visit https://example.com:8080/status@ok for health"

echo ""
echo "=== Email RFC 2606 Reserved Domains (bug #8) ==="
assert_no_detect "example.com" "alice.smith@example.com"
assert_no_detect "example.net" "bob@example.net"
assert_no_detect "example.org" "carol@example.org"
assert_no_detect ".test TLD" "contact team@myapp.test for support"
assert_no_detect ".invalid TLD" "sender@mail.invalid bounced"
assert_no_detect ".localhost TLD" "dev@app.localhost is a dev box"

echo ""
echo "=== Placeholder / Documentation Values Suppressed (denylist) ==="
assert_no_detect "Visa test PAN 4111...1111" "4111111111111111"
assert_no_detect "Visa test PAN 4242...4242" "4242424242424242"
assert_no_detect "Mastercard test PAN 5555...4444" "5555555555554444"
assert_no_detect "Amex test PAN 378282246310005" "378282246310005"
assert_no_detect "SSA example SSN 078-05-1120" "078-05-1120"
assert_no_detect "SSA example SSN 219099999 (with keyword)" "my ssn is 219099999"
assert_no_detect "AWS docs example access key" "AKIAIOSFODNN7EXAMPLE"
assert_no_detect "AWS docs example secret key" \
  "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
assert_no_detect "NANP reserved fictional phone 555-01xx" "call 555-555-0199 now"
assert_no_detect "All-repeated-digit 'card number'" "card 0000000000000000"

echo ""
echo "=== Vendor Secret Cross-Matching (bug: openai must not match sk-ant-) ==="
assert_type_absent "Anthropic key alone produces no openai_api_key hit" \
  "sk-ant-""api03-abcdefghijklmnopqrstuvwxyz0123456789" "openai_api_key"

echo ""
echo "=== Generic Secret Entropy Gate ==="
assert_no_detect "Low-entropy placeholder password" "password = changeme"
assert_no_detect "Low-entropy dictionary-word token" "token = mytokenvalue"
assert_no_detect "All-lowercase sequential value (high entropy but not secret-shaped)" "api_key = abcdefghijklmnop"

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
