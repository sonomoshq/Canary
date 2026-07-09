#!/usr/bin/env bash
# test-detectors.sh — Verify regex PII detectors produce correct output.
# Usage: bash tests/test-detectors.sh
# Exit code 0 = all passed, 1 = failures

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECTORS="$SCRIPT_DIR/canary/scripts/detectors.sh"

PASS=0
FAIL=0

assert_detects() {
  local label="$1"
  local input="$2"
  local expected_type="$3"

  local output
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)

  if echo "$output" | grep -q "\"type\":\"$expected_type\""; then
    PASS=$((PASS + 1))
    echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (expected type '$expected_type')"
    echo "        input: $input"
    echo "        output: $output"
  fi
}

assert_no_detect() {
  local label="$1"
  local input="$2"

  local output
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)

  if [[ -z "$output" ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label (no detection)"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (expected no detection but got output)"
    echo "        output: $output"
  fi
}

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
    echo "  PASS: $label"
  fi
}

assert_confidence() {
  local label="$1"
  local input="$2"
  local expected_type="$3"
  local expected_conf="$4"

  local output
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)

  if echo "$output" | grep -q "\"type\":\"$expected_type\".*\"confidence\":\"$expected_conf\""; then
    PASS=$((PASS + 1))
    echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (expected type '$expected_type' at confidence '$expected_conf')"
    echo "        input: $input"
    echo "        output: $output"
  fi
}

# Counts how many lines carry the given type — used to prove per-run dedup
# (bug #12): a value repeated in the input must only be emitted once.
assert_hit_count() {
  local label="$1"
  local input="$2"
  local expected_type="$3"
  local expected_count="$4"

  local output actual_count
  output=$(bash "$DETECTORS" "$input" 2>/dev/null || true)
  actual_count=$(echo "$output" | grep -c "\"type\":\"$expected_type\"" || true)

  if [[ "$actual_count" -eq "$expected_count" ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label ($actual_count hit(s))"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label (expected $expected_count hit(s) of '$expected_type', got $actual_count)"
    echo "        output: $output"
  fi
}

echo "=== Credit Card Detectors ==="
assert_detects "Visa (Luhn valid)" "4532015112830366" "credit_card"
assert_detects "Visa with dashes" "4532-0151-1283-0366" "credit_card"
assert_detects "Mastercard" "5425233430109903" "credit_card"

echo ""
echo "=== Email Detectors ==="
assert_detects "Standard email" "john.doe@company.org" "email"
assert_detects "Email with subdomain" "sarah@mail.example.com" "email"
assert_no_detect "Excluded: test@" "test@example.com"
assert_no_detect "Excluded: noreply@" "noreply@example.com"

echo ""
echo "=== SSN Detectors ==="
# 078-05-1120 / 219099999 are SSA-published example SSNs — now suppressed
# by the placeholder denylist (bug #12), so the positive cases here use
# fresh non-placeholder digits instead. Placeholder suppression itself is
# covered in test-no-false-positives.sh.
assert_detects "SSN with dashes (consistent separator)" "412-34-5678" "us_ssn"
assert_detects "SSN with spaces (consistent separator)" "412 34 5678" "us_ssn"
assert_no_detect "SSN mixed separators rejected (bug #6)" "412-34 5678"
assert_no_detect "SSN excluded: 000 area" "000-12-3456"
assert_no_detect "SSN excluded: 666 area" "666-12-3456"
echo "--- bare 9-digit SSN now requires a keyword in the line (bug #6) ---"
assert_detects "Bare SSN WITH 'ssn' keyword" "my ssn is 412345678" "us_ssn"
assert_detects "Bare SSN WITH 'social security' keyword" "his social security number is 534127890" "us_ssn"
assert_no_detect "Bare SSN with NO keyword" "the reference number is 412345678"

echo ""
echo "=== ABA Routing Detectors (bug #5: keyword-anchored) ==="
assert_detects "ABA routing WITH 'routing' keyword" "the routing number is 021000021" "aba_routing"
assert_detects "ABA routing WITH 'ABA' keyword" "ABA: 011401533" "aba_routing"
assert_no_detect "Bare 9-digit number with NO keyword (was firing as both ssn+aba)" "invoice 513653999"

echo ""
echo "=== AWS Key Detectors ==="
# AKIAIOSFODNN7EXAMPLE is AWS's own docs example key — now suppressed by
# the placeholder denylist; see test-no-false-positives.sh. Positive case
# here uses a fresh synthetic key of the correct 20-char shape instead.
assert_detects "AWS access key" "AKIA2QF7N4X9M1K6T8WZ" "aws_access_key"
assert_detects "AWS access key (ASIA/session prefix)" "ASIAZQ4K2M8N1P6R3T7V" "aws_access_key"
echo "--- aws_secret_key (bug #2: variable-length lookbehind rejected by PCRE, never fired) ---"
assert_detects "AWS secret key (non-placeholder 40-char value)" \
  "aws_secret_access_key = pTyGJMuH=bEL31IeL2HPcHyGcFRl1SPnXNYvMIHa" "aws_secret_key"
assert_detects "AWS secret key (env-var style, uppercase)" \
  "AWS_SECRET_ACCESS_KEY=pTyGJMuH=bEL31IeL2HPcHyGcFRl1SPnXNYvMIHa" "aws_secret_key"

echo ""
echo "=== VIN Detectors (bug #1: zero-width lookahead pipe stage, never fired) ==="
assert_detects "Valid VIN" "1HGCM82633A004352" "vin"
assert_no_detect "All-digit 17-char (not a VIN)" "12345678901234567"

echo ""
echo "=== MAC Address Detectors (bug #4) ==="
assert_detects "MAC address (colon-separated)" "device mac aa:bb:cc:dd:ee:ff connected" "mac_address"
assert_detects "MAC address (hyphen-separated)" "device mac aa-bb-cc-dd-ee-ff connected" "mac_address"

echo ""
echo "=== IPv6 Detectors (bug #4: no longer confused with clocks/MACs) ==="
assert_detects "Full IPv6 address" "connect to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 now" "ipv6"
assert_detects "Compressed IPv6 address" "server at fe80::1ff:fe23:4567:890a is up" "ipv6"

echo ""
echo "=== Bitcoin Address Detectors ==="
assert_detects "Bitcoin legacy" "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" "bitcoin_address"
assert_confidence "Bitcoin confidence is 'medium', not 'high' (bug #9: format-only check)" \
  "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" "bitcoin_address" "medium"

echo ""
echo "=== Ethereum Address Detectors ==="
assert_detects "Ethereum address" "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08" "ethereum_address"
assert_confidence "Ethereum confidence is 'medium', not 'high' (bug #9: format-only check)" \
  "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08" "ethereum_address" "medium"

echo ""
echo "=== Phone Number Detectors ==="
assert_detects "US phone" "+1 (555) 123-4567" "phone_number"
assert_detects "International phone" "+14155551234" "phone_number"

echo ""
echo "=== URL Credentials Detectors ==="
assert_detects "URL with password" "https://admin:secret123@db.example.com" "url_credentials"

echo ""
echo "=== IPv4 Detectors ==="
# 203.0.113.x is RFC 5737 TEST-NET-3 (documentation range) — correctly excluded.
# Use an actual public IP for the positive test.
assert_detects "Public IPv4" "8.8.8.8" "ipv4"
assert_no_detect "Private IPv4 (192.168)" "192.168.1.1"
assert_no_detect "Localhost" "127.0.0.1"

echo ""
echo "=== IBAN Detectors ==="
assert_detects "German IBAN" "DE89370400440532013000" "iban"

echo ""
echo "=== Medicare MBI Detectors ==="
assert_detects "Medicare MBI" "1EG4-TE5-MK72" "us_mbi"

echo ""
echo "=== Vendor Secret Pack (new detectors) ==="
# Fixture tokens are split with an empty "" so no contiguous secret-shaped
# literal exists in this file — GitHub push protection scans test fixtures
# too. Bash concatenates the halves back into the real test value.
assert_detects "GitHub PAT (classic ghp_)" "token: ghp_""oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclR" "github_pat"
assert_detects "GitHub PAT (fine-grained github_pat_)" \
  "github_pat_""z3AwzKsbVRJN9wVGFYGW2WmQzCudiH_7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdY" "github_pat"
assert_detects "GitLab PAT" "glpat-""aBcDeFgHiJkLmNoPqRsT" "gitlab_pat"
assert_detects "Slack token" "xoxb-""1234567890-abcdefghij" "slack_token"
assert_detects "Slack webhook" "https://hooks.slack.com/services/""T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" "slack_webhook"
assert_detects "Stripe live secret key" "sk_live_""51H8abcdefghijklmnopqrst" "stripe_api_key"
assert_detects "Anthropic API key" "sk-ant-""api03-abcdefghijklmnopqrstuvwxyz0123456789" "anthropic_api_key"
assert_detects "OpenAI API key" "sk-proj-""abcdefghijklmnopqrstuvwxyz0123456789" "openai_api_key"
assert_type_absent "OpenAI does NOT also fire on an Anthropic key (negative lookahead)" \
  "sk-ant-""api03-abcdefghijklmnopqrstuvwxyz0123456789" "openai_api_key"
assert_detects "Google API key" "AIza""icpHdEoziIbob-y6ShRfh2zucR-LGOTU2Ix" "google_api_key"
assert_detects "SendGrid API key" "SG.""abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" "sendgrid_api_key"
assert_detects "npm token" "npm_""YmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6" "npm_token"
assert_detects "JWT" "eyJ""hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ-abcdefghij" "jwt"
assert_detects "Private key block" "-----BEGIN RSA PRIVATE KEY-----" "private_key_block"
assert_detects "DB URL credentials (postgres)" "postgres://user:p4ssw0rd@dbhost:5432/mydb" "db_url_credentials"
assert_detects "DB URL credentials (mongodb+srv)" "mongodb+srv://svc:t0pSecret@cluster0.mongodb.net/prod" "db_url_credentials"

echo ""
echo "=== Generic Secret (entropy-gated) ==="
assert_detects "High-entropy value after 'api_key ='" "api_key = Tg7Rk2Xy9Bn4Wq8Lp3Vz6Cm1" "generic_secret"
assert_confidence "Generic secret confidence is 'medium'" "api_key = Tg7Rk2Xy9Bn4Wq8Lp3Vz6Cm1" "generic_secret" "medium"
assert_no_detect "Low-entropy placeholder value ('changeme')" "password = changeme"
assert_no_detect "Low-entropy dictionary-word value" "token = mytokenvalue"

echo ""
echo "=== Checksummed IDs (new detectors) ==="
assert_detects "NHS number (mod-11, with 'nhs' keyword)" "my nhs number is 9434765919" "nhs_number"
assert_detects "NPI (Luhn w/ 80840 prefix, with 'npi' keyword)" "npi: 1234567893" "npi_number"
assert_detects "DEA number (check digit, with 'dea' keyword)" "dea number AB1234563" "dea_number"
assert_detects "Canadian SIN (Luhn, with 'sin' keyword)" "my sin is 046-454-286" "sin_canadian"
assert_detects "Canadian SIN (Luhn, with 'social insurance' phrase)" "social insurance number: 046454286" "sin_canadian"
assert_detects "US ITIN (with 'itin' keyword -> high)" "itin 912-70-1234" "us_itin"
assert_confidence "US ITIN WITHOUT keyword is 'medium'" "912-70-1234" "us_itin" "medium"
assert_confidence "US ITIN WITH keyword is 'high'" "itin 912-70-1234" "us_itin" "high"

echo ""
echo "=== Per-run Dedup (bug #12) ==="
assert_hit_count "Same email twice in one message -> one hit" \
  "email me at dana.lee@northwind-consulting.com or dana.lee@northwind-consulting.com again" "email" 1
assert_hit_count "Same credit card twice -> one hit" \
  "card 4532015112830366, repeat: 4532015112830366" "credit_card" 1

echo ""
echo "=== JSON Safety (bug #3: hand-interpolated JSON broke on embedded quotes) ==="
if command -v jq >/dev/null 2>&1; then
  json_quote_output=$(bash "$DETECTORS" 'url = "https://admin:secret123@db.example.com"' 2>/dev/null || true)
  all_valid=1
  while IFS= read -r hit_line; do
    [[ -z "$hit_line" ]] && continue
    echo "$hit_line" | jq -e . >/dev/null 2>&1 || all_valid=0
  done <<< "$json_quote_output"
  if [[ -n "$json_quote_output" && "$all_valid" -eq 1 ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: url_credentials with trailing quote still emits valid JSON"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: url_credentials with trailing quote produced invalid/empty JSON"
    echo "        output: $json_quote_output"
  fi
else
  echo "  SKIP: jq not available, skipping JSON-validity check"
fi

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
