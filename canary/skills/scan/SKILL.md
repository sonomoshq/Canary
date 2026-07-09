---
name: scan
description: Use when the user worries they pasted a secret, asks "did I leak anything?", or wants a full-history privacy audit — the automatic scan only covers the latest message.
disable-model-invocation: false
user-invocable: true
argument-hint: "[full|quick]"
allowed-tools: Bash(cat:*), Bash(jq:*), Bash(echo:*), Bash(wc:*), Bash(python3:*), Bash(ls:*)
---

# Sonomos LLM PII Scan

Scan your own conversation history for sensitive data that regex pattern matching cannot catch.

## Instructions

1. Find the transcript. List recent transcripts and pick the most recently modified one:

```bash
ls -t ~/.claude/projects/*/*.jsonl 2>/dev/null | head -5
```

The first line is the most recently modified transcript — use that one (if it's empty or unreadable, fall back to the next one in the list). Its filename stem (the part before `.jsonl`) is the session UUID — remember it as SESSION_ID for step 4.

2. Extract user message text from that transcript with this jq filter:

```bash
jq -r 'select(.type == "user") | .message.content | if type=="string" then . elif type=="array" then ([.[] | select(.type=="text") | .text] | join("\n")) else empty end' "$LATEST" 2>/dev/null
```

Honor `$ARGUMENTS`:
- `quick` (or no argument): only the last ~6000 characters of that output — pipe through `tail -c 6000`.
- `full`: ALL of it, every user message in the transcript. This is you reading and reasoning over the text, not a script — if it's long, work through it in batches mentally rather than truncating.

3. Scan that text yourself. Look for ALL of the following categories. For each item found, you'll record a hit (step 4).

### Identity
name, entity_name, us_passport, date_of_birth, us_ein_fein, national_id, tin_non_us, nhs_number, sin_canadian, us_itin, passport_non_us, license_plate

### Financial
us_bank_account, swift_bic

### Crypto
private_key, seed_phrase, wallet_key, xpub_key, monero_address, ripple_address, solana_address, metamask_key, exchange_api_key, txid, private_key_hex

### Legal
case_number, attorney_number, court_order, litigation_id, contract_number, patent_number, trademark, legal_entity, settlement_ref, subpoena, deposition, evidence_id, witness_id, filing_number

### Medical
medical_record_mrn, health_plan_id, dea_number, npi_number, diagnosis_code_icd10, procedure_code_cpt

### Technical
jwt, oauth_token, gcp_key, azure_key, generic_secret, generic_api_key, mac_address, geolocation, uuid, imei, serial_number, android_id, iphone_udid, github_pat, slack_token, stripe_api_key, twilio_credentials, sendgrid_api_key, private_key_hex

### Location
street_address, zip_code

### Organizational (high-risk semantic categories)
- **customer_data**: data clearly belonging to a specific customer/client
- **employee_data**: employee names with roles, salaries, reviews, HR info
- **third_party_data**: business partners' or vendors' internal info
- **trade_secret**: proprietary algorithms, formulas, unreleased product details, internal metrics
- **internal_comms**: internal emails, Slack messages, meeting notes with sensitive content
- **credentials_compound**: username+password pairs, connection strings with auth
- **financial_records**: revenue, salary data, pricing strategies, investor info

4. For each PII item found, redact the value (keep first 2 and last 2 chars, replace middle with dots), then record the hit:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/record-llm-hit.sh" "<category>" "<redacted>" "<high|medium>" "<SESSION_ID>"
```

Pass SESSION_ID (from step 1) as the 4th argument whenever you have it. Omit the 4th argument only if you couldn't determine it.

5. Report a summary: how many new items were found, a breakdown by category, and the current running total from the leaks file (`wc -l` on `${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}/leaks.jsonl`).

6. End your reply with exactly one machine-parseable status line:
   - `LEAK_SCAN: CLEAN` if nothing was found, or
   - `LEAK_SCAN: FOUND <n> item(s) — <type list>` (e.g. `LEAK_SCAN: FOUND 3 item(s) — name, us_passport, trade_secret`)

## Important
- NEVER output raw PII values. Always redact: `jo••••oe`, `12••••89`, etc.
- Focus on real PII, not example data, code variable names, or documentation references.
- Be conservative — medium/high confidence only. Don't flag generic words as names.
- If NO PII is found, say so clearly — that's a good result, and still end with `LEAK_SCAN: CLEAN`.
- Copyright © 2026 Sonomos Inc. All rights reserved.
