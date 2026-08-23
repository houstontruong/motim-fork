# Motim Phase B Remediation Note (Round 2 Fixes)

## Overview & Scope
- **Audit Finding**: C4 / H2 — CLI cURL \export\ and display paths outputting unredacted headers, URLs, and payloads.
- **Repository**: \C:\Users\houst\PycharmProjects\motim-fork- **Target**: Ensure \export\, \show\, \cat\, \diff\, \search\, \round\, \session\, and \services samples\ strictly apply defense-in-depth redaction to headers, query strings, URLs, and body payloads, preventing live replay of stored credentials even if seeded directly in SQLite.

---

## Changes Implemented

### 1. CLI Export & Display Sanitization (\motim/cli/main.py\)
- **\export\ command**:
  - Filtered hop-by-hop headers (\host\, \content-length\, \connection\, etc.).
  - Forced every request header through edactor.redact_header_value()\ (e.g. \Bearer [REDACTED]\, \session=[REDACTED]\, \[REDACTED]\).
  - Passed request body through edactor.redact_body_bytes()\ and edactor.redact_data_structure()\.
  - Sanitized target URL via edactor.redact_url()\.
- **\show\ command**:
  - Enforced redaction on request/response headers, body payloads (both raw bytes and JSON/text structures), URLs, and query parameters for both human-readable text and \--json\ machine-readable outputs.
- **\cat\ command**:
  - Enforced edactor.redact_body_bytes()\ and edactor.redact_data_structure()\ across dumped request/response bodies.
- **\search\, \round\, and \session\ commands**:
  - Enforced URL and query string sanitization across all returned exchange items and slices.

### 2. Structured Diff Sanitization (\motim/diff.py\)
- Integrated \get_redactor()\ into \diff_exchanges()\ to ensure header diffs and URL attributes never expose raw credentials.

### 3. Service Commands (\motim/cli/services.py\)
- Enforced URL and query parameter redaction on \samples\ command output.

---

## Regression Tests Added

1. **Gate 1 AST & Replay Prevention (\	ests/test_gates.py\)**:
   - Added \	est_export_curl_redaction_prevents_credential_replay\: Seeds raw Bearer tokens, session cookies, API keys, password payloads, client secrets, and query parameters directly into SQLite via SQL, runs \motim export\, and asserts that zero raw secrets are emitted while \[REDACTED]\ and \Bearer [REDACTED]\ are present.
2. **Defense-in-Depth CLI Test Suite (\	ests/test_cli.py\)**:
   - Added \TestCliSanitizationDefenseInDepth\ testing \export\, \show\ (text + JSON), \cat\ (request + response), \diff\, \search\, and \session\ against an unredacted raw SQLite database.

---

## Test Verification

- **Command**: \pytest -q- **Result**: \ passed\ (100% green)

---

## Git Status & Push
- Conventional commit: \ix(security): sanitize CLI export and display paths against credential replay- All changes staged and committed on \main\.
