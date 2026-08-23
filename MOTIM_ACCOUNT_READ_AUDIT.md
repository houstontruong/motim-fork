# Motim Account-Read Reconciliation — Codex Audit Fix Round

**Audited commit:** `9681bbc` (base `7a92a1e`)
**Independent test reproduction:** clean venv, `161 passed in 1.94s`
**Status:** NOT complete — fix every item below and add a regression test for each.

## Required fixes

### HIGH — duplicate JSON keys can bypass secret rejection

`motim/reconcile/engine.py:95` uses ordinary `json.loads`. Python accepts duplicate object keys and retains only the last one. A raw JSONL record can therefore contain an earlier credential-bearing `request`/`response` that gets overwritten by a later sanitized duplicate before validation sees it.

Reject duplicate JSON object keys at parse time (via `object_pairs_hook` or equivalent), at every nesting level, with a structured redacted `invalid_input` result. Add fixtures/tests covering duplicate top-level and nested `request`/`response` keys containing unique secret sentinels; neither the output nor error must expose a sentinel.

### HIGH — deduplication makes staleness input-order dependent

`motim/reconcile/dedup.py:55` compares exact duplicates without `observed_at` and keeps the first fact at line 73. The same fact recorded at different times can be classified stale or fresh based only on file order.

Define and implement deterministic temporal semantics: for exact semantic duplicates, retain the latest `observed_at` fact (and union source exchange IDs); conflicting duplicates must stay unresolved. Add a reversed-input regression test that asserts identical facts and staleness output.

### MEDIUM — non-finite numeric values violate the decimal contract

`motim/reconcile/decimal_util.py:24` accepts `NaN`, `Infinity`, and `-Infinity` through Python JSON/Decimal handling and emits them as strings.

Reject non-finite values during JSON parse and decimal normalization, returning redacted `invalid_input`/structured outcome. Add tests for all three forms.

### MEDIUM — negative max age crashes outside the CLI taxonomy

`motim/cli/reconcile_cmd.py:45` accepts negative `--max-age-seconds`; `staleness.py:29` raises uncaught `ValueError`, yielding an exit-1 traceback/no result JSON.

Reject negative values at Click validation and library API validation, with the documented `invalid_input` result and exit 4. Test both surfaces.

### MEDIUM — boolean response status passes integer validation

`motim/reconcile/validator.py:231` uses `isinstance(status, int)`; JSON `true` is a Python `bool`, hence accepted.

Require `type(status) is int` (or an equivalent JSON-integer check) and add a `true` fixture test.

### MEDIUM — direct JSONL strings can throw during path probing

`motim/reconcile/engine.py:40` calls `Path(exchanges).exists()` outside error handling. A long direct JSONL string may raise `OSError: File name too long` rather than return a structured invalid result.

Safely distinguish a local path from literal JSONL without unguarded filesystem probing; add a long-string regression test.

### LOW — syntax line numbers lose leading blank lines

`motim/reconcile/engine.py:78` strips the whole input before `splitlines()`, shifting physical line numbers.

Preserve source line numbering (or explicitly document otherwise) and add a leading-blank-line syntax-error test.

## Required verification

1. Run the targeted new regressions and the whole test suite.
2. Update `motim-account-read-report.md` to correct any overclaim and list the fix commit/test output.
3. Commit and push the fix on `main`.
4. Do not alter the offline-only safety boundary or broaden into capture/live-account work.

If you see a better approach than this brief describes, say so and explain why before changing direction.

## Round 2 — Required follow-up after `770f700`

The first remediation fixed the original 7 findings and passed 171 clean-venv tests, but a fresh Codex audit found three remaining edge cases. Fix all three with regressions:

1. **MEDIUM — iterable/dict API values bypass non-finite rejection** (`motim/reconcile/engine.py:265`). Raw JSON input rejects `NaN`/`Infinity`, but direct iterable/dict library inputs can carry nested non-finite values through validation. Apply one recursive finite-value validation rule before adapter dispatch for both input forms. It must return the structured `invalid_input` outcome without leaking values.
2. **MEDIUM — library `max_age_seconds` accepts non-integer/non-finite numbers** (`motim/reconcile/engine.py:189`). Enforce a finite, non-negative integer at the library boundary; reject floats including `NaN`/infinity with `invalid_input`. Keep the CLI and API semantics aligned.
3. **LOW — ambiguous valid file paths are treated as literal JSONL** (`motim/reconcile/engine.py:62`). Preserve literal-JSONL support without making existing paths inaccessible merely because their names begin with `{` or contain a newline. Prefer a safe `Path.exists()` attempt with `OSError` handling before choosing literal parsing, then add a regression test.

Update the report, run the full suite, commit/push, and request the same final verification. Do not broaden scope.

## Round 3 — Required follow-up after `e4a3d6f`

Fix all four findings with targeted regressions:

1. **HIGH — direct API secret scan skips tuples/sets** (`validator.py:78`). `contains_auth_elements` must recurse through every accepted container type, or the direct API must strictly normalize/reject non-JSON containers before scanning. A nested tuple/set containing secret-shaped data must return `invalid_input` and never expose the sentinel.
2. **MEDIUM — literal JSONL conflicts with an existing filename** (`engine.py:62`). Define deterministic interpretation. A literal JSON/JSONL string must never silently read a same-named file. Prefer explicit `Path` objects for file inputs and treat strings as literal input, or provide an explicit safe file-input surface; preserve the CLI's Path behavior. Test a working-directory file named `{}` plus a literal `{}` input.
3. **MEDIUM — datetime `as_of` is falsely labeled UTC** (`engine.py:206`). Require an aware UTC datetime, or convert aware non-UTC values to UTC before serializing. Reject naïve values. Test naïve, non-UTC aware, and UTC values with their correct staleness behavior.
4. **LOW — invalid direct API types bypass taxonomy** (`engine.py:184`). Non-string provider and non-iterable exchanges must return structured `invalid_input`, not raise. Add tests.

## Round 4 — Required follow-up after `3ec9aa6`

Fix both findings with targeted regressions:

1. **HIGH — nested authentication material fail-open** (`validator.py:18`). Reject authentication material key families (`signature`, `session_id`, `credentials`, `passphrase`) recursively with structured `invalid_input` and zero facts.
2. **MEDIUM — non-GET request methods accepted** (`validator.py:270`). Enforce normalized `GET`-only for `request.method`; reject mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) with `invalid_input`.

## Round 5 — Final Codex Remediation

Fix the remaining defect with targeted regressions:

1. **HIGH — nested authentication material fail-open for nonce** (`validator.py:18`). A syntactically valid `GET` record with `response.body.metadata.nonce` (or normalized variants such as `request_nonce`, `api_nonce`, `client_nonce`, `x-nonce`, `x_nonce`, `nonce_str`) must be rejected recursively with structured redacted `invalid_input` and zero facts.

## Round 6 — Redaction Consistency & Separator Normalization Remediation

Fix the remaining defect with targeted regressions:

1. **MEDIUM — redaction separator-normalization gap** (`motim/redact.py`). Synthetic keys `n_o_n_c_e` and `n-o-n-c-e` are rejected at reconciliation ingest, but could remain unredacted when `redact_header_value`, `redact_query_string`, or `redact_data_structure` is invoked independently. Apply a shared lowercase + hyphen/underscore-normalized sensitive-name match across all redaction paths.

## Round 7 — Final Confidentiality Remediation

Fix all four confidentiality findings with targeted regressions:

1. **HIGH — credential-bearing route key accepted and echoed in unsupported_schema** (`motim/reconcile/validator.py`, `adapters/bybit.py`, `adapters/lighter.py`). Reject credential-bearing URL/userinfo/query material before adapters can echo it; errors must be redacted and produce zero facts.
2. **MEDIUM — URL userinfo credentials visible in Redactor.redact_url()** (`motim/redact.py`). Sanitization must handle userinfo robustly (including URLs without query strings) as well as sensitive query fields.
3. **MEDIUM — Redactor.redact_data_structure() only traverses dict/list** (`motim/redact.py`). Make structural redaction safely recursive across mapping, tuple, set, and frozenset inputs without breaking deterministic or JSON-safe expectations.
4. **MEDIUM — Redactor.redact_body_bytes() preserves form auth fields when content type unknown** (`motim/redact.py`). Apply fail-closed treatment that masks sensitive key/value material without corrupting legitimate benign content.

## Round 8 — Confidentiality Remediation

Fix all three confidentiality findings with targeted regressions:

1. **HIGH — Fail-open unknown/generic bodies** (`motim/redact.py`). Support UTF-16 decoding with BOM preservation, sanitize colon-separated and generic key-value plain text bodies (e.g. `password: SECRET123`, `api_key: "abc"`), and enforce fail-closed sanitization for compressed or unparseable binary bodies (`b"[REDACTED: unparseable binary body]"`).
2. **HIGH — Percent-encoded key bypass** (`motim/reconcile/validator.py`, `motim/redact.py`). URL-decode query/fragment field names before sensitivity checks, rejecting any input with percent-encoded auth keys (such as `api%5Fkey=...`) with `invalid_input`, zero facts, and no canary leaks.
3. **MEDIUM — Fragment reflection** (`motim/reconcile/validator.py`, `adapters/bybit.py`, `adapters/lighter.py`). Inspect route `#` fragments for auth credentials during ingest validation and defensively strip `#` fragments, query parameters, and userinfo from unsupported route issue messages.

## Round 9 — Confidentiality Remediation

Fix both confidentiality findings with targeted regressions:

1. **HIGH — Fully percent-encoded structural delimiters can leak** (`motim/reconcile/validator.py`, `adapters/bybit.py`, `adapters/lighter.py`). Iteratively decode complete routes and segments before auth parsing to reject routes with encoded delimiters (e.g., `unsupported%3Fapi%5Fkey%3DTOPSECRET` or `unsupported%23token%3DTOPSECRET`) with `invalid_input` and zero facts, and defensively strip decoded structural delimiters from unsupported route messages.
2. **HIGH — BOM-less UTF-16/NUL-bearing body data can leak** (`motim/redact.py`). Detect NUL bytes and binary characteristics before plain text UTF-8 fallback; decode BOM-less UTF-16LE/BE via byte heuristics, sanitize credentials, and fail closed on arbitrary NUL-bearing binary payloads (`b"[REDACTED: unparseable binary body]"`).

## Round 10 — Deep-Encoding Remediation

Fix deep percent-encoding bypass finding with targeted regressions:

1. **HIGH — Deep percent-encoding bypass** (`motim/reconcile/validator.py`, `adapters/bybit.py`, `adapters/lighter.py`, `motim/redact.py`). Decode multi-layer percent-encoded strings to true fixpoint with input length-derived safe bound (`max(64, len(raw))`), fail closed on unresolved percent-encoding after the bounded decode limit (`_has_percent_encoding`), and defensively sanitize route issue messages in Bybit and Lighter adapters with `[REDACTED_ROUTE]` fallback.

## Round 11 — Bounded-Decoding Remediation

Fix malformed percent bypass and quadratic CPU cost findings with targeted regressions:

1. **HIGH — Malformed percent sequences bypass auth/redaction** (`motim/reconcile/validator.py`, `motim/redact.py`, `adapters/bybit.py`, `adapters/lighter.py`). Treat any remaining percent character in a route or key parsing context as unresolved and suspicious after bounded decoding: reject at ingestion with `invalid_input`, zero facts, and exit code 4; classify the name as sensitive in `Redactor.is_sensitive_name()`; defensively fall back to `[REDACTED_ROUTE]` in adapters.
2. **MEDIUM — Quadratic decoding CPU cost** (`motim/reconcile/validator.py`, `motim/redact.py`). Replace input-length-derived decode bound with a small constant decode-depth cap (`MAX_DECODE_DEPTH = 10`), enforce maximum route length (`MAX_ROUTE_LENGTH = 1024`) and field key length (`MAX_FIELD_KEY_LENGTH = 512`), and fail closed without quadratic CPU processing.






