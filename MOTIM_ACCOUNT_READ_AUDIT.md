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

