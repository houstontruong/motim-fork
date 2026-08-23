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
