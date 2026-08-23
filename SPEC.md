# Motim Account-Read Reconciliation — Offline Contract

**Status:** Implementation brief for AG. This is an offline parser/reconciler only. It does not capture traffic, sign in, re-query an account, or contact an exchange.

## Problem and scope

The hardened Motim fork can retain **sanitized** browser exchanges for discovery, but account data must be made useful without recreating an authenticated client. Build a provider-neutral reconciliation layer that translates synthetic, sanitized Bybit and Lighter exchange exports into traceable account facts: positions, fills, funding, balance/equity, and PnL.

This build uses synthetic fixtures and documented structural patterns only. A real-capture procedure is deliberately a separate, future decision and must not be added as code, a runbook, a test target, or an implied network integration here.

## Non-negotiable safety boundary

- No credentials, authenticated traffic, browser sign-in, orders, withdrawals, transfers, mutations, replay, outbound HTTP, WebSocket, proxy bypass, or system-wide proxy configuration.
- No network-client imports in reconciliation production modules. No socket may be opened by reconciliation code or its CLI.
- Never reconstruct, store, emit, or accept an auth value. Redacted headers/cookies/query/body fragments must not become facts or error text.
- Inputs are local fixture/export files only. Adapters must not guess live routes or fetch a schema.
- This is not a trading strategy, backtest, execution engine, or performance claim.

## Versioned input contract — `motim.sanitized_exchange.v1`

The reconciler accepts JSON Lines only. Every line is one validated sanitized exchange object:

```json
{
  "schema_version": "motim.sanitized_exchange.v1",
  "exchange_id": "fixture-bybit-001",
  "provider": "bybit",
  "captured_at": "2026-08-23T14:00:00Z",
  "request": {"method": "GET", "route_key": "positions"},
  "response": {"status": 200, "content_type": "application/json", "body": {}}
}
```

Rules:

- `schema_version`, `exchange_id`, `provider`, `captured_at`, `request.method`, `request.route_key`, `response.status`, and `response.body` are required. `captured_at` is RFC3339 UTC with `Z`; `exchange_id` is unique within an input file.
- `provider` is exactly `bybit` or `lighter`. `route_key` is a synthetic adapter key, not a copied live URL/path.
- Reject unknown top-level fields in strict mode; reject auth-shaped fields (`authorization`, `cookie`, `token`, `secret`, `password`, including case/underscore/hyphen variants) anywhere in the input tree with a redacted validation error.
- The fixture/export contains no request URL, host, query string, or raw header. The response body is a pre-sanitized JSON value, never opaque raw HTTP.

## Versioned output contract — `motim.account_read.v1`

`motim reconcile` emits exactly one JSON object to stdout:

```json
{
  "schema_version": "motim.account_read.v1",
  "provider": "bybit",
  "as_of": "2026-08-23T14:05:00Z",
  "outcome": "ok",
  "facts": [],
  "issues": []
}
```

Every fact has `fact_id`, `fact_type`, `provider`, `account_scope`, `observed_at`, `source_exchange_ids`, and `data`. `fact_type` is one of `position`, `fill`, `funding`, `balance`, `equity`, or `pnl`. All quantities, prices, fees, and PnL values are canonical base-10 decimal **strings** (never floats); currency/asset codes are uppercase strings. `source_exchange_ids` preserves one or more input IDs.

Deduplication key: `provider + account_scope + fact_type + native_id`; where a known fixture schema has no native ID, use the SHA-256 of canonicalized **already-sanitized** semantic fields documented by that adapter. Exact duplicates collapse to one fact and produce a `duplicate_event` issue naming only source IDs. Conflicting records with the same key produce no merged value and a `conflicting_duplicate` issue.

Staleness is deterministic: `--as-of RFC3339Z` is required for CLI reconciliation. A fact is `stale` when `as_of - observed_at > --max-age-seconds`; default is `0` (only equal-time facts are fresh). Staleness is reported as an issue and does not silently drop a valid fact. The library API requires an explicit `as_of` parameter—never call the system clock.

## Outcome and issue taxonomy

- `ok` (exit 0): every selected exchange is valid and recognized; issues may include harmless exact duplicates or staleness.
- `partial` (exit 2): one or more known-schema records are malformed/unusable or conflict, while other facts were produced. Each omitted record has a structured issue.
- `unsupported_schema` (exit 3): no selected exchange produces a recognized fact because its route/body structure is unsupported. Facts must not be guessed. If other selected exchanges reconcile, retain their facts but issue `unsupported_schema` per offending exchange and use outcome `partial` (exit 2).
- `invalid_input` (exit 4): input violates the sanitized-exchange contract, including secret-shaped fields; emit no facts from that exchange and never echo the value.

Each issue has `code`, `provider`, `source_exchange_id`, `severity`, and a redacted human message. Unknown schema is always visible as `unsupported_schema`, never silently coerced.

## Required public surface

- `motim reconcile --input FILE --provider {bybit,lighter} --as-of RFC3339Z [--max-age-seconds N] [--no-strict]` → one result JSON object on stdout; strict validation is the default and stdout has no log noise.
- `motim facts --result FILE [--type TYPE]` and `motim issues --result FILE [--code CODE]` read a previously produced `motim.account_read.v1` result file and filter only; neither accepts an exchange input or touches the network.
- A small Python API mirrors this contract: `reconcile(exchanges, provider, *, as_of, max_age_seconds=0, strict=True)` returning a validated result model. No I/O or clock access in the core.
- Add `ACCOUNT_READ_CONTRACT.md` with the exact schemas, exit codes, and a redacted fixture/output example. Update README only with this local-offline capability.

## Implementation boundaries

- Create a self-contained reconciliation package; do not couple it to proxy lifecycle or use a live Motim DB. A future importer can export sanitized records into the defined JSONL contract.
- Keep Bybit and Lighter adapters separate and registered explicitly. Their sole evidence is checked-in synthetic fixtures and documented structural patterns.
- Do not modify the prior hardening guarantees (replay/probe removal, redaction-before-persistence, egress deny-by-default, loopback bind, and private storage permissions).

## Mandatory verification gates

1. **Contract tests:** valid/invalid schema, decimal strings, source traceability, deterministic staleness, exact/conflicting deduplication, and redacted validation errors.
2. **Adapter tests:** both providers; positions/fills/funding/balance/equity/PnL; malformed/redacted records; unknown route/body schema; duplicate input; mixed recognized/unsupported exchanges.
3. **CLI smoke:** run `reconcile`, then `facts` and `issues`, against fixtures. Capture stdout and exit codes 0/2/3/4.
4. **No-network/no-replay:** (a) AST/static test rejects imports/calls to `socket`, `requests`, `httpx`, `urllib`, `aiohttp`, `websocket`, and `mitmproxy` in reconciliation modules; (b) run the actual CLI in a subprocess whose injected test `sitecustomize` replaces socket creation/DNS/HTTP entry points with immediate failure; (c) test must pass under that guard; (d) grep/AST regression confirms no reconciliation/export path can build a runnable request or emit a secret fixture sentinel.
5. **Security regression:** pass a fixture containing unique sentinel values for Bearer token, cookie, query secret, and body secret; assert none appears in result JSON, stderr, report, docs/examples, or persisted test artifacts.
6. **Full suite:** existing suite plus the above passes. `motim-account-read-report.md` records exact commands/output, changed files, known schema gaps, and explicitly says real capture is out of scope.

## Deliverables

- Reconciliation package, CLI/API, fixtures, and tests described above.
- `ACCOUNT_READ_CONTRACT.md` and `motim-account-read-report.md`.
- Small checkpoint commits after contract/tests, each adapter, then verification/docs.

## Working agreement

If you see a better approach than this brief describes, say so and explain why before changing direction. Preserve the MIT license. If a safety boundary conflicts with existing architecture, stop and document it—do not silently weaken it.
