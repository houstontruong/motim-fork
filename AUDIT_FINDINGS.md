# Codex Audit Findings — Motim-Fork Phase B (round 1)

**Date:** 2026-08-23 09:50 EDT
**Auditor:** Codex CLI (read-only sandbox, contents as untrusted data)
**Scope:** all changed Python files vs `93eb978` (20 files, 4 batches)
**Result:** 8 CRITICAL · 40 HIGH · 28 MEDIUM · 2 LOW — **the Phase B "done" claim is NOT valid yet.**

Treat every finding as a defect that must be fixed or explicitly justified. Fix CRITICAL and HIGH; address MEDIUM where cheap. Add regression tests for each fix. Update the gate tests so they *would have caught these*.

## Gold rules violated (read first)

The Phase B non-negotiables claimed:
1. "Replay capability removed at source" — **FALSE**: multiple replay-capable paths remain (below).
2. "Secrets redacted before persistence" — **FALSE**: several persistence paths bypass redaction.
3. "Egress allowlist by design" — **INCOMPLETE**: DNS rebinding bypasses it.
4. "Private 0700/0600 storage" — **INCOMPLETE**: many chmod-after-create races, silent failures.

---

## CRITICAL findings

### C1 — replay still reachable: `DBClient` (motim/db_client.py:20)
DBClient is an active HTTP client (httpx) that loads captured auth headers from SQLite and attaches them to outbound requests. This is a direct credential-replay path.
Fix: remove DBClient entirely, or make it read-only/offline so captured headers can never reach an HTTP transport.

### C2 — package exports network clients (motim/__init__.py:42)
`__init__.py` imports and exports Client, AsyncClient, DBClient and HTTP verb helpers — authenticated request replay remains available despite "source-level removal".
Fix: remove all network clients and request helpers from the package and its public exports.

### C3 — `auth.to_headers` reconstructs request-ready credentials (motim/auth.py:266)
Reconstructs Authorization/Cookie headers from captured credentials for any remaining caller.
Fix: remove request-header generation; expose only irreversibly redacted auth metadata.

### C4 — `export` command builds a runnable curl (motim/cli/main.py:256)
Reconstructs a runnable request with stored headers/body — a direct replay path.
Fix: remove runnable export, or export strictly redacted representation with auth headers/cookies/tokens/body omitted.

### C5–C8 — `Store` bypasses redaction entirely (motim/store.py)
- C5 (store.py:279): `update()` persists request headers verbatim under `spec["auth"]` — Authorization, Cookie, API keys, never redacted.
- C6 (store.py:299): parsed cookies persisted under `spec["auth"]["cookies"]` — session credentials on disk.
- C7 (store.py:366): arbitrary request/response bodies cached and written to YAML with no redaction.
- C8 (store.py:330): WebSocket frames persisted after truncation only — tokens leak to disk.
Fix (all): run mandatory strict redaction before anything enters the cache/disk. Store only auth scheme metadata, never credential values.

## HIGH findings (condensed)

### Replay/credential-leak paths
- H1 exchange_db.py:630 — `latest_auth_snapshot` retains complete cookie/auth header values ("for replay/chaining"). Remove auth snapshot storage entirely; store hashes or presence metadata only.
- H2 cli/main.py:604 — `export-yaml` copies `latest_auth_snapshot()` headers into artifact. Exclude auth values or strict-redact.
- H3 cli/main.py:628 — `export-yaml` writes without 0700/0600 enforcement.
- H4 exchange_db.py:790 — public `put_exchange`/`_put_exchange_no_commit` persist raw caller-supplied headers/bodies without redaction. Require a Redactor at the DB boundary.
- H5 proxy/pipeline.py:163 — raw headers/bodies/URLs/WS messages queued *before* redaction; redact synchronously at capture boundary.

### Redaction gaps (fail-open)
- H6 redact.py:270 — unparseable bodies (malformed JSON, multipart, binary) pass through unchanged → persisted. Fail closed: omit/replace unsanitizable bodies; explicit safe parsers.
- H7 redact.py:186 — `redact_query_string`/`redact_url` return original input on parse failure. Fail closed: replace with placeholder/omit.
- H8 exchange_db.py:104 — chmod failures silently ignored. Treat permission enforcement failure as fatal; verify mode before accepting captures.

### Egress allowlist bypass
- H9 addon.py:51 — allowlist validates hostname text only; never pins/resolves IPs → DNS rebinding to loopback/private/link-local/metadata. Resolve, reject prohibited ranges, pin validated address, revalidate every DNS answer. Also cover CONNECT, redirects, trailing dots, IDNA, userinfo, IPv6, encoded/case variants.

### Store races/state
- H10 store.py:36 — module-global `_cache`/`_dirty` shared across stores with different specs_dir. Make instance-local or key by canonical dir.
- H11 store.py:49 / H12 store.py:58 — flush clears dirty flags & copies specs outside lock → torn snapshots/lost updates. Deep-copy under lock; version-check; dirty clear only after successful write.
- H13 store.py:264 — `update()` mutates shared spec without lock. Serialize per-service or copy-on-write.
- H14 store.py:88 — process-wide `_shutdown` never reset; post-shutdown Store flushes nothing. Instance-owned event.
- H15 store.py:99 — atexit flushes to default SPECS_DIR regardless of store dir. Per-store cleanup.
- H16 store.py:65 — YAML written in place → torn/partial reads. Temp file + fsync + atomic replace.
- H17 store.py:68 — chmod(0600) after write_text → umask window. Create atomically with 0600 before writing.
- H18 store.py:115 — 0700 enforcement failure silently ignored + no symlink/ownership check. Fail closed; reject symlinks/non-owned dirs.

### PID file races (cli/proxy.py)
- H19 proxy.py:78 — non-atomic PID file check/create → concurrent starts. O_CREAT|O_EXCL or OS lock held for proxy lifetime.
- H20 proxy.py:134 — finally removes PID_FILE even if replaced by another process. Verify ownership under lock before unlink.
- H21 proxy.py:150 — `stop` SIGTERMs a PID from disk without verifying it's the motim proxy → PID-reuse kill. Validate ownership/identity (pidfd preferred).

### Exchange writer/Pipeline
- H22 exchange_writer.py:160 — `_flush_batch` swallows exceptions, `written` incremented for failed batch → silent loss + false success. Propagate/record; increment only after commit.
- H23 exchange_writer.py:78 / H24 pipeline.py:196 — close can leave daemon thread alive and/or discard queued writes; worker exceptions swallowed. Lifecycle states, queue task accounting, failure counters.

### Config/CLI hardening
- H25 config.py:306 — `Config.save()` writes sensitive `extra_headers` without 0600; parent not 0700.
- H26 config.py:205 — no type validation in `from_dict()` → crash on malformed YAML. Strict schema validation.
- H27 cli/main.py:701 — `init` config write is check-then-write, non-atomic, symlink-raceable. O_EXCL no-follow 0600.
- H28 cli/main.py:695 — `init` creates ~/.motim without enforcing 0700. Enforce + verify.
- H29 cli/main.py:843 — `agents-md` overwrites existing AGENTS.md without confirmation/backup. Require --force; atomic with backup.

### Test-suite gaps (tests no longer protect the claims)
- H30 test_gates.py:22 — G1 only checks one module/exports/table; misses alt resend paths. Add AST/import audit rejecting outbound network calls touching captured data.
- H31 test_gates.py:86 — redaction proof scans persistence only after orderly shutdown → WAL/journal transient secrets missed. Inspect while active + forced-crash tests.
- H32 test_gates.py:143 — no assertion that enqueue/flush actually happened → vacuous pass. Assert counts.
- H33 test_egress.py:41 — `"*"` allowed as a config value (disables allowlist). Reject global wildcards or require unsafe-mode gate.
- H34 test_gates.py:190 — egress tests cover only simple hosts. Add CONNECT/redirects/rebinding/IP-v4-vs-v6/IDNA/trailing-dot/userinfo/variants.
- H35 test_gates.py:213 — allowlisted hostname assumed enough without resolved-IP validation. Test address policy pre-connect and on DNS change.
- H36 test_redaction.py:91 — pipeline tests miss malformed JSON/form, invalid UTF-8, compressed/multipart, duplicate headers/params paths.
- H37 test_store.py:72 — Store tests pass raw credentials but never assert absence from memory/YAML. Assert redaction at Store boundary.
- H38 test_store.py:67 — name normalization omits traversal/symlinks/separators/collisions. Hostile-name containment tests.
- H39 test_store.py:50 — delete/clear untested against symlinks/traversal/concurrent flush.
- H40 test_gates.py:305 — permission tests inspect final modes only; add adversarial creation-window/symlink/umask tests.

## MEDIUM (representative; fix where cheap)
- discovery.py:74 — `get_store(cfg)` passes Config positionally as `specs_dir` (real bug: Store construction). Construct as `Store(config=cfg)`.
- discovery.py:79 — swallows all DB errors → corruption looks like "no services". Surface unexpected exceptions.
- exchange_db.py:552 — `session_slice` ValueError on empty filtered list; 450 — `rebuild_derived` ZeroDivisionError on batch_size=0; 588 — limit==0 returns full slice; 870/930 — cursor leaks.
- cli/main.py:327/338 — `--batch-size`/limit/offset accept zero/negative; 132 — missing exchange unhandled; 47 — malformed header rows crash; 174 — duplicate headers (Set-Cookie) collapsed in JSON output; 154 — empty body labeled "not captured"; 719/722 — `init` prints SETUP COMPLETE even if cert generation fails; child not reaped on terminate failure.
- redact.py:295 — `k.lower()` on unvalidated query keys → KeyError crash.
- normalize.py:23 — cookie split on commas corrupts values with commas; split on semicolons.
- store.py:398/401 — zero/negative sample limits → slicing surprises; 198 — fuzzy delete can hit wrong service; 429 — dedup hash non-canonical for nested maps.
- auth.py:35 — `from_spec` assumes spec["auth"] is mapping → AttributeError on malformed data.
- exchange_writer.py:42 — owned ExchangeDB leaked on init failure.
- pipeline.py:145 — close marks unstarted while thread alive; enqueue restarts same Thread → RuntimeError.
- db_client.py:42 — leaked DB on AuthMissingError/init failure (if DBClient is kept).
- test_store.py:125 — no concurrent stress tests; 142 — 100ms wall-clock assertion is flaky (instrument instead).

---

## What "done" now requires

1. All CRITICAL fixed and proven (replay paths gone: DBClient/Client/AsyncClient/verb helpers removed from package; export redacted or removed; auth snapshots removed; Store boundary redacts).
2. All HIGH fixed or explicitly justified in the report with a rationale.
3. Gate tests strengthened so every CRITICAL/HIGH above would fail the old code (add the adversarial cases listed).
4. Full suite green: `pytest -q` (was 134 passed before audit).
5. Fresh Codex re-audit of the changed files after fixes.

Update `motim-phase-b-report.md` with a section: "Codex audit round 1 → N findings → fixes applied → re-audit result."