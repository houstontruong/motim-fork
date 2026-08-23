# Motim Phase B — Production-Safe Fork Brief

**Status:** Brief for AG (Gemini 3.1 Pro). Read fully, then decide. You are encouraged to challenge or improve anything here — the author is a weaker model than you and deliberately did NOT prescribe implementation.

## Problem

Motim 0.2.1 captures browser network traffic through a mitmproxy addon, indexes exchanges into a SQLite DB, lets agents search endpoints, and can replay captured requests. The idea is genuinely useful: **where a service's UI hides a useful read API, capture that traffic once and let an agent query real endpoints instead of scraping the UI.**

Phase A (synthetic lab, completed 2026-08-23) proved the capture pipeline works correctly in a hardened, disposable Docker container on an isolated internal network. It also documented real security defects that make stock Motim a **No-Go near any real account**:

1. **Plaintext credential persistence** — captured headers/bodies (authorization, cookies, API keys) are stored raw in the DB.
2. **Unsafe replay** — the `replay` / `replay-seq` / `probe` commands re-send captured requests verbatim, including stale credentials, to targets that may no longer be trusted (SSRF-adjacent).
3. **Unconfined DB paths** — DB defaults to `~/.motim/` with no private-permission enforcement.
4. **Truncated-write replay** and associated correctness bugs found in audit.

Phase A canned those risks with a disposable lab: replay killed via runtime stubs + CLI guard, loopback-only bind, egress allowlist by construction, 0600 volume, teardown on exit. **A runtime patch is not a product.**

## Goal

Build **Motim-Fork**: a maintained fork where the Phase A hardening is true by design, not by deployment, and where a read-only agent integration can be built on top.

## Objectives (what "done" looks like)

1. **Replay/probe removed at the source.** No `replay`, `replay-seq`, or unsafe `probe` capability exists in the codebase at all — not stubbed, not guarded, **gone**. Define what safe replacement (if any) exists for legitimate read-only re-querying (e.g., a dry-run that never sends stored credentials).
2. **Redaction-before-persistence.** Captured flows are redacted (secrets stripped/parameterized) **before** anything is written to disk or DB. Redaction must be configurable and default-strict.
3. **Egress allowlist by design.** The proxy only forwards to destinations in an explicit allowlist. Default: deny all. Loopback-only bind.
4. **Credential hygiene.** No plaintext credential storage anywhere. If a flow is captured with secrets, the secrets never reach the DB. Document the threat model this changes.
5. **Safe defaults for DB + config.** Private permissions (0600 dirs/files), configurable but default-hardened paths, no broad captures without explicit profile selection.
6. **Readable, testable, documented.** Test suite passes (existing tests preserved or explicitly replaced with justification), README updated, security model documented in SECURITY.md.

## Non-Negotiables (from Phase A memo, Conditional-Go constraints)

- Replay ability is **removed at source** (not runtime-disabled). No code path can re-send a captured request with stored credentials.
- Secrets are redacted **before persistence** — the DB never holds raw credentials.
- Only allowlisted egress destinations; deny-by-default.
- Loopback-only proxy bind.
- DB/credential stores: 0600-equivalent permissions; excluded from backup/sync semantics by construction.
- No autonomous writes to real accounts from this codebase's default operation — read-first.

## Context You Have to Work With

- `/tmp/motim-fork` — this repo, stock Motim 0.2.1 (MIT, Python, mitmproxy addon).
- Key files (from Phase A source review): `motim/cli/proxy.py` (proxy start + CA guard), `motim/cli/main.py` (replay/probe commands ~line 697+, `init`), `motim/proxy/addon.py` (capture pipeline), `motim/exchange_db.py` (DB layer), `motim/config.py` (config, DB path configurable at line ~86).
- Phase A findings (authoritative on the defect list): Obsidian `OpenClaw/Build/Motim Sandbox Spike Memo.md` and `OpenClaw/Build/Motim Synology Lab Container.md` (Phase A lab plan + verified result).
- Constraints the fork must keep from the original: MIT license, CLI ergonomics, spec generation value.

## Validation Gates (each phase must prove itself)

1. **G1 — Code review: replay removed.** Grep the source for replay/probe paths; attack the design: can a captured request with credentials be re-sent by ANY code path (CLI, module import, plugin)? Prove no.
2. **G2 — Redaction test.** Capture a synthetic flow with an `Authorization: Bearer <token>` header. Prove the DB contains no raw token; prove the stored spec still identifies the endpoint. Test the strict profile.
3. **G3 — Egress test.** From a hardened container (read-only rootfs, cap_drop ALL, internal network): allowlist one destination; deny a second; prove both behaviors (mirror the Phase A egress proof).
4. **G4 — Integration stub.** A read-only client can list discovered endpoints and query a captured endpoint spec without replay. (This is the OpenClaw-facing API surface.)
5. **G5 — Suite + docs.** Tests green, SECURITY.md written, README reflects real behavior.

## Deliverable

A pushable fork (`motim-fork`) with the above done at source level, tests proving G1–G5, and a short SECURITY.md. Leave a ROADMAP.md noting what a read-only agent integration (Bybit/Lighter-style account-read reconciliation) would consume.

## Working agreement

- You are the architect here: if you see a better approach than described, say so and explain why before building.
- Do not break the MIT license (keep attribution).
- Prefer small, reviewable commits over one giant rewrite.
- If a "non-negotiable" conflicts with the original code's design in a way you can't resolve cleanly, stop and explain — don't silently downgrade the constraint.