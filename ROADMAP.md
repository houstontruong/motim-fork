# MOTIM Project Roadmap

## Vision
Motim is the high-performance, security-hardened API discovery and schema observation engine built for autonomous AI agents and engineering teams. It allows agents to understand API structures, endpoints, request formats, and auth mechanisms from real web and mobile traffic without security compromises.

---

## Phase B: Production-Safe Architecture & Security Hardening (Completed ✅)

- [x] **Gate G1 — Replay Truly Removed at Source**
  - Deleted active network replay clients (`Client`, `AsyncClient`, `DBClient`) and HTTP verb helpers (`get`, `post`, `put`, `delete`, `patch`, `request`).
  - Completely removed `agent_replay.py` and `auth.to_headers()` request-header generation.
  - Sanitized `export` and `export-yaml` commands to never output raw credentials.
  - Extracted offline comparison into pure static `motim/diff.py`.
  - Removed `replay`, `replay-seq`, and `probe` commands from CLI.
  - Removed `replays` SQLite schema, triggers, and foreign keys.
  - Added AST code audit and module absence tests.

- [x] **Gate G2 — Fail-Closed Redaction-Before-Persistence Engine**
  - Created `motim/redact.py` with strict and standard fail-closed redaction profiles.
  - Added header scrubbing for `Authorization` (Bearer/Basic), `Cookie` values, and API keys.
  - Added recursive payload redaction for JSON, URL-encoded forms, multipart, and regex text.
  - Added query parameter and URL token scrubbing.
  - Hooked redaction synchronously into `CapturePipeline`, `Store.update()`, and `ExchangeDB.put_exchange()` before memory/disk persistence.
  - Added synthetic canary token leak tests and live SQLite WAL inspection tests.

- [x] **Gate G3 — DNS Rebinding Immune Egress Allowlist & Loopback Binding**
  - Implemented zero-trust default deny-all egress policy in proxy addon.
  - Added `capture.allowed_hosts` support with exact, wildcard, IDNA, and port-stripped host matching.
  - Hardened against DNS rebinding by resolving domain names and verifying all A/AAAA records against prohibited networks (loopback, private, link-local, cloud metadata `169.254.169.254`, IPv6 `::1`, `fe80::/10`, `fc00::/7`).
  - Added HTTP CONNECT tunnel blocking and 3xx redirect destination inspection.
  - Enforced loopback-only binding (`127.0.0.1` / `::1`) in CLI proxy management, rejecting `0.0.0.0`.

- [x] **Gate G4 — Read-Only Discovery Interface & Race-Free Private Storage**
  - Created `motim/discovery.py` providing structured `discover()`, `discover_services()`, and `ServiceDiscovery`.
  - Enforced race-free atomic writes with `os.open` (`O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW`), `os.fsync`, and atomic `os.replace`.
  - Enforced private POSIX permissions (directory `0700`, files `0600`) and strict symlink rejection across all storage paths.
  - Added 1 MB payload body caps to prevent storage exhaustion.
  - Sourced authentication headers are strictly sanitized metadata.

- [x] **Gate G5 — Verification & Documentation**
  - Created `SECURITY.md`, `ROADMAP.md`, `motim-phase-b-report.md`, and `motim-phase-b-fixes-note.md`.
  - Updated `README.md` and AI agent instructions in `motim/skill.md`.
  - Added end-to-end regression test suite in `tests/test_gates.py` (17 gate tests, 128 suite tests passing).


---

## Phase C: Enhanced Discovery & Code Generation (Next Up 🚀)

- [ ] **OpenAPI 3.1 & JSON Schema Exporter**
  - Export discovered endpoints, parameter schemas, and request/response shapes into standard OpenAPI 3.1 YAML/JSON specifications.
  - Automatic JSON Schema derivation from observed sample payloads.

- [ ] **Static JS/Wasm Bundle LinkFinder Enhancements**
  - Deep AST-based endpoint harvesting from client-side Webpack, Vite, and Rollup bundles.
  - Route pattern reconstruction from frontend router configurations (React Router, Next.js, Vue Router).

- [ ] **Typed Client Code Generator**
  - Generate typed Python SDKs using `httpx` and `pydantic` models based on discovered schemas.
  - Generate typed TypeScript SDKs using `fetch` and `zod` validators.

- [ ] **Workspace & Session Partitioning**
  - Support multi-tenant project directories (`~/.motim/workspaces/<workspace_id>`).
  - Ephemeral proxy session tagging for isolated workflow audits.

- [ ] **Real-Time Discovery Event Stream**
  - SSE (Server-Sent Events) discovery stream for live UI dashboards and agent monitoring.
