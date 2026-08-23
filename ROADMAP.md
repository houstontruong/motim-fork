# MOTIM Project Roadmap

## Vision
Motim is the high-performance, security-hardened API discovery and schema observation engine built for autonomous AI agents and engineering teams. It allows agents to understand API structures, endpoints, request formats, and auth mechanisms from real web and mobile traffic without security compromises.

---

## Phase B: Production-Safe Architecture (Completed ✅)

- [x] **Gate G1 — Replay & Probe Removed at Source**
  - Deleted `motim/agent_replay.py` and replay test modules.
  - Extracted offline comparison into pure static `motim/diff.py`.
  - Removed `replay`, `replay-seq`, and `probe` commands from CLI.
  - Removed `replays` SQLite schema, triggers, and foreign keys.
  - Implemented AST and import verification tests.

- [x] **Gate G2 — Redaction-Before-Persistence Engine**
  - Created `motim/redact.py` with strict and standard redaction profiles.
  - Added header scrubbing for `Authorization` (Bearer/Basic), `Cookie` values, and API keys.
  - Added recursive payload redaction for JSON, URL-encoded forms, and regex text.
  - Added query parameter token scrubbing.
  - Hooked redaction directly into `CapturePipeline` before store/DB serialization.
  - Added synthetic canary token leak tests.

- [x] **Gate G3 — Egress Allowlist & Loopback Binding**
  - Implemented zero-trust default deny-all egress policy in proxy addon.
  - Added `capture.allowed_hosts` support with exact and wildcard domain matching.
  - Added immediate 403 Forbidden intercept for unauthorized destinations.
  - Enforced loopback-only binding (`127.0.0.1` / `::1`) in CLI proxy management, rejecting `0.0.0.0`.

- [x] **Gate G4 — Read-Only Client & Safe Storage Defaults**
  - Created `motim/discovery.py` providing structured `discover()`, `discover_services()`, and `ServiceDiscovery`.
  - Configured strict POSIX permissions (directory `0700`, files `0600`).
  - Added 1 MB payload body caps to prevent storage exhaustion.
  - Sourced authentication headers are strictly sanitized placeholders.

- [x] **Gate G5 — Verification & Documentation**
  - Created `SECURITY.md`, `ROADMAP.md`, and `motim-phase-b-report.md`.
  - Updated `README.md` and AI agent instructions in `motim/skill.md`.
  - Added end-to-end regression test suite in `tests/test_gates.py`.

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
