# motim

**M**odel **O**ver **T**raffic — **I**ntercept & **M**anage

A production-safe API discovery, schema observation, and inspection substrate for AI agents.

motim runs a local proxy that captures HTTP(S) traffic into a SQLite database with mandatory redaction-before-persistence and egress filtering. AI agents query the database and generated specs to understand how web services work, map endpoint patterns, and analyze schemas — with zero risk of credential leaks or uncontrolled request mutations.

```
Browser / Client                           Agent
       │                                     │
       ▼                                     ▼
┌──────────────┐      ┌────────────┐   ┌──────────────┐
│  motim proxy │─────▶│  SQLite    │◀──│  search      │
│  (allowlist) │ (PII │  (traffic) │   │  inspect     │
│  :8080       │ scrub│            │   │  discover    │
└──────────────┘      └────────────┘   └──────────────┘
```

You browse a site or run integration tests. motim records requests and responses while automatically stripping tokens, cookies, passwords, and private keys. Your agent searches and inspects that traffic, builds schema models, and extracts API contracts — safely and deterministically.

---

## Key Features

- **🛡️ Redaction-Before-Persistence (Gate G2)**: All sensitive tokens, Bearer/Basic headers, session cookies, JWTs, and API credentials are sanitized on the ingest hot-path before touching SQLite or disk files.
- **🚫 Replay & Probe Removed at Source (Gate G1)**: Mutation probe engines and active replay tools have been permanently excised, ensuring no state mutations or fund movements can be accidentally triggered.
- **🔒 Egress Allowlist & Loopback-Only Bind (Gate G3)**: Default deny-all egress filtering prevents unauthorized outbound calls; proxy binds exclusively to `127.0.0.1` / `::1`.
- **🔍 Read-Only Discovery Engine (Gate G4)**: High-level Python discovery API (`discover()`, `discover_services()`) and CLI tools for mapping endpoints, schemas, and parameter variations.
- **📂 Secure Storage Defaults**: Strict POSIX file permissions (`0700` directories, `0600` files) and 1 MB payload limits to safeguard storage.

---

## Examples

**Agent discovers how an API works:**
```bash
motim endpoints --service example --json
motim search --host api.example.com --method POST --json
motim show 42 --json    # full request + response
```

**Agent compares two observed exchanges:**
```bash
motim diff 42 43 --json
motim around 42 --window 60 --json    # nearby exchanges in session
```

**Agent extracts endpoints from frontend JavaScript bundles:**
```bash
motim linkfinder --host app.example.com --regex '^/api/' --json
```

Every command supports `--json` for machine-readable output.

---

## Install

```bash
pip install motim
```

Optional extras:
```bash
pip install 'motim[linkfinder]'  # JS endpoint extraction
```

---

## Getting started

1. **Initialize motim**:
   ```bash
   motim init          # create secure dirs (0700), trust CA cert, install agent skill
   ```

2. **Configure Allowlist (`~/.motim/config.yaml`)**:
   ```yaml
   capture:
     allowed_hosts:
       - "api.example.com"
       - "*.bybit.com"
   ```

3. **Start Proxy**:
   ```bash
   motim proxy start --port 8080 --listen-host 127.0.0.1
   # Configure your browser or test suite to use localhost:8080
   # Sanitized traffic flows into ~/.motim/motim.sqlite3
   ```

---

## Agent Integration

motim ships a skill file that teaches agents how to inspect traffic safely.

```bash
motim init              # auto-installs skill for Claude Code
motim agents-md         # writes AGENTS.md for Codex, opencode, etc.
```

---

## CLI Reference

```bash
# Proxy Management
motim proxy start [--port 8080] [--listen-host 127.0.0.1]
motim proxy stop
motim proxy status
motim doctor                    # health and security check

# Search & Inspect
motim search [--host H] [--method M] [--status S] [--path-contains P]
motim show ID                   # full sanitized exchange
motim cat ID                    # response body only
motim cat ID --request          # request body only
motim endpoints [--service S]   # endpoint patterns
motim services list             # captured services

# Analysis & Discovery
motim diff A B                  # diff two exchanges
motim around ID --window 60     # time-window slice
motim session ID                # session reconstruction

# JS Analysis
motim linkfinder [--host H] [--regex R]
motim js-endpoints [--service S]

# Configuration & Maintenance
motim export-yaml SERVICE       # YAML spec summary
motim rebuild-index             # rebuild derived indexes
motim config show               # view config

# Offline Reconciliation (motim.account_read.v1)
motim reconcile --input FIXTURE --provider bybit --as-of RFC3339Z
motim facts --result RESULT_JSON [--type TYPE]
motim issues --result RESULT_JSON [--code CODE]
```

---

## Offline Account-Read Reconciliation API

```python
from motim import reconcile

# Translate sanitized exchange exports into structured facts (offline only)
result = reconcile(
    "fixtures/bybit_all_facts.jsonl",
    provider="bybit",
    as_of="2026-08-23T14:05:00Z",
    max_age_seconds=0,
    strict=True,
)

print(result.outcome)  # 'ok', 'partial', 'unsupported_schema', or 'invalid_input'
for fact in result.facts:
    print(fact.fact_type, fact.data)
```

See [ACCOUNT_READ_CONTRACT.md](file:///C:/Users/houst/PycharmProjects/motim-fork/ACCOUNT_READ_CONTRACT.md) for full contract specifications and exit code mappings.

---

## Python Discovery API

```python
from motim import discover, discover_services, ExchangeDB

# List all captured services
services = discover_services()

# Inspect endpoint schemas and detected auth scheme
svc = discover("binance_futures")
print(svc.auth_type)     # 'api_key'
print(svc.endpoints)     # ['GET /fapi/v1/ticker/price', ...]

# Inspect structured endpoint details
for ep in svc.list_endpoints():
    print(ep.method, ep.path, ep.sample_count, ep.statuses_seen)

# Query SQLite database directly
with ExchangeDB("~/.motim/motim.sqlite3") as db:
    results = db.search_exchanges(host="api.example.com", limit=10)
```

---

## Security & Verification

See [SECURITY.md](file:///C:/Users/houst/PycharmProjects/motim-fork/SECURITY.md) for full details on threat models, redaction algorithms, and egress controls.
Run the complete security gate verification suite:

```bash
pytest tests/test_gates.py
```

---

## License

MIT
