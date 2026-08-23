---
name: motim
description: Search, inspect, and discover API schemas from captured network traffic. Use when you need to understand web APIs, discover endpoint schemas, map parameter structures, and debug observed traffic.
---

# motim — network traffic inspection & discovery layer for agents

motim captures browser and test HTTP(S) traffic into a local, redacted SQLite DB (`~/.motim/motim.sqlite3`). You search, inspect, discover, and diff those exchanges via CLI or Python API to understand how target services work — without credentials-in-the-wild or state mutation risks.

**Always use `--json` for structured output.**

## Decision tree

1. **Need to understand what endpoints a service provides?** → `motim endpoints --service <name> --json`
2. **Need to discover all observed services?** → `motim services list --json`
3. **Need to inspect a specific request/response flow?** → `motim show <id> --json`
4. **Need to compare two exchanges (e.g. success vs error)?** → `motim diff <id1> <id2> --json`
5. **Need to see what happened around an exchange?** → `motim around <id> --window 60 --json`
6. **Need to extract API routes from frontend JavaScript?** → `motim linkfinder --host <host> --regex '^/api/' --json`
7. **Need to reconstruct an interaction session?** → `motim session <id> --json`

## What gets captured & redacted

motim captures HTTP(S) traffic while automatically sanitizing sensitive data before storage:
- **Authorization & Tokens**: Bearer tokens, Basic credentials, and API keys are masked as `[REDACTED]`.
- **Cookies & Sessions**: Cookie keys are preserved for schema discovery, but all session values are redacted.
- **Payload Secrets**: Password fields, private keys, credit cards, and JWT signatures are scrubbed recursively.
- **Noise Filtering**: Analytics (Google Analytics, Segment, Mixpanel) and static assets (images, fonts) are discarded.

## Service keys

Hostnames are normalized into service keys: `api.example.com` → `api_example_com`. You can use any format — `api.example.com`, `api_example_com`, or just `example` (partial match). All resolve to the same service.

## Path templates

Paths are templatized: UUIDs and numeric IDs are replaced with `{id}`. So `/v1/databases/abc-123/query` becomes `/v1/databases/{id}/query`. This lets you see endpoint patterns instead of individual requests.

## Commands

### Search exchanges

Find captured exchanges by host, method, status, path, or service.

```bash
motim search --host api.example.com --method POST --status 200 --json
motim search --service example --path-contains "/query" --limit 50 --json
motim search --service example --offset 100 --limit 50 --json  # pagination
```

### Inspect an exchange

View full request + response details for a specific exchange.

```bash
motim show 42 --json              # full request + response as JSON
motim show 42 --request-only      # request only
motim show 42 --response-only     # response only
motim show 42 --raw               # skip pretty-printing
motim cat 42                      # response body only (pipe-friendly)
motim cat 42 --request            # request body only
motim export 42                   # export structure
```

### List endpoints

Show discovered endpoint patterns (method + templatized path) with hit counts and success rates.

```bash
motim endpoints --service example --json
motim endpoints --method POST --path-contains "/query" --json
```

### List services

Show all captured services with exchange counts.

```bash
motim services list --json             # list all services
motim services show example --json     # detailed service info
```

### Diff two exchanges

Compare two exchanges side by side — useful for understanding what changed between a working and broken request.

```bash
motim diff 42 43 --json
```

### Time-window exploration

Find exchanges around a specific exchange in time. Useful for understanding what happened before/after a request.

```bash
motim around 42 --window 60 --json        # exchanges ±60 seconds
motim around 42 --window 60 --service example --json  # filter by service
```

### Session reconstruction

Extract a full session slice around an exchange using gap-based splitting.

```bash
motim session 42 --json                    # default 120s gap
motim session 42 --gap 300 --json          # 5-minute gap threshold
```

### JS endpoint extraction

Extract API routes from captured JavaScript bundles. Discovers endpoints referenced in frontend code even before you trigger them in the UI.

```bash
motim linkfinder --host app.example.com --json                    # all links
motim linkfinder --host app.example.com --regex '^/api/' --json   # filter by pattern
motim js-endpoints --service example --json                       # aggregated hints
```

## Python discovery API

```python
from motim import discover, discover_services, Service

# Discover services and schemas
services = discover_services()
service = discover("example")

print("Auth type:", service.auth_type)
for ep in service.list_endpoints():
    print(ep.method, ep.path, ep.sample_count)

# Compare parameter variations across samples
svc = Service.load("example")
comparison = svc.samples.compare("POST /api/endpoint")
print("Constant params:", comparison.constant_params)
print("Varying params:", comparison.varying_params)
```
