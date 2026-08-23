# Security Policy & Architecture

## Overview

Motim is an agentic HTTP/API discovery and schema inspection proxy designed for secure environments. The production-safe Motim fork eliminates credentials-in-the-wild risks by enforcing five foundational security guarantees:

1. **Replay Truly Removed at Source (Gate G1)**
2. **Fail-Closed Redaction-Before-Persistence Engine (Gate G2)**
3. **Egress Allowlist Immune to DNS Rebinding & Loopback-Only Binding (Gate G3)**
4. **Read-Only Discovery Interface & Safe Storage Defaults (Gate G4)**
5. **Continuous Verification & Audit Testing (Gate G5)**

---

## 1. Threat Model & Mitigations

| Threat | Description | Motim Mitigation |
|---|---|---|
| **Credential Exfiltration** | Captured API tokens, JWTs, or session cookies leaked to disk or shared storage. | **Fail-Closed Redaction-Before-Persistence**: Credentials, Authorization headers, and secret payloads are sanitized at the capture boundary before entering queue buffers or touching disk/database files. Unparseable payloads fail closed to `[REDACTED: unparseable body]`. |
| **Accidental State Mutation / Replay** | An AI agent re-transmits recorded stateful requests (orders, deletes, fund transfers). | **Replay Truly Removed**: All active network replay clients (`Client`, `AsyncClient`, `DBClient`, `get`, `post`, `put`, `delete`, `patch`, `request`), header generators (`auth.to_headers`), and database replays tables have been permanently excised. |
| **DNS Rebinding & Egress Smuggling** | Malicious domains resolving to internal IPs (e.g. metadata `169.254.169.254`, loopback, or LAN) or tunneling via CONNECT/redirects. | **DNS Rebinding Immune Egress Filter**: Egress allowlist resolves DNS records, verifies all A/AAAA records against prohibited networks (loopback, private, link-local, cloud metadata, testnet, IPv4-mapped IPv6), validates HTTP CONNECT tunnels, and inspects 3xx redirects. |
| **Remote Proxy Hijacking** | Remote actors connecting to an exposed proxy port on `0.0.0.0`. | **Loopback-Only Bind**: The proxy strictly binds to `127.0.0.1` / `::1`. Any attempt to bind to `0.0.0.0` or external network interfaces is rejected with a fatal error. |
| **Local File Snooping & Symlink Attacks** | Non-root local users or malicious symlinks reading or hijacking spec files/SQLite DBs. | **Race-Free Private Storage**: Directories enforce `0700` and files enforce `0600` via atomic `os.open` (`O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW`), `os.fsync`, and atomic `os.replace`. Symlinks are strictly rejected across all storage paths. |
| **Disk Exhaustion DOS** | High-volume capture filling storage with large binary payloads. | **Size Limits**: `max_body_bytes` enforces a default 1 MB per-body cap, truncating payloads safely and setting truncation flags. |


---

## 2. Redaction-Before-Persistence Architecture

Redaction in Motim is handled by `motim.redact.Redactor`. It runs synchronously inside the proxy pipeline on the hot-path before queuing into SQLite or writing YAML specs.

### Sensitive Header Sanitization
- `Authorization`: Transformed to `Bearer [REDACTED]` or `Basic [REDACTED]`.
- `Cookie` / `Set-Cookie`: Cookie names and structure are retained for schema discovery, but all values are replaced with `[REDACTED]` (e.g. `session_id=[REDACTED]; csrf=[REDACTED]`).
- `X-API-Key`, `API-Key`, `X-Auth-Token`, `X-Access-Token`, `X-CSRF-Token`: Completely masked with `[REDACTED]`.

### Query Parameter & URL Scrubbing
- Sensitive parameters (`token`, `api_key`, `secret`, `password`, `session`, `sig`, `code`, `jwt`) are sanitized in-place in raw URLs and query parameter dictionaries.

### Payload & Body Scrubbing
- **JSON**: Decoded and recursively traversed. Any key containing `password`, `token`, `secret`, `api_key`, `auth`, `jwt`, `private_key`, `credential`, `card_number`, `ssn` is masked with `[REDACTED]`.
- **Form Data**: URL-encoded key-value pairs are parsed and sensitive fields redacted.
- **Regex Sanitization**: Text and string payloads are scanned for JWT patterns (`ey[A-Za-z0-9_-]+\...`), Bearer tokens, and RSA/EC private keys (`-----BEGIN PRIVATE KEY-----`).

---

## 3. Zero-Trust Egress Allowlist

By default, `capture.allowed_hosts` in `~/.motim/config.yaml` is empty (`[]`). In this mode, all outbound requests through the proxy are blocked.

### Configuration Example
```yaml
capture:
  allowed_hosts:
    - "api.bybit.com"
    - "*.deribit.com"
    - "fapi.binance.com"
```

When an intercepted request targets a domain not in the allowlist, the proxy terminates the request locally:
- HTTP Status: `403 Forbidden`
- Response Header: `x-motim-egress-blocked: 1`
- Body: `403 Forbidden: Destination '<host>' is not in Motim egress allowlist.`

---

## 4. Discovery-First Client Interface

The Motim client layer is strictly designed for **discovery and schema inspection**:
- `motim.discover(service_name)`: Returns structured endpoint summaries, HTTP methods, observed status codes, and detected auth schemes.
- `motim.discover_services()`: Lists available services.
- `motim.Store` & `motim.ExchangeDB`: Provides indexed offline query access to observed API structures.

No API execution client transmits persistent or captured credentials. Callers wishing to make live requests against discovered endpoints must supply fresh, runtime credentials explicitly authorized by the host environment.

---

## 5. Reporting Vulnerabilities

If you discover a security vulnerability in Motim, please contact the maintainers directly or open a private security advisory on GitHub. Please do not publish security disclosures publicly before coordination.
