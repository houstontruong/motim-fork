# Motim Account-Read Reconciliation — Codex Audit Remediation Report

**Date:** 2026-08-23  
**Project:** Motim Hardened Fork (`motim-fork`)  
**Task:** Codex Audit Remediation (Offline Reconciliation Layer & Defense-in-Depth Redaction Engine)  
**Status:** Remediated, Verified, and Zero Gaps Remaining  

---

## 1. Executive Summary

This report documents the remediation of all audit findings across all rounds, including the Round 10 finding from the Codex audit of commit `cb21423` in the offline-only account-read reconciliation layer and defense-in-depth redaction engine of `motim-fork`:

1. **Defect 1 (Round 10 — Deep Percent-Encoding Bypass - HIGH):** `validator._fully_unquote_plus()` and adapter issue sanitizers previously had a 5-round decode limit. A route whose structural delimiters were encoded six or more times (e.g. `unsupported?api_key=TOPSECRET_DEPTH6` encoded to 6+ layers) bypassed validation and reached adapter unsupported-route issue generation, reflecting the encoded secret. We replaced the fixed 5-round limit with a length-derived safe bound (`max(64, len(raw))`), unquoting to true fixpoint, while failing closed (`_has_percent_encoding`) on unresolved percent-encoding at the bounded limit with `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`, returning structured `outcome: "invalid_input"`, zero facts, and exit code 4. Adapters also defensively fall back to `[REDACTED_ROUTE]` if any unresolved percent-encoding or suspicious delimiter remains.

All defects have been remediated within the strict offline-only, zero-network, zero-credential safety boundary. All 294 tests in the suite pass cleanly.

---

## 2. Audit Findings & Remediations

### Finding 1: Credential-Bearing Route Keys Accepted and Echoed in Unsupported Schema

#### Defect Description
A route key containing URL query credentials or userinfo (e.g., `positions?api_key=SECRET` or `https://user:password@host/positions`) passed validation if it was a non-empty string not starting with `Bearer`. When dispatched to adapters (`BybitAdapter` or `LighterAdapter`), `supports_route(route_key)` returned `False`, and the adapter generated an `unsupported_schema` issue containing the credential verbatim: `Bybit route 'positions?api_key=SECRET' is not supported`.

#### Remediation
- **Recursive Ingest String Inspection:** `contains_auth_elements()` in `motim/reconcile/validator.py` was updated with `_is_auth_string()`:
  - Scans for URL userinfo credentials (`user:pass@host` or sensitive usernames matching `AUTH_KEY_PATTERNS` or canaries).
  - Parses query and form parameters (delimited by `?`, `&`, `;`, `=`) and checks parameter names against normalized `AUTH_KEY_PATTERNS` and values against Bearer, JWT, and canary tokens.
- **Explicit Route Key Validation:** In `validate_sanitized_exchange()`, `request.route_key` is explicitly validated with `_is_auth_string(route_key)`: any credential-bearing route key immediately raises `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`.
- **Zero Facts & Redacted Error:** Reconciler returns structured `outcome: "invalid_input"` and `facts: []`; CLI exits with code `4`.
- **Adapter Defense-in-Depth:** `BybitAdapter` and `LighterAdapter` strip query and userinfo material before formatting unsupported route issue messages (`clean_route = route_key.split("?")[0].split("@")[-1]`).

---

### Finding 2: URL Userinfo Credentials Visible in `Redactor.redact_url()`

#### Defect Description
`Redactor.redact_url()` contained an early-return check `if "?" not in url: return url`. If a URL had no query string (e.g., `https://admin:password@api.example.com/v1/positions`), it returned the URL untouched. Furthermore, `parsed.netloc` was never redacted in `urlunparse`, leaking userinfo even when query parameters were present.

#### Remediation
- **Removed Query-Only Short-Circuit:** Removed `if "?" not in url: return url`.
- **Userinfo Redaction:** Parses `parsed.netloc` (and handles schemeless URLs containing `@`). If `@` is present in `netloc`:
  - If `username:password`, masks `password` to `[REDACTED]`. If `username` matches sensitive name patterns, JWT, Bearer, or canary patterns, masks `username` to `[REDACTED]` as well (`username:[REDACTED]@host` or `[REDACTED]:[REDACTED]@host`).
  - If single token-like userinfo (`token@host`), masks userinfo to `[REDACTED]@host`.
- **Path and Fragment Sanitization:** Scans `path` and `fragment` against JWT, Bearer, canary, and private key regexes; sanitizes query-shaped fragments via `redact_query_string`.
- **Fail-Closed Fallback:** Malformed URLs return `"[REDACTED_URL]"`.

---

### Finding 3: Structural Redaction Limited to Dict/List

#### Defect Description
`Redactor.redact_data_structure()` only checked `isinstance(data, dict)` and `isinstance(data, list)`. Input containers containing `tuple`, `set`, `frozenset`, or non-dict `Mapping` / non-list `Sequence` structures were returned as-is without inspecting or redacting nested elements.

#### Remediation
- **Recursive Container Traversal:**
  - `Mapping` / `dict`: Recursively redacts keys and values, masking values for sensitive keys.
  - `list`: Recursively redacts items as `list`.
  - `tuple`: Recursively redacts items as `tuple`.
  - `set`: Recursively redacts items as `set`.
  - `frozenset`: Recursively redacts items as `frozenset`.
  - Other `Sequence` (excluding `str`, `bytes`, `bytearray`): Recursively redacts items.
  - Other `Set`: Recursively redacts items.
  - `bytes` / `bytearray`: Dispatches to `redact_body_bytes`.
  - `str`: Applies token/JWT/Bearer/canary/private key patterns, and sanitizes URLs/queries if present.
- **Deterministic & Safe:** Preserves container types and deterministic model behavior.

---

### Finding 4: Form-Shaped Body Bytes Preserved When Content Type Unknown

#### Defect Description
`Redactor.redact_body_bytes()` checked `if "x-www-form-urlencoded" in ct or (b"=" in body_bytes and b"&" in body_bytes and not body_bytes.strip().startswith(b"<")):`. If `content_type` was omitted or unknown (`None`, `""`, `text/plain`, `application/octet-stream`), and the payload was a single form-shaped credential (e.g. `b"password=supersecret"`, `b"token=abc"`, `b"api_key=sk-123"`), `b"&"` was absent, causing it to fall through to generic regex replacements that left plaintext secrets intact.

#### Remediation
- **Fail-Closed Form/Key-Value Handler:** Implemented `_redact_form_text(text, *, strict_urlencode=False)`:
  - If `content_type` is explicitly `"x-www-form-urlencoded"`, re-encodes via standard `urlencode`.
  - If `content_type` is unknown or generic text and `b"=" in body_bytes` (without leading `<`), parses key-value pairs across single/multi-parameter and multi-line strings.
  - If sensitive keys (`password`, `token`, `api_key`, `secret`, `n_o_n_c_e`, etc.) are present, replaces sensitive values with `[REDACTED]`.
  - If no sensitive keys are present, preserves benign text/code without percent-encoding mangling.
- **Content-Type Routing Order:** Explicit code/markup types (`javascript`, `xml`, `html`, `yaml`, `css`) are routed to syntax-preserving text redaction before generic form checks.

---

## 3. Changed Files

| File | Changes Made |
|---|---|
| `motim/reconcile/validator.py` | Added `_has_percent_encoding` to detect unresolved percent-encoding; replaced 5-round limit in `_fully_unquote_plus` with length-derived safe bound (`max(64, len(raw))`); updated `_is_auth_string` to fail closed on unresolved percent-encoding at the bounded limit. |
| `motim/reconcile/adapters/bybit.py` | Defensively sanitized unsupported route messages using `_has_percent_encoding` and `_fully_unquote_plus`, falling back to `[REDACTED_ROUTE]` on unresolved encoding or suspicious delimiters. |
| `motim/reconcile/adapters/lighter.py` | Defensively sanitized unsupported route messages using `_has_percent_encoding` and `_fully_unquote_plus`, falling back to `[REDACTED_ROUTE]` on unresolved encoding or suspicious delimiters. |
| `motim/redact.py` | Updated `normalize_sensitive_name` with bounded iterative unquoting (`max(64, len(s))`) to resolve arbitrarily deep percent-encoded sensitive names. |
| `tests/test_reconcile_security.py` | Added parameterized `test_deep_percent_encoded_structural_delimiters_rejected_at_depths_6_to_20` across Bybit and Lighter via API, JSONL strings, and CLI, and added `test_adapter_deep_percent_encoding_unsupported_route_sanitization_defense_in_depth`. |
| `MOTIM_ACCOUNT_READ_AUDIT.md` | Added Round 10 audit specifications. |
| `motim-account-read-report.md` | Updated execution report with Round 10 verification evidence and 294-test suite output. |
| `motim-account-read-audit-fix.md` | This document. |

---

## 4. Verification Commands & Actual Test Output

### 4.1 Full Test Suite (`pytest`)
**Command:** `pytest`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.15, pytest-9.0.2, pluggy-1.6.0
rootdir: C:\Users\houst\PycharmProjects\motim-fork
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.13.0, asyncio-1.3.0, timeout-2.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 294 items

tests\test_auth.py .....................                                 [  7%]
tests\test_cli.py .................                                      [ 12%]
tests\test_client.py ..                                                  [ 13%]
tests\test_config.py ............                                        [ 17%]
tests\test_diff.py .                                                     [ 18%]
tests\test_egress.py ........                                            [ 20%]
tests\test_exchange_db.py .....                                          [ 22%]
tests\test_exchange_writer.py .                                          [ 22%]
tests\test_gates.py ..................                                   [ 28%]
tests\test_linkfinder_integration.py ..                                  [ 29%]
tests\test_reconcile_adapters.py .....                                   [ 31%]
tests\test_reconcile_cli.py ..............                               [ 36%]
tests\test_reconcile_contract.py .....................................   [ 48%]
tests\test_reconcile_no_network.py ...                                   [ 49%]
tests\test_reconcile_security.py ....................................... [ 62%]
..................................................                       [ 79%]
tests\test_redaction.py .................                                [ 85%]
tests\test_service.py ........................                           [ 93%]
tests\test_store.py ..................                                   [100%]

============================= 294 passed in 7.07s =============================
```

### 4.2 Security & Redaction Regressions (`pytest -v tests/test_redaction.py tests/test_reconcile_security.py`)
**Command:** `pytest -v tests/test_redaction.py tests/test_reconcile_security.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================= 106 passed in 0.79s =============================
```

### 4.3 Contract Tests (`pytest -v tests/test_reconcile_contract.py`)
**Command:** `pytest -v tests/test_reconcile_contract.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================== 37 passed in 0.54s ==============================
```

### 4.4 No-Network Guard Tests (`pytest -v tests/test_reconcile_no_network.py`)
**Command:** `pytest -v tests/test_reconcile_no_network.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================== 3 passed in 2.49s ===============================
```

---

## 5. Safety Boundary Verification & Remaining Gaps

- **Offline-Only Invariant:** Verified via AST inspection (`test_ast_rejects_network_and_proxy_imports`) and active socket sabotage (`test_subprocess_execution_under_blocked_socket_guard`). No socket, network client, or network library is imported or invoked.
- **Zero Credentials / Zero Replay:** Deeply percent-encoded credentials (tested through 20 layers of encoding), route fragments, BOM-less UTF-16 credentials, colon-separated plain text secrets, and NUL-bearing binary payloads are rejected or sanitized across all boundaries with zero leaks. No network replay code exists.
- **Remaining Gaps:** None. All findings from the Codex audit of commit `cb21423` are completely resolved with comprehensive regression tests. Live account capture, traffic recording, and network clients remain strictly out of scope.


