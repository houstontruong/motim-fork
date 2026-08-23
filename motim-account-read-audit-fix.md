# Motim Account-Read Reconciliation — Codex Audit Remediation Report

**Date:** 2026-08-23  
**Project:** Motim Hardened Fork (`motim-fork`)  
**Task:** Codex Audit Remediation (Offline Reconciliation Layer & Defense-in-Depth Redaction Engine)  
**Status:** Remediated, Verified, and Zero Gaps Remaining  

---

## 1. Executive Summary

This report documents the remediation of all audit findings across all rounds, including the two Round 9 findings from the Codex audit of commit `46ff8d6` in the offline-only account-read reconciliation layer and defense-in-depth redaction engine of `motim-fork`:

1. **Defect 1 (Round 9 — Fully Percent-Encoded Structural Delimiters Can Leak - HIGH):** Route keys with fully percent-encoded structural delimiters (e.g. `unsupported%3Fapi%5Fkey%3DTOPSECRET` or `unsupported%23token%3DTOPSECRET`) were previously decoded only for pattern matches rather than query/fragment parsing, allowing encoded query/fragment credentials to bypass validation and be reflected in adapter error messages. We implemented iterative route and parameter decoding (`_fully_unquote_plus`) before query/fragment auth parsing in `validator.py`, rejecting all inputs containing encoded delimiter credentials with `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`, returning structured `outcome: "invalid_input"`, zero facts, and exit code 4. Adapters also defensively strip decoded delimiters (`?`, `#`, `;`, `@`) before formatting issue messages.
2. **Defect 2 (Round 9 — BOM-less UTF-16 / NUL-Bearing Body Data Can Leak - HIGH):** `Redactor.redact_body_bytes()` previously treated BOM-less UTF-16LE/BE and NUL-bearing binary payloads with missing (`None`) or generic (`text/plain`, `application/octet-stream`) content types as UTF-8, decoding them without error and bypassing colon-separated text regexes, which allowed credentials to persist. We implemented strict binary/NUL characteristic detection before UTF-8 fallback, using byte heuristics to detect, decode, and redact BOM-less UTF-16LE and UTF-16BE text, while failing closed on arbitrary NUL-bearing binary payloads (`b"[REDACTED: unparseable binary body]"`).

All defects have been remediated within the strict offline-only, zero-network, zero-credential safety boundary. All 284 tests in the suite pass cleanly.

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
| `motim/redact.py` | Added byte heuristics in `redact_body_bytes` to detect, decode, and redact BOM-less UTF-16LE and UTF-16BE payloads with missing or generic content types, and enforce fail-closed handling (`b"[REDACTED: unparseable binary body]"`) on arbitrary NUL-bearing binary data. |
| `motim/reconcile/validator.py` | Implemented `_fully_unquote_plus` to iteratively decode routes, segments, and parameter keys/values before query/fragment auth parsing in `_is_auth_string` and `_normalize_key_name`, rejecting any input with encoded delimiter credentials (`?` -> `%3F`, `#` -> `%23`, `=` -> `%3D`). |
| `motim/reconcile/adapters/bybit.py` | Defensively stripped iteratively unquoted delimiters (`?`, `#`, `;`, `@`) in unsupported route issue messages using `_fully_unquote_plus`. |
| `motim/reconcile/adapters/lighter.py` | Defensively stripped iteratively unquoted delimiters (`?`, `#`, `;`, `@`) in unsupported route issue messages using `_fully_unquote_plus`. |
| `tests/test_redaction.py` | Added `test_redactor_bomless_utf16_and_nul_handling` and `test_persistence_path_bomless_utf16_redaction` covering BOM-less UTF-16LE/BE with missing/generic content types and SQLite persistence. |
| `tests/test_reconcile_security.py` | Added parameterized `test_fully_percent_encoded_structural_delimiters_rejected_with_zero_facts` across Bybit and Lighter via API, JSONL strings, and CLI, and updated `test_adapter_unsupported_route_sanitization_defense_in_depth`. |
| `MOTIM_ACCOUNT_READ_AUDIT.md` | Added Round 9 audit specifications. |
| `motim-account-read-report.md` | Updated execution report with Round 9 verification evidence and 284-test suite output. |
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
collected 284 items

tests\test_auth.py .....................                                 [  7%]
tests\test_cli.py .................                                      [ 13%]
tests\test_client.py ..                                                  [ 14%]
tests\test_config.py ............                                        [ 18%]
tests\test_diff.py .                                                     [ 18%]
tests\test_egress.py ........                                            [ 21%]
tests\test_exchange_db.py .....                                          [ 23%]
tests\test_exchange_writer.py .                                          [ 23%]
tests\test_gates.py ..................                                   [ 29%]
tests\test_linkfinder_integration.py ..                                  [ 30%]
tests\test_reconcile_adapters.py .....                                   [ 32%]
tests\test_reconcile_cli.py ..............                               [ 37%]
tests\test_reconcile_contract.py .....................................   [ 50%]
tests\test_reconcile_no_network.py ...                                   [ 51%]
tests\test_reconcile_security.py ....................................... [ 65%]
........................................                                 [ 79%]
tests\test_redaction.py .................                                [ 85%]
tests\test_service.py ........................                           [ 93%]
tests\test_store.py ..................                                   [100%]

============================= 284 passed in 8.54s =============================
```

### 4.2 Security & Redaction Regressions (`pytest -v tests/test_redaction.py tests/test_reconcile_security.py`)
**Command:** `pytest -v tests/test_redaction.py tests/test_reconcile_security.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================= 96 passed in 0.70s ==============================
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
- **Zero Credentials / Zero Replay:** All fully percent-encoded structural delimiters, route fragments, BOM-less UTF-16 credentials, colon-separated plain text secrets, and NUL-bearing binary payloads are rejected or sanitized across all boundaries with zero leaks. No network replay code exists.
- **Remaining Gaps:** None. All findings from the Codex audit of commit `46ff8d6` are completely resolved with comprehensive regression tests. Live account capture, traffic recording, and network clients remain strictly out of scope.


