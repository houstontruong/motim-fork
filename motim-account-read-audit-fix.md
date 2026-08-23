# Motim Account-Read Reconciliation — Codex Audit Remediation Report

**Date:** 2026-08-23  
**Project:** Motim Hardened Fork (`motim-fork`)  
**Task:** Codex Audit Remediation (Offline Reconciliation Layer & Defense-in-Depth Redaction Engine)  
**Status:** Remediated, Verified, and Zero Gaps Remaining  

---

## 1. Executive Summary

This report documents the remediation of all audit findings across all rounds, including the two Round 11 findings from the Codex audit of commit `08ae77b` in the offline-only account-read reconciliation layer and defense-in-depth redaction engine of `motim-fork`:

1. **Defect 1 (Round 11 — Malformed Percent Sequences Bypass Auth/Redaction - HIGH):** Previously, `_has_percent_encoding()` only matched valid `%XX` triples. Malformed percent sequences such as `api%GG_key`, `api%G0_key`, `api%0G_key`, `api%`, and `pass%word` bypassed `contains_auth_elements()` and `Redactor.is_sensitive_name()`. We updated the validator, redactor, and adapter issue formatting to treat **any remaining percent character (`%`)** in a sensitive-name, key, or route parsing context as unresolved and suspicious after bounded decoding. Any input containing malformed percent sequences in routes, query params, fragments, or payload keys is rejected at ingest with `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`, returning structured `outcome: "invalid_input"`, zero facts emitted, and CLI exit code 4. In `Redactor`, any field or header name with `%` is classified as sensitive and its value is masked to `[REDACTED]`. In adapters, routes with unresolved `%` in their clean segment fall back to `[REDACTED_ROUTE]`.
2. **Defect 2 (Round 11 — Quadratic Decoding CPU Cost - MEDIUM):** The input-length-derived decode bound in prior rounds created potential quadratic CPU scaling on hostile inputs with thousands of repeated `%25` sequences. We replaced the dynamic bound with a small constant depth cap (`MAX_DECODE_DEPTH = 10`), enforced strict maximum length bounds on route keys (`MAX_ROUTE_LENGTH = 1024`) and payload keys (`MAX_FIELD_KEY_LENGTH = 512`), and failed closed immediately on hostile inputs without multi-second CPU processing (verified $< 0.1$s execution).

All defects have been remediated within the strict offline-only, zero-network, zero-credential safety boundary. All 310 tests in the suite pass cleanly.

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
| `motim/reconcile/validator.py` | Added constant depth cap `MAX_DECODE_DEPTH = 10`, `MAX_ROUTE_LENGTH = 1024`, and `MAX_FIELD_KEY_LENGTH = 512`; updated `_fully_unquote_plus` to use small constant cap; updated `_is_auth_string` and `contains_auth_elements` to treat any percent character (`%`) in routes, query params, fragments, and payload keys as unresolved/suspicious, rejecting at ingestion with `invalid_input`, zero facts, and exit code 4. |
| `motim/redact.py` | Updated `normalize_sensitive_name` with constant depth cap `MAX_DECODE_DEPTH = 10` and key length cap `MAX_KEY_LENGTH = 512`; updated `is_sensitive_name` to classify any key with `%` as sensitive, masking values in `redact_data_structure`. |
| `motim/reconcile/adapters/bybit.py` | Defensively sanitized unsupported route issue messages using `_fully_unquote_plus` and falling back to `[REDACTED_ROUTE]` on length violation or if `%` remains in the clean route segment. |
| `motim/reconcile/adapters/lighter.py` | Defensively sanitized unsupported route issue messages using `_fully_unquote_plus` and falling back to `[REDACTED_ROUTE]` on length violation or if `%` remains in the clean route segment. |
| `tests/test_redaction.py` | Added `test_redactor_malformed_percent_sequences_and_hostile_size` verifying sensitive classification, value masking, and non-quadratic execution on hostile inputs. |
| `tests/test_reconcile_security.py` | Added parameterized `test_malformed_percent_sequences_rejected_with_zero_facts` across Bybit and Lighter via direct API, JSONL strings, and CLI; added `test_malformed_percent_field_keys_in_payload_rejected_with_zero_facts`, `test_hostile_size_and_depth_limits_performance`, and `test_adapter_malformed_percent_route_sanitization_defense_in_depth`. |
| `MOTIM_ACCOUNT_READ_AUDIT.md` | Added Round 11 audit specifications. |
| `motim-account-read-report.md` | Updated execution report with Round 11 verification evidence and 310-test suite output. |
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
collected 310 items

tests\test_auth.py .....................                                 [  6%]
tests\test_cli.py .................                                      [ 12%]
tests\test_client.py ..                                                  [ 12%]
tests\test_config.py ............                                        [ 16%]
tests\test_diff.py .                                                     [ 17%]
tests\test_egress.py ........                                            [ 19%]
tests\test_exchange_db.py .....                                          [ 21%]
tests\test_exchange_writer.py .                                          [ 21%]
tests\test_gates.py ..................                                   [ 27%]
tests\test_linkfinder_integration.py ..                                  [ 28%]
tests\test_reconcile_adapters.py .....                                   [ 29%]
tests\test_reconcile_cli.py ..............                               [ 34%]
tests\test_reconcile_contract.py .....................................   [ 46%]
tests\test_reconcile_no_network.py ...                                   [ 47%]
tests\test_reconcile_security.py ....................................... [ 59%]
.................................................................        [ 80%]
tests\test_redaction.py ..................                               [ 86%]
tests\test_service.py ........................                           [ 94%]
tests\test_store.py ..................                                   [100%]

============================= 310 passed in 6.86s =============================
```

### 4.2 Security & Redaction Regressions (`pytest -v tests/test_redaction.py tests/test_reconcile_security.py`)
**Command:** `pytest -v tests/test_redaction.py tests/test_reconcile_security.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================= 122 passed in 0.84s =============================
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
- **Zero Credentials / Zero Replay:** Malformed percent sequences (`%GG`, `%G0`, `%0G`, `%`), deep percent-encoded credentials, route fragments, BOM-less UTF-16 credentials, colon-separated plain text secrets, and NUL-bearing binary payloads are rejected or sanitized across all boundaries with zero leaks. No network replay code exists.
- **Remaining Gaps:** None. All findings from the Codex audit of commit `08ae77b` are completely resolved with comprehensive regression tests. Live account capture, traffic recording, and network clients remain strictly out of scope.


