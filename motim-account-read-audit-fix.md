# Motim Account-Read Reconciliation — Codex Audit Remediation Report

**Date:** 2026-08-23  
**Project:** Motim Hardened Fork (`motim-fork`)  
**Task:** Codex Audit Remediation (Offline Reconciliation Layer & Defense-in-Depth Redaction Engine)  
**Status:** Remediated, Verified, and Zero Gaps Remaining  

---

## 1. Executive Summary

This report documents the remediation of all four Codex audit findings in the offline-only account-read reconciliation layer and defense-in-depth redaction engine of `motim-fork`:

1. **Defect 1 (Security Boundary — Credential-Bearing Route Keys Echoed in Unsupported Schema):** A route key containing URL query credentials or URL userinfo was previously accepted at reconciliation ingest and could be echoed verbatim in adapter `unsupported_schema` issues. Credential-bearing URL/userinfo/query material in `route_key` (and throughout input records) is now strictly rejected at ingest with `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`, returning structured `outcome: "invalid_input"`, zero facts emitted, and CLI exit code `4`. Error messages are strictly redacted.
2. **Defect 2 (Defense-in-Depth — URL Userinfo Credentials Visible in `Redactor.redact_url()`):** `Redactor.redact_url()` previously bypassed redaction when `?` was not present in the URL and did not sanitize `parsed.netloc`. Sanitization now unconditionally inspects URLs with or without query strings, parses `netloc` userinfo, robustly masks password and sensitive user credentials as `[REDACTED]`, sanitizes query parameters, and regex-masks path/fragment tokens.
3. **Defect 3 (Defense-in-Depth — Structural Redaction Limited to Dict/List):** `Redactor.redact_data_structure()` previously traversed only `dict` and `list`, leaving sensitive values inside `tuple`, `set`, `frozenset`, custom `Mapping`, and `Sequence` containers unredacted. Structural redaction is now safely recursive across all container types while maintaining deterministic and model-compatible outputs.
4. **Defect 4 (Defense-in-Depth — Form-Shaped Body Bytes Preserved When Content Type Unknown):** `Redactor.redact_body_bytes()` previously required both `b"="` and `b"&"` when content type was unknown, allowing single form-shaped auth fields (e.g. `password=supersecret`, `token=abc`, `api_key=sk-123`, `n_o_n_c_e=nonce123`) to pass through unredacted. Fail-closed form and key-value sanitization now detects and masks sensitive keys/values across single/multi-parameter and single/multi-line payloads without corrupting legitimate benign content or code.

All defects have been remediated within the strict offline-only, zero-network, zero-credential safety boundary. All 240 tests in the suite pass cleanly.

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
| `motim/reconcile/validator.py` | Enhanced `contains_auth_elements` with `_is_auth_string` inspecting URL userinfo and query credentials; added explicit `route_key` auth validation in `validate_sanitized_exchange`; updated `BEARER_PATTERN` regex matching. |
| `motim/reconcile/adapters/bybit.py` | Defense-in-depth: sanitized `route_key` in unsupported route issue messages. |
| `motim/reconcile/adapters/lighter.py` | Defense-in-depth: sanitized `route_key` in unsupported route issue messages. |
| `motim/redact.py` | Updated `redact_url` to sanitize userinfo on URLs with/without query strings; updated `redact_data_structure` to recursively handle `tuple`, `set`, `frozenset`, `Mapping`, and `Sequence`; added `_redact_form_text` and updated `redact_body_bytes` for fail-closed form sanitization. |
| `tests/test_redaction.py` | Added unit tests: `test_redactor_url_userinfo_redaction`, `test_redactor_recursive_containers_data_structure`, `test_redactor_body_bytes_unknown_content_type_fail_closed`. |
| `tests/test_reconcile_security.py` | Added parameterized regression `test_credential_bearing_route_keys_rejected_with_zero_facts` testing API, JSONL strings, and CLI subprocess execution across query credentials and userinfo variants with sentinel canary assertions. |
| `MOTIM_ACCOUNT_READ_AUDIT.md` | Added Round 7 audit specifications. |
| `ACCOUNT_READ_CONTRACT.md` | Documented strict rejection of credential-bearing route keys at ingest. |
| `motim-account-read-report.md` | Updated execution report with Round 7 remediation details and 240-test suite evidence. |
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
collected 240 items

tests\test_auth.py .....................                                 [  8%]
tests\test_cli.py .................                                      [ 15%]
tests\test_client.py ..                                                  [ 16%]
tests\test_config.py ............                                        [ 21%]
tests\test_diff.py .                                                     [ 22%]
tests\test_egress.py ........                                            [ 25%]
tests\test_exchange_db.py .....                                          [ 27%]
tests\test_exchange_writer.py .                                          [ 27%]
tests\test_gates.py ..................                                   [ 35%]
tests\test_linkfinder_integration.py ..                                  [ 36%]
tests\test_reconcile_adapters.py .....                                   [ 38%]
tests\test_reconcile_cli.py ..............                               [ 44%]
tests\test_reconcile_contract.py .....................................   [ 59%]
tests\test_reconcile_no_network.py ...                                   [ 60%]
tests\test_reconcile_security.py ....................................... [ 77%]
..                                                                       [ 77%]
tests\test_redaction.py ...........                                      [ 82%]
tests\test_service.py ........................                           [ 92%]
tests\test_store.py ..................                                   [100%]

============================= 240 passed in 5.93s =============================
```

### 4.2 Security & Redaction Regressions (`pytest -v tests/test_redaction.py tests/test_reconcile_security.py`)
**Command:** `pytest -v tests/test_redaction.py tests/test_reconcile_security.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.15, pytest-9.0.2, pluggy-1.6.0
rootdir: C:\Users\houst\PycharmProjects\motim-fork
configfile: pyproject.toml
plugins: anyio-4.13.0, asyncio-1.3.0, timeout-2.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 52 items

tests/test_redaction.py::test_redactor_header_redaction PASSED           [  1%]
tests/test_redaction.py::test_redactor_query_param_redaction PASSED      [  3%]
tests/test_redaction.py::test_redactor_json_body_redaction PASSED        [  5%]
tests/test_redaction.py::test_redactor_raw_body_bytes_redaction PASSED   [  7%]
tests/test_redaction.py::test_redactor_separator_normalization_headers PASSED [  9%]
tests/test_redaction.py::test_redactor_separator_normalization_query_string PASSED [ 11%]
tests/test_redaction.py::test_redactor_separator_normalization_data_structure PASSED [ 13%]
tests/test_redaction.py::test_pipeline_redaction_before_persistence PASSED [ 15%]
tests/test_redaction.py::test_redactor_url_userinfo_redaction PASSED     [ 17%]
tests/test_redaction.py::test_redactor_recursive_containers_data_structure PASSED [ 19%]
tests/test_redaction.py::test_redactor_body_bytes_unknown_content_type_fail_closed PASSED [ 21%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_sentinels_rejected_and_never_emitted_in_api PASSED [ 23%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_sentinels_rejected_and_never_emitted_in_cli PASSED [ 25%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-top-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "route_key": "positions", "authorization": "Bearer CANARY_DUP_TOP_AUTH_001"}, "request": {"method": "GET", "route_key": "positions"}, "response": {"status": 200, "body": {}}}-CANARY_DUP_TOP_AUTH_001] PASSED [ 26%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-req-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "secret_header": "Bearer CANARY_DUP_REQ_AUTH_002", "secret_header": "clean", "route_key": "positions"}, "response": {"status": 200, "body": {}}}-CANARY_DUP_REQ_AUTH_002] PASSED [ 28%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-resp-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "route_key": "positions"}, "response": {"status": 200, "token": "CANARY_DUP_RESP_TOKEN_003", "token": "clean", "body": {}}}-CANARY_DUP_RESP_TOKEN_003] PASSED [ 30%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_scan_nested_tuples_and_sets_rejected_and_never_leaked PASSED [ 32%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[signature-CANARY_SIG_HEX_abcdef1234567890] PASSED [ 34%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[session_id-CANARY_SESS_ID_998877665544] PASSED [ 36%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[credentials-CANARY_CREDENTIALS_BLOB_AABBCC] PASSED [ 38%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[passphrase-CANARY_PASSPHRASE_SECRET_WORD] PASSED [ 40%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[sessionId-CANARY_CAMEL_SESSION_ID_112233] PASSED [ 42%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[user_credentials-CANARY_USER_CREDS_445566] PASSED [ 44%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[request_signature-CANARY_REQ_SIG_778899] PASSED [ 46%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[api_passphrase-CANARY_API_PASSPHRASE_001122] PASSED [ 48%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[nonce-CANARY_NONCE_VALUE_1234567890] PASSED [ 50%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[n_o_n_c_e-CANARY_SPLIT_UNDERSCORE_NONCE_123456] PASSED [ 51%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[n-o-n-c-e-CANARY_SPLIT_HYPHEN_NONCE_654321] PASSED [ 53%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[x_n_o_n_c_e-CANARY_SPLIT_X_UNDERSCORE_NONCE_778899] PASSED [ 55%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[x-n-o-n-c-e-CANARY_SPLIT_X_HYPHEN_NONCE_998877] PASSED [ 57%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[request_nonce-CANARY_REQ_NONCE_9876543210] PASSED [ 59%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[api_nonce-CANARY_API_NONCE_AABBCCDDEEFF] PASSED [ 61%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[client_nonce-CANARY_CLIENT_NONCE_11223344] PASSED [ 63%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[x_nonce-CANARY_X_NONCE_55667788] PASSED [ 65%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[x-nonce-CANARY_X_HYPHEN_NONCE_990011] PASSED [ 67%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[nonce_str-CANARY_NONCE_STR_22334455] PASSED [ 69%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[Nonce-CANARY_PASCAL_NONCE_66778899] PASSED [ 71%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[NONCE-CANARY_UPPER_NONCE_00112233] PASSED [ 73%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[N_O_N_C_E-CANARY_UPPER_SPLIT_NONCE_112244] PASSED [ 75%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[N-O-N-C-E-CANARY_UPPER_HYPHEN_SPLIT_NONCE_442211] PASSED [ 76%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_nonce_rejection_reproduction_and_zero_facts PASSED [ 78%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?api_key=CANARY_ROUTE_APIKEY_1122-CANARY_ROUTE_APIKEY_1122] PASSED [ 80%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?token=CANARY_ROUTE_TOKEN_3344-CANARY_ROUTE_TOKEN_3344] PASSED [ 82%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?secret=CANARY_ROUTE_SECRET_5566-CANARY_ROUTE_SECRET_5566] PASSED [ 84%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?password=CANARY_ROUTE_PASSWORD_7788-CANARY_ROUTE_PASSWORD_7788] PASSED [ 86%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?n_o_n_c_e=CANARY_ROUTE_NONCE_9900-CANARY_ROUTE_NONCE_9900] PASSED [ 88%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?n-o-n-c-e=CANARY_ROUTE_HYPHEN_NONCE_1234-CANARY_ROUTE_HYPHEN_NONCE_1234] PASSED [ 90%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[https://user:CANARY_ROUTE_USERINFO_1234@bybit.com/positions-CANARY_ROUTE_USERINFO_1234] PASSED [ 92%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[https://CANARY_ROUTE_APIKEY_5678@bybit.com/positions-CANARY_ROUTE_APIKEY_5678] PASSED [ 94%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?authorization=CANARY_ROUTE_AUTH_9012-CANARY_ROUTE_AUTH_9012] PASSED [ 96%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?session_id=CANARY_ROUTE_SESSION_3456-CANARY_ROUTE_SESSION_3456] PASSED [ 98%]
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_credential_bearing_route_keys_rejected_with_zero_facts[positions?signature=CANARY_ROUTE_SIG_7890-CANARY_ROUTE_SIG_7890] PASSED [100%]

============================= 52 passed in 0.35s ==============================
```

### 4.3 Contract Tests (`pytest tests/test_reconcile_contract.py`)
**Command:** `pytest -v tests/test_reconcile_contract.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_canonical_decimal_strings PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_parse_rfc3339_z PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_strict_mode_rejects_unknown_top_level_fields PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_reject_duplicate_exchange_ids_in_batch PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_reject_auth_shaped_fields_with_redacted_error PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_source_traceability PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_deterministic_staleness PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_exact_vs_conflicting_deduplication PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_finite_decimals_rejected PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_response_status_boolean_rejected PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_deduplication_order_independence_and_staleness PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_reconcile_negative_max_age_seconds PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_direct_jsonl_long_string_and_special_chars PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_source_line_numbering_with_leading_blank_lines PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_iterable_dict_non_finite_rejection PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_reconcile_max_age_seconds_rejects_floats_and_non_finites PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_path_handling_with_brackets_and_special_names PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_literal_jsonl_string_does_not_read_same_named_file PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_datetime_as_of_aware_utc_conversion_and_naive_rejection PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_invalid_direct_api_types_return_structured_invalid_input PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[POST] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[post] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[PUT] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[put] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[PATCH] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[patch] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[DELETE] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[delete] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[OPTIONS] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[HEAD] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[CONNECT] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[TRACE] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_non_get_request_methods_rejected_with_invalid_input[UNKNOWN] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_normalized_get_request_method_accepted[GET] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_normalized_get_request_method_accepted[get] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_normalized_get_request_method_accepted[  GET  ] PASSED
tests/test_reconcile_contract.py::TestGate1ContractRequirements::test_normalized_get_request_method_accepted[  get  ] PASSED

============================== 37 passed in 0.54s ==============================
```

### 4.4 No-Network Guard Tests (`pytest tests/test_reconcile_no_network.py`)
**Command:** `pytest -v tests/test_reconcile_no_network.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
tests/test_reconcile_no_network.py::TestGate4NoNetworkNoReplay::test_ast_rejects_network_and_proxy_imports PASSED
tests/test_reconcile_no_network.py::TestGate4NoNetworkNoReplay::test_subprocess_execution_under_blocked_socket_guard PASSED
tests/test_reconcile_no_network.py::TestGate4NoNetworkNoReplay::test_no_runnable_request_or_replay_construction PASSED

============================== 3 passed in 2.65s ===============================
```

---

## 5. Safety Boundary Verification & Remaining Gaps

- **Offline-Only Invariant:** Verified via AST inspection (`test_ast_rejects_network_and_proxy_imports`) and active socket sabotage (`test_subprocess_execution_under_blocked_socket_guard`). No socket, network client, or network library is imported or invoked.
- **Zero Credentials / Zero Replay:** Credential-bearing route keys, URL userinfo, query credentials, and body forms are rejected or sanitized across all boundaries with zero leaks. No network replay code exists.
- **Remaining Gaps:** None. All four confidentiality findings from the Codex audit are completely resolved with regression tests. Live account capture, traffic recording, and network clients remain strictly out of scope.


