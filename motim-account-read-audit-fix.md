# Motim Account-Read Reconciliation — Codex Audit Remediation Report

**Date:** 2026-08-23  
**Project:** Motim Hardened Fork (`motim-fork`)  
**Task:** Codex Audit Remediation (Offline Reconciliation Layer)  
**Status:** Remediated, Verified, and Zero Gaps Remaining  

---

## 1. Executive Summary

This report documents the remediation of the two Codex audit findings identified against commit `3ec9aa6` in the offline-only account-read reconciliation layer of `motim-fork`:

1. **Defect 1 (Security Boundary):** Nested authentication material (e.g. `signature`, `session_id`, `credentials`, `passphrase`, `password`, `auth_token`, `client_secret`) below `response.body.metadata` or any other nested level was fail-open and emitted facts.
2. **Defect 2 (Contract Enforcement):** Any non-empty `request.method` (including mutating verbs such as `POST`, `PUT`, `PATCH`, `DELETE`) was accepted. The contract requires account-read reconciliation to accept normalized `GET` only and reject non-GET methods with structured `invalid_input` output.

Both defects have been remediated within the strict offline-only, zero-network, zero-credential safety boundary. All 207 tests in the suite pass cleanly.

---

## 2. Audit Findings & Remediations

### Finding 1: Nested Authentication Material Fail-Open

#### Defect Description
In previous versions, `AUTH_KEY_PATTERNS` in `motim/reconcile/validator.py` did not include authentication material key families such as `signature`, `session_id`, `credentials`, and `passphrase`. As a result, input records containing metadata with keys such as `response.body.metadata.signature` or `response.body.metadata.session_id` passed validation and emitted account facts.

#### Remediation
- **Expanded Auth Pattern Matching:** Updated `AUTH_KEY_PATTERNS` in `motim/reconcile/validator.py` to include:
  - `"signature"` (captures `signature`, `signatures`, `request_signature`, `api_signature`, `signature_v2`, etc.)
  - `"session"` (captures `session`, `session_id`, `sessionid`, `session_token`, `sessions`, `session_key`, etc.)
  - `"credential"` (captures `credential`, `credentials`, `user_credentials`, etc.)
  - `"passphrase"` (captures `passphrase`, `pass_phrase`, `passphrases`, `api_passphrase`, etc.)
  - `"auth"` (captures `auth`, `authorization`, `authentication`, `auth_token`, `oauth`, etc.)
  - `"password"`, `"secret"`, `"cookie"`, `"token"`, `"bearer"`, `"jwt"`, `"apikey"`, `"api_key"`, `"private_key"`, `"sec_websocket_key"`, `"client_secret"`.
- **Recursive Boundary Scan:** `contains_auth_elements()` recursively scans all nested dictionaries, mappings, sequences, lists, tuples, sets, and frozensets at any depth in the JSON structure.
- **Canary Value Detection:** Extended string and byte canary scans to check for `signature`, `session`, `credential`, `passphrase`, and `auth` sentinel strings.
- **Fail-Closed Result:** If any auth key or value is detected anywhere in the input tree, `validate_sanitized_exchange()` raises `ValidationError("Rejected input containing auth-shaped field [REDACTED]", code="auth_field_detected")`. The engine returns structured `outcome: "invalid_input"` with zero facts emitted, and CLI exits with code `4`. Error messages never echo secret or sentinel values.

---

### Finding 2: Any Non-Empty Request Method Accepted

#### Defect Description
In previous versions, `validator.py` only checked `if not isinstance(method, str) or not method.strip():`. Any non-empty string as `request.method` (including `POST`, `PUT`, `PATCH`, `DELETE`) was accepted.

#### Remediation
- **Normalized GET-Only Enforcement:** In `motim/reconcile/validator.py`, added strict validation checking that `normalized_method = method.strip().upper()` is strictly equal to `"GET"`.
- **Mutating Method Rejection:** Any non-`GET` method (`POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`, `CONNECT`, `TRACE`, etc.) raises `ValidationError("Invalid request.method '<method>': only 'GET' is accepted for account-read reconciliation", code="invalid_input")`.
- **Normalization:** Valid method strings (e.g. `"GET"`, `"get"`, `"  GET  "`) are normalized to `"GET"` in `req["method"]`.
- **Structured Outcome:** Reconciler returns `outcome: "invalid_input"` and zero facts; CLI exits with code `4`.

---

## 3. Changed Files

| File | Changes Made |
|---|---|
| `motim/reconcile/validator.py` | Added `signature`, `session`, `credential`, `passphrase`, `auth`, `authentication` to `AUTH_KEY_PATTERNS`; added canary token patterns for new key families; enforced normalized `GET` only for `request.method`, rejecting mutating HTTP methods. |
| `ACCOUNT_READ_CONTRACT.md` | Updated Non-Negotiable Safety Constraints and Section 2 field definitions to document recursive rejection of `signature`, `session_id`, `credentials`, `passphrase`, and that `request.method` accepts normalized `GET` only. |
| `tests/test_reconcile_security.py` | Added `test_nested_auth_material_key_families_rejected_below_metadata` parameterized over `signature`, `session_id`, `credentials`, `passphrase`, `sessionId`, `user_credentials`, `request_signature`, `api_passphrase` across Python API, JSONL strings, and CLI subprocess execution with sentinel canary leak verification. |
| `tests/test_reconcile_contract.py` | Added `test_non_get_request_methods_rejected_with_invalid_input` (parameterized across `POST`, `post`, `PUT`, `put`, `PATCH`, `patch`, `DELETE`, `delete`, `OPTIONS`, `HEAD`, `CONNECT`, `TRACE`, `UNKNOWN`) and `test_normalized_get_request_method_accepted` (`GET`, `get`, padded whitespace). |
| `tests/test_reconcile_cli.py` | Added `test_cli_reconcile_non_get_method_exit_4` parameterized over `POST`, `PUT`, `PATCH`, `DELETE` verifying exit code 4 and structured JSON `invalid_input` output on stdout. |
| `motim-account-read-report.md` | Updated execution report with Round 4 audit remediation details, updated gate tables, and new test suite evidence (207 passed). |
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
collected 207 items

tests\test_auth.py .....................                                 [ 10%]
tests\test_cli.py .................                                      [ 18%]
tests\test_client.py ..                                                  [ 19%]
tests\test_config.py ............                                        [ 25%]
tests\test_diff.py .                                                     [ 25%]
tests\test_egress.py ........                                            [ 29%]
tests\test_exchange_db.py .....                                          [ 31%]
tests\test_exchange_writer.py .                                          [ 32%]
tests\test_gates.py ..................                                   [ 41%]
tests\test_linkfinder_integration.py ..                                  [ 42%]
tests\test_reconcile_adapters.py .....                                   [ 44%]
tests\test_reconcile_cli.py ..............                               [ 51%]
tests\test_reconcile_contract.py .....................................   [ 69%]
tests\test_reconcile_no_network.py ...                                   [ 70%]
tests\test_reconcile_security.py ..............                          [ 77%]
tests\test_redaction.py .....                                            [ 79%]
tests\test_service.py ........................                           [ 91%]
tests\test_store.py ..................                                   [100%]

============================= 207 passed in 5.74s =============================
```

### 4.2 Security & Canary Leak Tests (`pytest tests/test_reconcile_security.py`)
**Command:** `pytest -v tests/test_reconcile_security.py`  
**Exit Code:** `0`  
**Actual Output:**
```text
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_sentinels_rejected_and_never_emitted_in_api PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_sentinels_rejected_and_never_emitted_in_cli PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[bad_jsonl0-CANARY_DUP_TOP_AUTH_001] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[bad_jsonl1-CANARY_DUP_REQ_AUTH_002] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_duplicate_json_keys_containing_sentinels_rejected_and_redacted[bad_jsonl2-CANARY_DUP_RESP_TOKEN_003] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_secret_scan_nested_tuples_and_sets_rejected_and_never_leaked PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[signature-CANARY_SIG_HEX_abcdef1234567890] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[session_id-CANARY_SESS_ID_998877665544] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[credentials-CANARY_CREDENTIALS_BLOB_AABBCC] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[passphrase-CANARY_PASSPHRASE_SECRET_WORD] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[sessionId-CANARY_CAMEL_SESSION_ID_112233] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[user_credentials-CANARY_USER_CREDS_445566] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[request_signature-CANARY_REQ_SIG_778899] PASSED
tests/test_reconcile_security.py::TestGate5SecurityRegression::test_nested_auth_material_key_families_rejected_below_metadata[api_passphrase-CANARY_API_PASSPHRASE_001122] PASSED

============================== 14 passed in 0.45s ==============================
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
tests/test_reconcile_no_network.py::TestGate4NoNetworkNoReplay::test_no_request_builder_or_secret_fixture_sentinel_emission PASSED

============================== 3 passed in 0.38s ===============================
```

---

## 5. Safety Boundary Verification & Remaining Gaps

- **Offline-Only Invariant:** Verified via AST inspection (`test_ast_rejects_network_and_proxy_imports`) and active socket sabotage (`test_subprocess_execution_under_blocked_socket_guard`). No socket, network client, or network library is imported or invoked.
- **Zero Credentials / Zero Replay:** Input scanning recursively prevents credential-bearing objects from being parsed or processed. No network replay code exists.
- **Remaining Gaps:** None. Both audit items are fully resolved with regression tests. Live account capture, traffic recording, and network clients remain strictly out of scope.
