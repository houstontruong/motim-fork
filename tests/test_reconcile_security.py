"""Security regression and sentinel canary leak audit tests (Gate 5)."""

from __future__ import annotations

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from motim.cli.main import cli
from motim.reconcile import Outcome, reconcile

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reconciliation"

SENTINEL_VALUES = (
    "eyCanaryBearerSecretToken12345.eyHeaderPayload.Signature",
    "canary_session_cookie_9988",
    "canary_api_key_secret_7766",
    "canary_password_secret_5544",
    "canary_auth_token_3322",
    "canary_nonce_secret_8899",
)


class TestGate5SecurityRegression:
    """Gate 5: Security regression tests ensuring secrets are rejected and never leaked."""

    def test_secret_sentinels_rejected_and_never_emitted_in_api(self):
        """Reconciliation API strictly rejects secrets and never leaks canary strings in output or issues."""
        fixture_path = FIXTURES_DIR / "security_secret_sentinels.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.INVALID_INPUT.value
        assert len(result.facts) == 0

        # Check full serialized JSON string
        result_json = json.dumps(result.to_dict())
        for sentinel in SENTINEL_VALUES:
            assert sentinel not in result_json, f"Security leak! Sentinel '{sentinel}' leaked into result JSON"

        # Check issues messages
        for issue in result.issues:
            for sentinel in SENTINEL_VALUES:
                assert sentinel not in issue.message, f"Security leak! Sentinel '{sentinel}' leaked into issue message"
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

    def test_secret_sentinels_rejected_and_never_emitted_in_cli(self):
        """CLI strictly rejects secrets with exit 4 and never prints sentinels to stdout or stderr."""
        runner = CliRunner()
        fixture_path = FIXTURES_DIR / "security_secret_sentinels.jsonl"
        cli_result = runner.invoke(
            cli,
            [
                "reconcile",
                "--input",
                str(fixture_path),
                "--provider",
                "bybit",
                "--as-of",
                "2026-08-23T14:05:00Z",
            ],
        )

        assert cli_result.exit_code == 4

        # Audit both stdout and stderr
        for sentinel in SENTINEL_VALUES:
            assert sentinel not in cli_result.output, f"Security leak! Sentinel '{sentinel}' found in CLI output"

        # Audit parsed JSON
        parsed = json.loads(cli_result.output)
        assert parsed["outcome"] == "invalid_input"
        assert len(parsed["facts"]) == 0

    @pytest.mark.parametrize(
        "bad_jsonl,sentinel",
        [
            (
                '{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-top-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "route_key": "positions", "authorization": "Bearer CANARY_DUP_TOP_AUTH_001"}, "request": {"method": "GET", "route_key": "positions"}, "response": {"status": 200, "body": {}}}',
                "CANARY_DUP_TOP_AUTH_001",
            ),
            (
                '{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-req-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "secret_header": "Bearer CANARY_DUP_REQ_AUTH_002", "secret_header": "clean", "route_key": "positions"}, "response": {"status": 200, "body": {}}}',
                "CANARY_DUP_REQ_AUTH_002",
            ),
            (
                '{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "dup-resp-1", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "route_key": "positions"}, "response": {"status": 200, "token": "CANARY_DUP_RESP_TOKEN_003", "token": "clean", "body": {}}}',
                "CANARY_DUP_RESP_TOKEN_003",
            ),
        ],
    )
    def test_duplicate_json_keys_containing_sentinels_rejected_and_redacted(self, tmp_path: Path, bad_jsonl: str, sentinel: str):
        """Duplicate keys at top-level or nested levels are rejected at parse time and never expose secrets."""
        # 1. API test
        res = reconcile(bad_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0
        res_json = json.dumps(res.to_dict())
        assert sentinel not in res_json
        for issue in res.issues:
            assert sentinel not in issue.message
            assert "[REDACTED]" in issue.message

        # 2. CLI test
        fixture_file = tmp_path / f"dup_key_{sentinel}.jsonl"
        fixture_file.write_text(bad_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel not in cli_res.output

    def test_secret_scan_nested_tuples_and_sets_rejected_and_never_leaked(self):
        """Direct API input with secret sentinels inside nested tuples, sets, and frozensets must be rejected without leaks."""
        sentinel_tuple = "CANARY_SECRET_IN_TUPLE_998811"
        sentinel_set = "CANARY_SECRET_IN_SET_887722"
        sentinel_frozenset = "CANARY_SECRET_IN_FROZENSET_776633"

        # 1. Nested tuple in response body
        exchange_tuple = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "secret-tuple-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {
                    "nested_items": (f"Bearer {sentinel_tuple}", "regular_item"),
                },
            },
        }

        # 2. Nested set in response body
        exchange_set = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "secret-set-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {
                    "tags": {sentinel_set, "tag_clean"},
                },
            },
        }

        # 3. Nested frozenset in request
        exchange_frozenset = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "secret-frozenset-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {
                "method": "GET",
                "route_key": "positions",
            },
            "response": {
                "status": 200,
                "body": {
                    "auth_elements": frozenset([f"Bearer {sentinel_frozenset}"]),
                },
            },
        }

        for ex_dict, sentinel in [
            (exchange_tuple, sentinel_tuple),
            (exchange_set, sentinel_set),
            (exchange_frozenset, sentinel_frozenset),
        ]:
            res = reconcile([ex_dict], "bybit", as_of="2026-08-23T14:05:00Z")
            assert res.outcome == Outcome.INVALID_INPUT.value
            assert len(res.facts) == 0

            # Audit full result serialization
            res_json = json.dumps(res.to_dict())
            assert sentinel not in res_json, f"Sentinel {sentinel} leaked in result JSON"

            # Audit issues
            assert len(res.issues) >= 1
            for issue in res.issues:
                assert sentinel not in issue.message, f"Sentinel {sentinel} leaked in issue message"
                assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

    @pytest.mark.parametrize(
        "auth_key,sentinel_value",
        [
            ("signature", "CANARY_SIG_HEX_abcdef1234567890"),
            ("session_id", "CANARY_SESS_ID_998877665544"),
            ("credentials", "CANARY_CREDENTIALS_BLOB_AABBCC"),
            ("passphrase", "CANARY_PASSPHRASE_SECRET_WORD"),
            ("sessionId", "CANARY_CAMEL_SESSION_ID_112233"),
            ("user_credentials", "CANARY_USER_CREDS_445566"),
            ("request_signature", "CANARY_REQ_SIG_778899"),
            ("api_passphrase", "CANARY_API_PASSPHRASE_001122"),
            ("nonce", "CANARY_NONCE_VALUE_1234567890"),
            ("n_o_n_c_e", "CANARY_SPLIT_UNDERSCORE_NONCE_123456"),
            ("n-o-n-c-e", "CANARY_SPLIT_HYPHEN_NONCE_654321"),
            ("x_n_o_n_c_e", "CANARY_SPLIT_X_UNDERSCORE_NONCE_778899"),
            ("x-n-o-n-c-e", "CANARY_SPLIT_X_HYPHEN_NONCE_998877"),
            ("request_nonce", "CANARY_REQ_NONCE_9876543210"),
            ("api_nonce", "CANARY_API_NONCE_AABBCCDDEEFF"),
            ("client_nonce", "CANARY_CLIENT_NONCE_11223344"),
            ("x_nonce", "CANARY_X_NONCE_55667788"),
            ("x-nonce", "CANARY_X_HYPHEN_NONCE_990011"),
            ("nonce_str", "CANARY_NONCE_STR_22334455"),
            ("Nonce", "CANARY_PASCAL_NONCE_66778899"),
            ("NONCE", "CANARY_UPPER_NONCE_00112233"),
            ("N_O_N_C_E", "CANARY_UPPER_SPLIT_NONCE_112244"),
            ("N-O-N-C-E", "CANARY_UPPER_HYPHEN_SPLIT_NONCE_442211"),
        ],
    )
    def test_nested_auth_material_key_families_rejected_below_metadata(self, auth_key: str, sentinel_value: str, tmp_path: Path):
        """Authentication material keys (signature, session_id, credentials, passphrase, nonce) below response.body.metadata are rejected with zero facts."""
        # 1. Direct Python API (nested dictionary below response.body.metadata)
        exchange_dict = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": f"nested-auth-{auth_key}-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {
                    "result": {
                        "list": [
                            {
                                "symbol": "BTCUSDT",
                                "side": "Buy",
                                "size": "0.5",
                                "entryPrice": "50000",
                                "markPrice": "51000",
                            }
                        ]
                    },
                    "metadata": {
                        auth_key: sentinel_value,
                        "request_context": {"trace_id": "trace-123"},
                    },
                },
            },
        }

        res_api = reconcile([exchange_dict], "bybit", as_of="2026-08-23T14:05:00Z")
        assert res_api.outcome == Outcome.INVALID_INPUT.value
        assert len(res_api.facts) == 0
        assert len(res_api.issues) >= 1
        res_json = json.dumps(res_api.to_dict())
        assert sentinel_value not in res_json
        for issue in res_api.issues:
            assert sentinel_value not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # 2. JSONL string / file format
        jsonl_str = json.dumps(exchange_dict) + "\n"
        res_jsonl = reconcile(jsonl_str, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel_value not in json.dumps(res_jsonl.to_dict())

        # 3. CLI execution via file
        fixture_file = tmp_path / f"nested_{auth_key}.jsonl"
        fixture_file.write_text(jsonl_str, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel_value not in cli_res.output
        cli_data = json.loads(cli_res.output)
        assert cli_data["outcome"] == "invalid_input"
        assert len(cli_data["facts"]) == 0

    def test_nested_nonce_rejection_reproduction_and_zero_facts(self, tmp_path: Path):
        """Direct audit reproduction: syntactically valid GET record with response.body.metadata.nonce returns invalid_input and zero facts."""
        sentinel_nonce = "CANARY_AUDIT_NONCE_FAIL_OPEN_PROOF_998877"
        record = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "audit-nonce-repro-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {
                    "result": {
                        "list": [
                            {
                                "symbol": "ETHUSDT",
                                "side": "Buy",
                                "size": "10.0",
                                "entryPrice": "3000",
                                "markPrice": "3050",
                            }
                        ]
                    },
                    "metadata": {
                        "nonce": sentinel_nonce,
                    },
                },
            },
        }

        # Direct Python API validation
        res = reconcile([record], "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0
        assert len(res.issues) >= 1
        res_json = json.dumps(res.to_dict())
        assert sentinel_nonce not in res_json
        for issue in res.issues:
            assert sentinel_nonce not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # Direct JSONL string validation
        raw_jsonl = json.dumps(record) + "\n"
        res_jsonl = reconcile(raw_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel_nonce not in json.dumps(res_jsonl.to_dict())

        # CLI subprocess execution validation
        jsonl_path = tmp_path / "nonce_repro.jsonl"
        jsonl_path.write_text(raw_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(jsonl_path), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel_nonce not in cli_res.output
        cli_out = json.loads(cli_res.output)
        assert cli_out["outcome"] == "invalid_input"
        assert len(cli_out["facts"]) == 0


