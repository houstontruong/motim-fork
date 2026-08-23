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

    @pytest.mark.parametrize(
        "route_key,sentinel",
        [
            ("positions?api_key=CANARY_ROUTE_APIKEY_1122", "CANARY_ROUTE_APIKEY_1122"),
            ("positions?token=CANARY_ROUTE_TOKEN_3344", "CANARY_ROUTE_TOKEN_3344"),
            ("positions?secret=CANARY_ROUTE_SECRET_5566", "CANARY_ROUTE_SECRET_5566"),
            ("positions?password=CANARY_ROUTE_PASSWORD_7788", "CANARY_ROUTE_PASSWORD_7788"),
            ("positions?n_o_n_c_e=CANARY_ROUTE_NONCE_9900", "CANARY_ROUTE_NONCE_9900"),
            ("positions?n-o-n-c-e=CANARY_ROUTE_HYPHEN_NONCE_1234", "CANARY_ROUTE_HYPHEN_NONCE_1234"),
            ("https://user:CANARY_ROUTE_USERINFO_1234@bybit.com/positions", "CANARY_ROUTE_USERINFO_1234"),
            ("https://CANARY_ROUTE_APIKEY_5678@bybit.com/positions", "CANARY_ROUTE_APIKEY_5678"),
            ("positions?authorization=CANARY_ROUTE_AUTH_9012", "CANARY_ROUTE_AUTH_9012"),
            ("positions?session_id=CANARY_ROUTE_SESSION_3456", "CANARY_ROUTE_SESSION_3456"),
            ("positions?signature=CANARY_ROUTE_SIG_7890", "CANARY_ROUTE_SIG_7890"),
        ],
    )
    def test_credential_bearing_route_keys_rejected_with_zero_facts(self, route_key: str, sentinel: str, tmp_path: Path):
        """Credential-bearing URL/userinfo/query route keys are rejected at ingest with zero facts and redacted errors."""
        record = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "route-cred-test-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": route_key},
            "response": {
                "status": 200,
                "body": {
                    "result": {
                        "list": [
                            {
                                "symbol": "BTCUSDT",
                                "side": "Buy",
                                "size": "1.0",
                                "entryPrice": "50000",
                                "markPrice": "50500",
                            }
                        ]
                    }
                },
            },
        }

        # 1. Direct Python API
        res = reconcile([record], "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0
        assert len(res.issues) >= 1
        res_json = json.dumps(res.to_dict())
        assert sentinel not in res_json
        for issue in res.issues:
            assert sentinel not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # 2. JSONL string API
        raw_jsonl = json.dumps(record) + "\n"
        res_jsonl = reconcile(raw_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel not in json.dumps(res_jsonl.to_dict())

        # 3. CLI execution via file
        fixture_file = tmp_path / "route_cred.jsonl"
        fixture_file.write_text(raw_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel not in cli_res.output
        cli_out = json.loads(cli_res.output)
        assert cli_out["outcome"] == "invalid_input"
        assert len(cli_out["facts"]) == 0

    @pytest.mark.parametrize(
        "provider,route_key,sentinel",
        [
            # Percent-encoded query keys across Bybit and Lighter
            ("bybit", "positions?api%5Fkey=CANARY_PCT_APIKEY_11", "CANARY_PCT_APIKEY_11"),
            ("bybit", "positions?api%2dkey=CANARY_PCT_APIKEY_22", "CANARY_PCT_APIKEY_22"),
            ("bybit", "positions?%61%70%69%5f%6b%65%79=CANARY_PCT_APIKEY_33", "CANARY_PCT_APIKEY_33"),
            ("bybit", "positions?token%5fkey=CANARY_PCT_TOK_44", "CANARY_PCT_TOK_44"),
            ("bybit", "positions?secret%5fkey=CANARY_PCT_SEC_55", "CANARY_PCT_SEC_55"),
            ("bybit", "positions?n%5fo%5fn%5fc%5fe=CANARY_PCT_NONCE_66", "CANARY_PCT_NONCE_66"),
            ("bybit", "positions?%70%61%73%73%77%6f%72%64=CANARY_PCT_PASS_77", "CANARY_PCT_PASS_77"),
            ("lighter", "account_positions?api%5Fkey=CANARY_LIGHTER_PCT_88", "CANARY_LIGHTER_PCT_88"),
            ("lighter", "trades?api%2dkey=CANARY_LIGHTER_PCT_99", "CANARY_LIGHTER_PCT_99"),
            ("lighter", "account?%73%65%63%72%65%74=CANARY_LIGHTER_PCT_00", "CANARY_LIGHTER_PCT_00"),
            # Route fragments across Bybit and Lighter
            ("bybit", "positions#api_key=CANARY_FRAG_BYBIT_11", "CANARY_FRAG_BYBIT_11"),
            ("bybit", "positions#token=CANARY_FRAG_BYBIT_22", "CANARY_FRAG_BYBIT_22"),
            ("bybit", "positions#secret=CANARY_FRAG_BYBIT_33", "CANARY_FRAG_BYBIT_33"),
            ("bybit", "positions#api%5Fkey=CANARY_FRAG_BYBIT_44", "CANARY_FRAG_BYBIT_44"),
            ("bybit", "positions#n_o_n_c_e=CANARY_FRAG_BYBIT_55", "CANARY_FRAG_BYBIT_55"),
            ("lighter", "account_positions#api_key=CANARY_FRAG_LIGHTER_11", "CANARY_FRAG_LIGHTER_11"),
            ("lighter", "trades#token=CANARY_FRAG_LIGHTER_22", "CANARY_FRAG_LIGHTER_22"),
            ("lighter", "account#secret=CANARY_FRAG_LIGHTER_33", "CANARY_FRAG_LIGHTER_33"),
            ("lighter", "account_trades#api%5Fkey=CANARY_FRAG_LIGHTER_44", "CANARY_FRAG_LIGHTER_44"),
        ],
    )
    def test_percent_encoded_and_fragment_route_keys_rejected_with_zero_facts(
        self, provider: str, route_key: str, sentinel: str, tmp_path: Path
    ):
        """Percent-encoded auth query keys and route fragment credentials return invalid_input with zero facts."""
        body_content = (
            {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "1.0", "entryPrice": "50000", "markPrice": "50500"}]}}
            if provider == "bybit"
            else {"code": 200, "data": {"positions": [{"market_id": "BTC", "side": "LONG", "size": "1.0", "entry_price": "50000", "mark_price": "50500"}]}}
        )
        record = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": f"pct-frag-{provider}-001",
            "provider": provider,
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": route_key},
            "response": {
                "status": 200,
                "body": body_content,
            },
        }

        # 1. Python API validation
        res_api = reconcile([record], provider, as_of="2026-08-23T14:05:00Z")
        assert res_api.outcome == Outcome.INVALID_INPUT.value
        assert len(res_api.facts) == 0
        assert len(res_api.issues) >= 1
        res_json = json.dumps(res_api.to_dict())
        assert sentinel not in res_json
        for issue in res_api.issues:
            assert sentinel not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # 2. JSONL string validation
        raw_jsonl = json.dumps(record) + "\n"
        res_jsonl = reconcile(raw_jsonl, provider, as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel not in json.dumps(res_jsonl.to_dict())

        # 3. CLI execution validation
        fixture_file = tmp_path / f"pct_frag_{provider}.jsonl"
        fixture_file.write_text(raw_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", provider, "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel not in cli_res.output
        cli_out = json.loads(cli_res.output)
        assert cli_out["outcome"] == "invalid_input"
        assert len(cli_out["facts"]) == 0

    def test_adapter_unsupported_route_sanitization_defense_in_depth(self):
        """Adapters defensively strip query strings, fragments, and userinfo from unsupported route messages."""
        from motim.reconcile.adapters.bybit import BybitAdapter
        from motim.reconcile.adapters.lighter import LighterAdapter

        bybit = BybitAdapter()
        lighter = LighterAdapter()

        canary_frag_1 = "CANARY_ADAPTER_FRAG_SECRET_1122"
        canary_frag_2 = "CANARY_ADAPTER_FRAG_SECRET_3344"
        canary_enc_1 = "CANARY_ADAPTER_ENC_SECRET_5566"
        canary_enc_2 = "CANARY_ADAPTER_ENC_SECRET_7788"

        # 1. Bybit adapter unsupported route with literal fragment
        bybit_exchange = {
            "exchange_id": "bybit-unsupp-001",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": f"unsupported_route#api_key={canary_frag_1}"},
            "response": {"status": 200, "body": {}},
        }
        res_bybit = bybit.reconcile_exchange(bybit_exchange)
        assert not res_bybit.is_supported
        assert len(res_bybit.issues) == 1
        assert canary_frag_1 not in res_bybit.issues[0].message
        assert res_bybit.issues[0].message == "Bybit route 'unsupported_route' is not supported"

        # 2. Lighter adapter unsupported route with literal fragment
        lighter_exchange = {
            "exchange_id": "lighter-unsupp-001",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": f"unsupported_route#token={canary_frag_2}"},
            "response": {"status": 200, "body": {}},
        }
        res_lighter = lighter.reconcile_exchange(lighter_exchange)
        assert not res_lighter.is_supported
        assert len(res_lighter.issues) == 1
        assert canary_frag_2 not in res_lighter.issues[0].message
        assert res_lighter.issues[0].message == "Lighter route 'unsupported_route' is not supported"

        # 3. Bybit adapter unsupported route with fully percent-encoded query delimiter
        bybit_enc_exchange = {
            "exchange_id": "bybit-unsupp-002",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": f"unsupported_route%3Fapi%5Fkey%3D{canary_enc_1}"},
            "response": {"status": 200, "body": {}},
        }
        res_bybit_enc = bybit.reconcile_exchange(bybit_enc_exchange)
        assert not res_bybit_enc.is_supported
        assert len(res_bybit_enc.issues) == 1
        assert canary_enc_1 not in res_bybit_enc.issues[0].message
        assert res_bybit_enc.issues[0].message == "Bybit route 'unsupported_route' is not supported"

        # 4. Lighter adapter unsupported route with fully percent-encoded fragment delimiter
        lighter_enc_exchange = {
            "exchange_id": "lighter-unsupp-002",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": f"unsupported_route%23token%3D{canary_enc_2}"},
            "response": {"status": 200, "body": {}},
        }
        res_lighter_enc = lighter.reconcile_exchange(lighter_enc_exchange)
        assert not res_lighter_enc.is_supported
        assert len(res_lighter_enc.issues) == 1
        assert canary_enc_2 not in res_lighter_enc.issues[0].message
        assert res_lighter_enc.issues[0].message == "Lighter route 'unsupported_route' is not supported"

    @pytest.mark.parametrize(
        "provider,route_key,sentinel",
        [
            # Fully percent-encoded query delimiters (? -> %3F, = -> %3D)
            ("bybit", "unsupported%3Fapi%5Fkey%3DTOPSECRET_CANARY_1", "TOPSECRET_CANARY_1"),
            ("bybit", "unsupported%3fapi%5fkey%3dTOPSECRET_CANARY_2", "TOPSECRET_CANARY_2"),
            ("bybit", "positions%3Fapi%5Fkey%3DTOPSECRET_CANARY_3", "TOPSECRET_CANARY_3"),
            ("bybit", "positions%3Ftoken%3DTOPSECRET_CANARY_4", "TOPSECRET_CANARY_4"),
            ("bybit", "unsupported%3Fsecret%3DTOPSECRET_CANARY_5", "TOPSECRET_CANARY_5"),
            ("bybit", "unsupported%3Fn_o_n_c_e%3DTOPSECRET_CANARY_6", "TOPSECRET_CANARY_6"),
            ("bybit", "unsupported%3F%61%70%69%5f%6b%65%79%3dTOPSECRET_CANARY_7", "TOPSECRET_CANARY_7"),
            # Double percent-encoded query delimiters (? -> %253F, = -> %253D)
            ("bybit", "unsupported%253Fapi%255Fkey%253DTOPSECRET_CANARY_8", "TOPSECRET_CANARY_8"),
            # Fully percent-encoded fragment delimiters (# -> %23, = -> %3D)
            ("bybit", "unsupported%23token%3DTOPSECRET_CANARY_9", "TOPSECRET_CANARY_9"),
            ("bybit", "unsupported%23api%5Fkey%3DTOPSECRET_CANARY_10", "TOPSECRET_CANARY_10"),
            ("bybit", "positions%23secret%3DTOPSECRET_CANARY_11", "TOPSECRET_CANARY_11"),
            ("bybit", "positions%23n%2do%2dn%2dc%2de%3DTOPSECRET_CANARY_12", "TOPSECRET_CANARY_12"),
            # Lighter provider fully percent-encoded query and fragment delimiters
            ("lighter", "trades%3Fapi%5Fkey%3DTOPSECRET_LIGHTER_1", "TOPSECRET_LIGHTER_1"),
            ("lighter", "account_positions%23token%3DTOPSECRET_LIGHTER_2", "TOPSECRET_LIGHTER_2"),
            ("lighter", "unsupported%3Fsecret%3DTOPSECRET_LIGHTER_3", "TOPSECRET_LIGHTER_3"),
            ("lighter", "unsupported%23password%3DTOPSECRET_LIGHTER_4", "TOPSECRET_LIGHTER_4"),
            ("lighter", "account%3F%73%65%63%72%65%74%3dTOPSECRET_LIGHTER_5", "TOPSECRET_LIGHTER_5"),
            ("lighter", "unsupported%253Ftoken%253DTOPSECRET_LIGHTER_6", "TOPSECRET_LIGHTER_6"),
        ],
    )
    def test_fully_percent_encoded_structural_delimiters_rejected_with_zero_facts(
        self, provider: str, route_key: str, sentinel: str, tmp_path: Path
    ):
        """Fully percent-encoded structural delimiters (? -> %3F, # -> %23, = -> %3D) are rejected with invalid_input and zero facts."""
        body_content = (
            {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "1.0", "entryPrice": "50000", "markPrice": "50500"}]}}
            if provider == "bybit"
            else {"code": 200, "data": {"positions": [{"market_id": "BTC", "side": "LONG", "size": "1.0", "entry_price": "50000", "mark_price": "50500"}]}}
        )
        record = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": f"enc-delims-{provider}-001",
            "provider": provider,
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": route_key},
            "response": {
                "status": 200,
                "body": body_content,
            },
        }

        # 1. Direct Python API
        res_api = reconcile([record], provider, as_of="2026-08-23T14:05:00Z")
        assert res_api.outcome == Outcome.INVALID_INPUT.value
        assert len(res_api.facts) == 0
        assert len(res_api.issues) >= 1
        res_json = json.dumps(res_api.to_dict())
        assert sentinel not in res_json
        for issue in res_api.issues:
            assert sentinel not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # 2. JSONL string API
        raw_jsonl = json.dumps(record) + "\n"
        res_jsonl = reconcile(raw_jsonl, provider, as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel not in json.dumps(res_jsonl.to_dict())

        # 3. CLI execution
        fixture_file = tmp_path / f"enc_delims_{provider}.jsonl"
        fixture_file.write_text(raw_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", provider, "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel not in cli_res.output
        cli_out = json.loads(cli_res.output)
        assert cli_out["outcome"] == "invalid_input"
        assert len(cli_out["facts"]) == 0

    @pytest.mark.parametrize(
        "provider,raw_pattern,depth,sentinel",
        [
            ("bybit", "unsupported?api_key={secret}", 6, "TOPSECRET_DEPTH6_BYBIT"),
            ("bybit", "unsupported?token={secret}", 7, "TOPSECRET_DEPTH7_BYBIT"),
            ("bybit", "positions?api_key={secret}", 8, "TOPSECRET_DEPTH8_BYBIT"),
            ("bybit", "positions#secret={secret}", 10, "TOPSECRET_DEPTH10_BYBIT"),
            ("bybit", "unsupported#password={secret}", 15, "TOPSECRET_DEPTH15_BYBIT"),
            ("lighter", "trades?api_key={secret}", 6, "TOPSECRET_DEPTH6_LIGHTER"),
            ("lighter", "account_positions#token={secret}", 7, "TOPSECRET_DEPTH7_LIGHTER"),
            ("lighter", "unsupported?secret={secret}", 10, "TOPSECRET_DEPTH10_LIGHTER"),
            ("lighter", "unsupported#password={secret}", 20, "TOPSECRET_DEPTH20_LIGHTER"),
        ],
    )
    def test_deep_percent_encoded_structural_delimiters_rejected_at_depths_6_to_20(
        self, provider: str, raw_pattern: str, depth: int, sentinel: str, tmp_path: Path
    ):
        """Routes with multi-layer percent-encoded delimiters at depths 6 to 20 are rejected with invalid_input and zero facts."""
        # Construct deeply percent-encoded route key
        # Start with unencoded route
        curr = raw_pattern.format(secret=sentinel)
        # Apply depth layers of percent-encoding to structural delimiters / route
        for _ in range(depth):
            res_parts = []
            for b in curr.encode("utf-8"):
                if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (45, 46, 95, 126):
                    res_parts.append(chr(b))
                else:
                    res_parts.append(f"%{b:02X}")
            curr = "".join(res_parts)
        deep_route = curr

        body_content = (
            {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "1.0", "entryPrice": "50000", "markPrice": "50500"}]}}
            if provider == "bybit"
            else {"code": 200, "data": {"positions": [{"market_id": "BTC", "side": "LONG", "size": "1.0", "entry_price": "50000", "mark_price": "50500"}]}}
        )
        record = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": f"deep-enc-{provider}-d{depth}",
            "provider": provider,
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": deep_route},
            "response": {
                "status": 200,
                "body": body_content,
            },
        }

        # 1. Direct Python API
        res_api = reconcile([record], provider, as_of="2026-08-23T14:05:00Z")
        assert res_api.outcome == Outcome.INVALID_INPUT.value
        assert len(res_api.facts) == 0
        assert len(res_api.issues) >= 1
        res_json = json.dumps(res_api.to_dict())
        assert sentinel not in res_json
        for issue in res_api.issues:
            assert sentinel not in issue.message
            assert "[REDACTED]" in issue.message or "auth" in issue.message.lower()

        # 2. JSONL string API
        raw_jsonl = json.dumps(record) + "\n"
        res_jsonl = reconcile(raw_jsonl, provider, as_of="2026-08-23T14:05:00Z")
        assert res_jsonl.outcome == Outcome.INVALID_INPUT.value
        assert len(res_jsonl.facts) == 0
        assert sentinel not in json.dumps(res_jsonl.to_dict())

        # 3. CLI execution
        fixture_file = tmp_path / f"deep_enc_{provider}_d{depth}.jsonl"
        fixture_file.write_text(raw_jsonl, encoding="utf-8")
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", provider, "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        assert sentinel not in cli_res.output
        cli_out = json.loads(cli_res.output)
        assert cli_out["outcome"] == "invalid_input"
        assert len(cli_out["facts"]) == 0

    def test_adapter_deep_percent_encoding_unsupported_route_sanitization_defense_in_depth(self):
        """Adapters defensively sanitize routes with 6+ layers of percent-encoding."""
        from motim.reconcile.adapters.bybit import BybitAdapter
        from motim.reconcile.adapters.lighter import LighterAdapter

        bybit = BybitAdapter()
        lighter = LighterAdapter()

        canary_d6 = "CANARY_ADAPTER_DEPTH6_SECRET_9988"
        canary_d12 = "CANARY_ADAPTER_DEPTH12_SECRET_7766"

        # Construct 6-layer encoded route for Bybit
        curr6 = f"unsupported_route?api_key={canary_d6}"
        for _ in range(6):
            parts = []
            for b in curr6.encode("utf-8"):
                if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (45, 46, 95, 126):
                    parts.append(chr(b))
                else:
                    parts.append(f"%{b:02X}")
            curr6 = "".join(parts)

        bybit_exchange = {
            "exchange_id": "bybit-deep-001",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": curr6},
            "response": {"status": 200, "body": {}},
        }
        res_bybit = bybit.reconcile_exchange(bybit_exchange)
        assert not res_bybit.is_supported
        assert len(res_bybit.issues) == 1
        assert canary_d6 not in res_bybit.issues[0].message
        assert res_bybit.issues[0].message == "Bybit route 'unsupported_route' is not supported"

        # Construct 12-layer encoded route for Lighter
        curr12 = f"unsupported_route#token={canary_d12}"
        for _ in range(12):
            parts = []
            for b in curr12.encode("utf-8"):
                if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (45, 46, 95, 126):
                    parts.append(chr(b))
                else:
                    parts.append(f"%{b:02X}")
            curr12 = "".join(parts)

        lighter_exchange = {
            "exchange_id": "lighter-deep-001",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": curr12},
            "response": {"status": 200, "body": {}},
        }
        res_lighter = lighter.reconcile_exchange(lighter_exchange)
        assert not res_lighter.is_supported
        assert len(res_lighter.issues) == 1
        assert canary_d12 not in res_lighter.issues[0].message
        assert res_lighter.issues[0].message == "Lighter route 'unsupported_route' is not supported"






