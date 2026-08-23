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
