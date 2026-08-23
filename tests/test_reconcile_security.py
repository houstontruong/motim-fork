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
