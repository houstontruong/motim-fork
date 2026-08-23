"""Verification tests for CLI smoke (Gate 3), No-Network guard (Gate 4), and Security Sentinels (Gate 5)."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from motim.cli.main import cli
from motim.reconcile import Outcome, reconcile

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reconciliation"
REPO_ROOT = Path(__file__).parent.parent
PYTHON_EXE = sys.executable


class TestGate3CLISmoke:
    """Gate 3: CLI smoke tests for reconcile, facts, and issues commands."""

    def test_cli_reconcile_bybit_ok_exit_0(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "bybit_all_facts.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert data["schema_version"] == "motim.account_read.v1"
        assert data["provider"] == "bybit"
        assert data["outcome"] == Outcome.OK.value
        assert len(data["facts"]) >= 5

    def test_cli_reconcile_lighter_ok_exit_0(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "lighter_all_facts.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "lighter", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert data["schema_version"] == "motim.account_read.v1"
        assert data["provider"] == "lighter"
        assert data["outcome"] == Outcome.OK.value
        assert len(data["facts"]) >= 5

    def test_cli_reconcile_partial_exit_2(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "bybit_mixed.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 2
        data = json.loads(res.output)
        assert data["outcome"] == Outcome.PARTIAL.value
        assert len(data["facts"]) == 1
        assert len(data["issues"]) >= 1

    def test_cli_reconcile_unsupported_schema_exit_3(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "unknown_route.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 3
        data = json.loads(res.output)
        assert data["outcome"] == Outcome.UNSUPPORTED_SCHEMA.value
        assert len(data["facts"]) == 0
        assert any(i["code"] == "unsupported_schema" for i in data["issues"])

    def test_cli_reconcile_invalid_input_exit_4(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "invalid_contract.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 4
        data = json.loads(res.output)
        assert data["outcome"] == Outcome.INVALID_INPUT.value
        assert len(data["facts"]) == 0

    def test_cli_reconcile_negative_max_age_exit_4(self):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "bybit_all_facts.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z", "--max-age-seconds", "-10"],
        )
        assert res.exit_code == 4
        data = json.loads(res.output)
        assert data["outcome"] == Outcome.INVALID_INPUT.value
        assert len(data["facts"]) == 0
        assert any(i["code"] == "invalid_input" for i in data["issues"])

    @pytest.mark.parametrize("bad_method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_cli_reconcile_non_get_method_exit_4(self, bad_method: str, tmp_path: Path):
        """CLI strictly rejects non-GET request methods with exit code 4 and invalid_input JSON."""
        runner = CliRunner()
        bad_jsonl = (
            f'{{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "method-{bad_method}", '
            f'"provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", '
            f'"request": {{"method": "{bad_method}", "route_key": "positions"}}, '
            f'"response": {{"status": 200, "body": {{"result": {{"list": [{{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5", "entryPrice": "50000", "markPrice": "51000"}}]}}}}}}}}'
        )
        fixture_file = tmp_path / f"method_{bad_method}.jsonl"
        fixture_file.write_text(bad_jsonl, encoding="utf-8")

        res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_file), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 4
        data = json.loads(res.output)
        assert data["outcome"] == Outcome.INVALID_INPUT.value
        assert len(data["facts"]) == 0
        assert any("only 'GET' is accepted" in i["message"] for i in data["issues"])

    def test_cli_facts_and_issues_filter(self, tmp_path: Path):
        runner = CliRunner()
        fixture = str(FIXTURES_DIR / "bybit_all_facts.jsonl")
        res = runner.invoke(
            cli,
            ["reconcile", "--input", fixture, "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert res.exit_code == 0
        result_file = tmp_path / "result.json"
        result_file.write_text(res.output, encoding="utf-8")

        # Test motim facts without filter
        res_facts = runner.invoke(cli, ["facts", "--result", str(result_file)])
        assert res_facts.exit_code == 0
        facts_list = json.loads(res_facts.output)
        assert len(facts_list) >= 5

        # Test motim facts filtered by type
        res_pos = runner.invoke(cli, ["facts", "--result", str(result_file), "--type", "position"])
        assert res_pos.exit_code == 0
        pos_facts = json.loads(res_pos.output)
        assert len(pos_facts) == 1
        assert pos_facts[0]["fact_type"] == "position"
        assert pos_facts[0]["data"]["symbol"] == "BTCUSDT"

        # Test motim issues without filter
        res_issues = runner.invoke(cli, ["issues", "--result", str(result_file)])
        assert res_issues.exit_code == 0
        issues_list = json.loads(res_issues.output)
        assert isinstance(issues_list, list)

        # Test invalid result file
        invalid_res_file = tmp_path / "invalid_result.json"
        invalid_res_file.write_text('{"schema_version": "invalid.v1"}', encoding="utf-8")
        res_invalid = runner.invoke(cli, ["facts", "--result", str(invalid_res_file)])
        assert res_invalid.exit_code == 1


class TestGate4NoNetworkNoReplay:
    """Gate 4: Static AST and dynamic subprocess network-sabotage guards."""

    def test_ast_proves_no_network_client_imports(self):
        """AST audit guarantees zero network libraries are imported in reconcile modules."""
        reconcile_dir = REPO_ROOT / "motim" / "reconcile"
        cli_reconcile = REPO_ROOT / "motim" / "cli" / "reconcile_cmd.py"
        files_to_check = list(reconcile_dir.rglob("*.py")) + [cli_reconcile]

        forbidden_modules = {
            "socket",
            "requests",
            "httpx",
            "urllib",
            "urllib3",
            "aiohttp",
            "websocket",
            "websockets",
            "mitmproxy",
            "http.client",
            "ftplib",
            "smtplib",
        }

        for py_file in files_to_check:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_pkg = alias.name.split(".")[0]
                        assert top_pkg not in forbidden_modules, (
                            f"Forbidden import '{alias.name}' in {py_file}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_pkg = node.module.split(".")[0]
                        assert top_pkg not in forbidden_modules, (
                            f"Forbidden from-import '{node.module}' in {py_file}"
                        )

    def test_subprocess_cli_under_network_sabotage_guard(self, tmp_path: Path):
        """Run CLI in a subprocess with sitecustomize that immediately fails on any socket/DNS call."""
        guard_dir = tmp_path / "guard_site"
        guard_dir.mkdir()
        sitecustomize_py = guard_dir / "sitecustomize.py"
        sitecustomize_py.write_text(
            """
import socket
import sys

def _prohibited(*args, **kwargs):
    raise RuntimeError("SECURITY VIOLATION: NETWORK ACCESS ATTEMPTED IN OFFLINE RECONCILER")

socket.socket = _prohibited
socket.create_connection = _prohibited
socket.getaddrinfo = _prohibited
socket.gethostbyname = _prohibited

try:
    import urllib.request
    urllib.request.urlopen = _prohibited
except ImportError:
    pass

try:
    import http.client
    http.client.HTTPConnection = _prohibited
    http.client.HTTPSConnection = _prohibited
except ImportError:
    pass
""",
            encoding="utf-8",
        )

        fixture = str(FIXTURES_DIR / "bybit_all_facts.jsonl")
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{guard_dir}{os.pathsep}{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"

        cmd = [
            PYTHON_EXE,
            "-m",
            "motim.cli.main",
            "reconcile",
            "--input",
            fixture,
            "--provider",
            "bybit",
            "--as-of",
            "2026-08-23T14:05:00Z",
        ]

        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"Process failed under network guard: {proc.stderr}"
        data = json.loads(proc.stdout)
        assert data["outcome"] == "ok"
        assert len(data["facts"]) >= 5


class TestGate5SecuritySentinels:
    """Gate 5: Verification that secret sentinels are rejected and never leaked."""

    def test_secret_sentinels_rejected_and_never_leaked(self):
        fixture_path = FIXTURES_DIR / "security_secret_sentinels.jsonl"
        sentinels = [
            "eyCanaryBearerSecretToken12345.eyHeaderPayload.Signature",
            "canary_session_cookie_9988",
            "canary_api_key_secret_7766",
            "canary_password_secret_5544",
            "canary_auth_token_3322",
        ]

        # 1. Test Python API
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")
        assert result.outcome == Outcome.INVALID_INPUT.value
        assert len(result.facts) == 0

        res_json = json.dumps(result.to_dict())
        for secret in sentinels:
            assert secret not in res_json, f"Secret canary '{secret}' leaked into result JSON!"

        # 2. Test CLI
        runner = CliRunner()
        cli_res = runner.invoke(
            cli,
            ["reconcile", "--input", str(fixture_path), "--provider", "bybit", "--as-of", "2026-08-23T14:05:00Z"],
        )
        assert cli_res.exit_code == 4
        for secret in sentinels:
            assert secret not in cli_res.output, f"Secret canary '{secret}' leaked into CLI output!"
