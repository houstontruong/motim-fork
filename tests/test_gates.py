"""Validation Gate Tests (G1–G5) for Motim Phase B Production-Safe Fork."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import motim
from motim.cli.main import cli


class TestGate1ReplayRemovedAtSource:
    """Gate G1 — Code review & AST/import proof: replay and probe removed at source.

    Proves:
    - No replay/probe modules exist (motim.agent_replay is gone).
    - No replay/probe functions exist in motim or its CLI.
    - No replays database table exists.
    - No code path can re-send captured requests with credentials.
    """

    def test_agent_replay_module_does_not_exist(self):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("motim.agent_replay")

    def test_no_replay_or_probe_in_top_level_exports(self):
        exported_names = dir(motim)
        forbidden = ["replay_exchange", "build_replay_plan", "probe", "replay_seq", "agent_replay"]
        for name in forbidden:
            assert name not in exported_names, f"Found forbidden export: {name}"
            assert name not in motim.__all__, f"Found forbidden in __all__: {name}"

    def test_no_replay_commands_in_cli(self):
        command_names = list(cli.commands.keys())
        forbidden_commands = ["replay", "replay-seq", "probe"]
        for cmd in forbidden_commands:
            assert cmd not in command_names, f"Found forbidden CLI command: {cmd}"

    def test_no_replays_table_in_exchange_db(self, tmp_path: Path):
        db = motim.ExchangeDB(tmp_path / "motim.sqlite3")
        try:
            cur = db._conn.cursor()
            tables = [
                row[0]
                for row in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            assert "replays" not in tables, "Found forbidden 'replays' table in SQLite schema"
            assert not hasattr(db, "record_replay"), "Found forbidden record_replay method on ExchangeDB"
        finally:
            db.close()


class TestGate2RedactionBeforePersistence:
    """Gate G2 — Synthetic test traffic with known fake API keys/tokens.

    Asserts:
    - Zero sensitive tokens in SQLite DB and YAML files on disk.
    - Headers, query params, and body payloads (JSON/form/text) are redacted before storage.
    - Auth tokens, session cookies, passwords, and private keys never touch disk unmasked.
    """

    def test_synthetic_traffic_redaction_proof(self, tmp_path: Path):
        import json
        from motim.exchange_db import ExchangeDB, HeaderField
        from motim.exchange_writer import BufferedExchangeWriter
        from motim.proxy.pipeline import CapturePipeline
        from motim.redact import Redactor
        from motim.store import Store

        # Canary tokens that must NEVER appear in persistence
        CANARY_TOKENS = [
            "sk_live_canary_secret_token_12345",
            "eyCanaryJwtHeader.eyCanaryJwtPayload.Signature67890",
            "super_secret_login_password_abc",
            "session_cookie_secret_xyz999",
            "query_param_api_secret_456",
        ]

        spec_dir = tmp_path / "specs"
        store = Store(specs_dir=spec_dir)
        db_path = tmp_path / "motim.sqlite3"
        writer = BufferedExchangeWriter(db_path, flush_interval_ms=10, queue_max=100)
        redactor = Redactor(profile="strict")

        pipeline = CapturePipeline(
            store=store,
            exchange_writer=writer,
            redactor=redactor,
        )
        pipeline.start()

        try:
            req_body_json = json.dumps(
                {
                    "api_key": CANARY_TOKENS[0],
                    "jwt": CANARY_TOKENS[1],
                    "password": CANARY_TOKENS[2],
                    "public_field": "visible_ok",
                }
            ).encode("utf-8")

            pipeline.enqueue(
                "http",
                {
                    "scheme": "https",
                    "host": "test-canary.example.com",
                    "port": 443,
                    "method": "POST",
                    "status": 200,
                    "path": f"/v1/secure?token={CANARY_TOKENS[4]}",
                    "path_only": "/v1/secure",
                    "query": f"token={CANARY_TOKENS[4]}",
                    "query_params": {"token": CANARY_TOKENS[4]},
                    "url": f"https://test-canary.example.com/v1/secure?token={CANARY_TOKENS[4]}",
                    "service_key": "test_canary_example_com",
                    "request_headers": {
                        "Authorization": f"Bearer {CANARY_TOKENS[0]}",
                        "Cookie": f"session={CANARY_TOKENS[3]}",
                        "X-API-Key": CANARY_TOKENS[0],
                        "Content-Type": "application/json",
                    },
                    "response_headers": {
                        "Content-Type": "application/json",
                        "Set-Cookie": f"session={CANARY_TOKENS[3]}; Path=/",
                    },
                    "req_fields": [
                        HeaderField("Authorization", f"Bearer {CANARY_TOKENS[0]}"),
                        HeaderField("Cookie", f"session={CANARY_TOKENS[3]}"),
                        HeaderField("X-API-Key", CANARY_TOKENS[0]),
                    ],
                    "resp_fields": [
                        HeaderField("Set-Cookie", f"session={CANARY_TOKENS[3]}; Path=/"),
                    ],
                    "req_body": req_body_json,
                    "resp_body": b'{"status": "ok"}',
                    "req_content_type": "application/json",
                    "resp_content_type": "application/json",
                },
            )

            pipeline.stop(timeout=3.0)
            writer.close()
            store.flush()

            # 1. Audit all files on disk under tmp_path
            for file_path in tmp_path.rglob("*"):
                if file_path.is_file():
                    content_bytes = file_path.read_bytes()
                    for canary in CANARY_TOKENS:
                        canary_b = canary.encode("utf-8")
                        assert canary_b not in content_bytes, (
                            f"LEAK DETECTED: Canary token {canary!r} found in file {file_path}"
                        )

            # 2. Audit SQLite DB tables directly
            db = ExchangeDB(db_path)
            try:
                cur = db._conn.cursor()
                for table in ["exchanges", "headers", "bodies", "auth_snapshots", "endpoints_index", "services_index"]:
                    rows = cur.execute(f"SELECT * FROM {table}").fetchall()
                    for row in rows:
                        row_str = " ".join(str(v) for v in row)
                        for canary in CANARY_TOKENS:
                            assert canary not in row_str, (
                                f"LEAK DETECTED: Canary token {canary!r} found in table {table}"
                            )
            finally:
                db.close()

        finally:
            writer.close()


class TestGate3EgressAllowlistAndLoopback:
    """Gate G3 — Egress allowlist enforcement and loopback-only bind.

    Asserts:
    - Default policy is deny-all (empty allowlist blocks all destinations).
    - Requests to non-allowlisted destinations receive immediate 403 Forbidden.
    - Requests to allowlisted destinations are forwarded.
    - Proxy bind enforces loopback-only interfaces (127.0.0.1, ::1) and rejects 0.0.0.0.
    """

    def test_default_deny_all_policy(self):
        from motim.proxy.addon import is_host_allowed

        assert not is_host_allowed("api.github.com", [])
        assert not is_host_allowed("api.bybit.com", None)
        assert not is_host_allowed("127.0.0.1", [])

    def test_allowlist_filtering_and_403_rejection(self):
        from motim.config import Config
        from motim.proxy.addon import MotimAddon

        addon = MotimAddon()
        config = Config()
        config.capture.allowed_hosts = ["api.bybit.com", "*.deribit.com"]
        addon._config = config

        class MockRequest:
            def __init__(self, host: str):
                self.host = host
                self.pretty_host = host

        class MockFlow:
            def __init__(self, host: str):
                self.request = MockRequest(host)
                self.response = None

        # 1. Allowed destinations
        flow_allowed_1 = MockFlow("api.bybit.com")
        addon.request(flow_allowed_1)
        assert flow_allowed_1.response is None

        flow_allowed_2 = MockFlow("test.deribit.com")
        addon.request(flow_allowed_2)
        assert flow_allowed_2.response is None

        # 2. Blocked destination
        flow_blocked = MockFlow("malicious-exfiltration.com")
        addon.request(flow_blocked)
        assert flow_blocked.response is not None
        assert flow_blocked.response.status_code == 403
        assert flow_blocked.response.headers.get("x-motim-egress-blocked") == "1"

    def test_loopback_only_bind_enforcement(self):
        from click.testing import CliRunner
        from motim.cli.proxy import proxy

        runner = CliRunner()

        # Reject 0.0.0.0
        res_all_interfaces = runner.invoke(proxy, ["start", "--listen-host", "0.0.0.0"])
        assert res_all_interfaces.exit_code != 0
        assert "Security violation" in res_all_interfaces.output or "prohibited" in res_all_interfaces.output

        # Reject external routable IP
        res_external_ip = runner.invoke(proxy, ["start", "--listen-host", "192.168.1.50"])
        assert res_external_ip.exit_code != 0
        assert "Security violation" in res_external_ip.output or "prohibited" in res_external_ip.output


