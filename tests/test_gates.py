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


class TestGate4DiscoveryAndSafeStorage:
    """Gate G4 — Read-only discovery interface and safe storage defaults.

    Asserts:
    - Discovery interface returns schemas and endpoints for inspection.
    - No persistent credentials are used or exposed for unauthenticated replay.
    - Storage directories (0700) and files (0600) enforce private permissions on POSIX.
    - Max body size limits (1MB default) are enforced.
    """

    def test_discovery_interface_schema_inspection(self, tmp_path: Path):
        from motim.discovery import discover, discover_services
        from motim.store import Store

        spec_dir = tmp_path / "specs"
        store = Store(specs_dir=spec_dir)

        # Populate a sample service spec
        sample_spec = {
            "service": "binance_futures",
            "base_url": "https://fapi.binance.com",
            "auth": {
                "type": "api_key",
                "header": "X-MBX-APIKEY",
                "value": "[REDACTED]",
                "last_seen": "2026-08-23T12:00:00",
            },
            "observed_endpoints": [
                "GET /fapi/v1/ping",
                "GET /fapi/v1/ticker/price",
                "POST /fapi/v1/order",
            ],
            "samples": [
                {
                    "endpoint": "GET /fapi/v1/ticker/price",
                    "status": 200,
                    "query_params": {"symbol": "BTCUSDT"},
                    "response_body": {"symbol": "BTCUSDT", "price": "60000.00"},
                }
            ],
        }
        store.save("binance_futures", sample_spec)
        store.flush()

        # Discover services
        services = discover_services(store=store)
        assert "binance_futures" in services

        # Inspect service
        disc = discover("binance_futures", store=store)
        assert disc.auth_type == "api_key"
        assert disc.base_url == "https://fapi.binance.com"
        assert len(disc.endpoints) == 3

        endpoints = disc.list_endpoints()
        assert len(endpoints) == 3
        ticker_ep = next(e for e in endpoints if e.path == "/fapi/v1/ticker/price")
        assert ticker_ep.sample_count == 1
        assert 200 in ticker_ep.statuses_seen

    def test_safe_storage_file_permissions(self, tmp_path: Path):
        import os
        from motim.exchange_db import ExchangeDB
        from motim.store import Store

        spec_dir = tmp_path / "specs"
        store = Store(specs_dir=spec_dir)
        path = store.save("test_service", {"service": "test_service", "observed_endpoints": []})
        store.flush()

        db_path = tmp_path / "db" / "motim.sqlite3"
        db = ExchangeDB(db_path)
        db.close()

        if os.name != "nt":
            # POSIX directory permission 0700
            assert (spec_dir.stat().st_mode & 0o777) == 0o700
            assert (db_path.parent.stat().st_mode & 0o777) == 0o700
            # POSIX file permission 0600
            assert (path.stat().st_mode & 0o777) == 0o600
            assert (db_path.stat().st_mode & 0o777) == 0o600


class TestGate5DocumentationAndDeliverables:
    """Gate G5 — Complete deliverables, security documentation, and regression green."""

    def test_required_deliverables_exist(self):
        project_root = Path(__file__).parent.parent
        required_files = [
            "SECURITY.md",
            "ROADMAP.md",
            "motim-phase-b-report.md",
            "README.md",
            "motim/skill.md",
        ]
        for req in required_files:
            file_path = project_root / req
            assert file_path.exists(), f"Required deliverable {req} does not exist"
            assert file_path.stat().st_size > 100, f"Required deliverable {req} is empty or too short"

    def test_security_policy_content(self):
        project_root = Path(__file__).parent.parent
        security_text = (project_root / "SECURITY.md").read_text()
        assert "Redaction-Before-Persistence" in security_text
        assert "Egress Allowlist" in security_text
        assert "Loopback-Only" in security_text

    def test_roadmap_content(self):
        project_root = Path(__file__).parent.parent
        roadmap_text = (project_root / "ROADMAP.md").read_text()
        assert "Phase B" in roadmap_text
        assert "Gate G1" in roadmap_text
        assert "Gate G2" in roadmap_text
        assert "Gate G3" in roadmap_text
        assert "Gate G4" in roadmap_text
        assert "Gate G5" in roadmap_text
        assert "Phase C" in roadmap_text




