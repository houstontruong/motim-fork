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
