"""No-network and no-replay verification tests (Gate 4)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path
import pytest

RECONCILE_DIR = Path(__file__).parent.parent / "motim" / "reconcile"
CLI_RECONCILE_FILE = Path(__file__).parent.parent / "motim" / "cli" / "reconcile_cmd.py"
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reconciliation"

FORBIDDEN_MODULES = frozenset(
    {
        "socket",
        "requests",
        "httpx",
        "urllib",
        "aiohttp",
        "websocket",
        "mitmproxy",
        "http.client",
        "urllib.request",
        "urllib.parse",
    }
)


class TestGate4NoNetworkNoReplay:
    """Gate 4: Static AST and runtime socket guard tests verifying complete isolation from network."""

    def test_ast_rejects_network_and_proxy_imports(self):
        """AST analysis confirms no forbidden network or proxy imports exist in reconciliation code."""
        files_to_check = list(RECONCILE_DIR.glob("**/*.py")) + [CLI_RECONCILE_FILE]
        assert len(files_to_check) >= 6, "Expected at least 6 files in reconciliation package"

        for file_path in files_to_check:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod_root = alias.name.split(".")[0]
                        assert (
                            alias.name not in FORBIDDEN_MODULES and mod_root not in FORBIDDEN_MODULES
                        ), f"Forbidden import '{alias.name}' found in {file_path.name}:{node.lineno}"
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        mod_root = node.module.split(".")[0]
                        assert (
                            node.module not in FORBIDDEN_MODULES and mod_root not in FORBIDDEN_MODULES
                        ), f"Forbidden from-import '{node.module}' found in {file_path.name}:{node.lineno}"

    def test_subprocess_execution_under_blocked_socket_guard(self, tmp_path):
        """CLI runs in a subprocess where all sockets, DNS, and HTTP entrypoints raise immediate failure."""
        guard_code = textwrap.dedent(
            """
            import sys

            # Trap socket creation
            import socket
            def _fail(*args, **kwargs):
                raise RuntimeError("SECURITY VIOLATION: Network socket access attempted!")

            socket.socket = _fail
            socket.create_connection = _fail
            socket.getaddrinfo = _fail
            socket.gethostbyname = _fail

            # Trap http.client
            import http.client
            http.client.HTTPConnection = _fail
            http.client.HTTPSConnection = _fail
            """
        )
        sitecustomize_path = tmp_path / "sitecustomize.py"
        sitecustomize_path.write_text(guard_code, encoding="utf-8")

        # 1. Verify that the guard is indeed functional
        canary_cmd = [
            sys.executable,
            "-c",
            "import socket; socket.socket()",
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{Path(__file__).parent.parent}"

        proc_canary = subprocess.run(
            canary_cmd,
            env=env,
            capture_output=True,
            text=True,
        )
        assert proc_canary.returncode != 0
        assert "SECURITY VIOLATION: Network socket access attempted!" in proc_canary.stderr

        # 2. Run motim reconcile under this active network-blocking guard
        valid_fixture = FIXTURES_DIR / "bybit_all_facts.jsonl"
        cmd = [
            sys.executable,
            "-m",
            "motim.cli.main",
            "reconcile",
            "--input",
            str(valid_fixture),
            "--provider",
            "bybit",
            "--as-of",
            "2026-08-23T14:05:00Z",
        ]
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Process failed with stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}"
        assert '"outcome": "ok"' in proc.stdout

    def test_no_runnable_request_or_replay_construction(self):
        """Grep and AST check confirming no replay / HTTP request construction in reconciliation paths."""
        files_to_check = list(RECONCILE_DIR.glob("**/*.py")) + [CLI_RECONCILE_FILE]
        replay_keywords = ("replay", "execute_request", "send_request", "send_http", "session.get", "session.post")

        for file_path in files_to_check:
            content = file_path.read_text(encoding="utf-8")
            for kw in replay_keywords:
                assert kw not in content, f"Disallowed keyword '{kw}' found in {file_path.name}"
