"""Tests for optional curl_cffi replay transport (stubbed)."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from motim.agent_replay import replay_exchange
from motim.exchange_db import ExchangeDB, HeaderField


def test_replay_exchange_curl_transport_uses_stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        eid = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="GET",
            path="/v1/users",
            query=None,
            url="https://example.com/v1/users",
            status=200,
            req_headers=[HeaderField("X-Test", "1")],
            resp_headers=[],
            req_body=None,
            resp_body=b"old",
        )

        # Stub curl_cffi.requests.request
        class _Resp:
            status_code = 201
            headers = {"Content-Type": "text/plain", "X-Resp": "ok"}
            content = b"new"

        def _request(*args, **kwargs):
            return _Resp()

        stub_requests = types.SimpleNamespace(request=_request)
        stub_module = types.SimpleNamespace(requests=stub_requests)
        monkeypatch.setitem(__import__("sys").modules, "curl_cffi", stub_module)

        r = replay_exchange(db, eid, transport="curl", impersonate="chrome")
        assert r.status == 201
        stored = db.get_exchange(r.replay_id)
        assert stored["bodies"]["response"] == b"new"
    finally:
        db.close()
