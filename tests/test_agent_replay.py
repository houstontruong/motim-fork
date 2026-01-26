"""Tests for agent replay/diff helpers."""

from pathlib import Path

import httpx

from motim.agent_replay import build_replay_plan, diff_exchanges, replay_exchange
from motim.exchange_db import ExchangeDB, HeaderField


def test_build_replay_plan_drops_hop_by_hop_headers(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        eid = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="POST",
            path="/v1/test",
            query=None,
            url="https://example.com/v1/test",
            status=200,
            req_headers=[
                HeaderField("Host", "example.com"),
                HeaderField("Content-Length", "999"),
                HeaderField("X-Test", "1"),
            ],
            resp_headers=[],
            req_body=b"abc",
            resp_body=b"ok",
        )
        ex = db.get_exchange(eid)
        plan = build_replay_plan(ex)
        header_names = {k.lower() for k, _ in plan.headers}
        assert "host" not in header_names
        assert "content-length" not in header_names
        assert "x-test" in header_names
    finally:
        db.close()


def test_build_replay_plan_patch_json(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        eid = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="POST",
            path="/v1/test",
            query=None,
            url="https://example.com/v1/test",
            status=200,
            req_headers=[HeaderField("Content-Type", "application/json")],
            resp_headers=[],
            req_body=b'{"a":1,"nested":{"x":1}}',
            resp_body=b"ok",
        )
        ex = db.get_exchange(eid)
        plan = build_replay_plan(ex, json_patches=[{"a": 2, "nested": {"y": 3}}])
        assert plan.body == b'{"a":2,"nested":{"x":1,"y":3}}'
    finally:
        db.close()


def test_replay_exchange_stores_result(tmp_path: Path, monkeypatch):
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

        transport = httpx.MockTransport(
            lambda request: httpx.Response(201, headers={"X-Resp": "ok"}, content=b"new")
        )

        # Monkeypatch httpx.Client used inside replay_exchange to use our transport.
        real_client = httpx.Client

        def _client_factory(*args, **kwargs):
            kwargs["transport"] = transport
            return real_client(*args, **kwargs)

        monkeypatch.setattr(httpx, "Client", _client_factory)

        result = replay_exchange(db, eid, set_headers=("X-Test=2",))
        assert result.replay_id != eid
        assert result.replay_record_id is not None
        stored = db.get_exchange(result.replay_id)
        assert stored["status"] == 201
        assert stored["bodies"]["response"] == b"new"
    finally:
        db.close()


def test_diff_exchanges_detects_status_change(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        a_id = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="GET",
            path="/x",
            query=None,
            url="https://example.com/x",
            status=403,
        )
        b_id = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="GET",
            path="/x",
            query=None,
            url="https://example.com/x",
            status=200,
        )
        d = diff_exchanges(db.get_exchange(a_id), db.get_exchange(b_id))
        assert d["a"]["status"] == 403
        assert d["b"]["status"] == 200
    finally:
        db.close()
