"""Tests for SQLite exchange database."""

from pathlib import Path

from motim.exchange_db import ExchangeDB, HeaderField


def test_put_and_get_exchange(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3", max_body_bytes=10)
    try:
        eid = db.put_exchange(
            scheme="https",
            host="example.com",
            port=443,
            method="POST",
            path="/v1/test",
            query="a=1",
            url="https://example.com/v1/test?a=1",
            status=200,
            req_headers=[HeaderField("Content-Type", "application/json")],
            resp_headers=[HeaderField("Content-Type", "application/json")],
            req_body=b'{"hello":"world"}',
            resp_body=b'{"ok":true}',
            req_content_type="application/json",
            resp_content_type="application/json",
        )
        ex = db.get_exchange(eid)
        assert ex["host"] == "example.com"
        assert ex["method"] == "POST"
        assert ex["status"] == 200
        assert ex["req_body_len"] == len(b'{"hello":"world"}')
        assert ex["req_body_truncated"] == 1  # max_body_bytes=10
        assert ex["bodies"]["request"] == b'{"hello":"'
    finally:
        db.close()


def test_search_exchanges(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        db.put_exchange(
            scheme="https",
            host="a.example.com",
            port=443,
            method="GET",
            path="/v1/users",
            query=None,
            url="https://a.example.com/v1/users",
            status=403,
        )
        db.put_exchange(
            scheme="https",
            host="a.example.com",
            port=443,
            method="GET",
            path="/v1/users/me",
            query=None,
            url="https://a.example.com/v1/users/me",
            status=200,
        )
        results = db.search_exchanges(host="a.example.com", method="GET", limit=10)
        assert len(results) == 2
        results_403 = db.search_exchanges(host="a.example.com", status=403, limit=10)
        assert len(results_403) == 1
        assert results_403[0]["status"] == 403
    finally:
        db.close()


def test_resolve_service_key_dotted(tmp_path: Path):
    """Dotted hostnames like 'api.example.com' should resolve to 'api_example_com'."""
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="GET",
            path="/v1/test",
            query=None,
            url="https://api.example.com/v1/test",
            status=200,
        )
        # service_key is auto-normalized to api_example_com
        assert db.resolve_service_key("api_example_com") == "api_example_com"
        # dotted input should also resolve
        assert db.resolve_service_key("api.example.com") == "api_example_com"
        # partial dotted input
        assert db.resolve_service_key("api.example") == "api_example_com"
        # colons too
        assert db.resolve_service_key("api:example:com") == "api_example_com"
    finally:
        db.close()


def test_search_exchanges_path_contains(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        db.put_exchange(
            scheme="https",
            host="a.example.com",
            port=443,
            method="GET",
            path="/v1/users/me",
            query=None,
            url="https://a.example.com/v1/users/me",
            status=200,
        )
        results = db.search_exchanges(path_contains="/me", limit=10)
        assert len(results) == 1
        assert results[0]["path"] == "/v1/users/me"
    finally:
        db.close()
