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


def test_exchange_db_edge_cases_and_zero_limits(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        eid = db.put_exchange(
            scheme="https",
            host="edge.example.com",
            port=443,
            method="POST",
            path="/v1/auth",
            query="token=secret123",
            url="https://edge.example.com/v1/auth?token=secret123",
            status=200,
            req_headers=[
                HeaderField("Authorization", "Bearer sensitive_jwt_token_123"),
                HeaderField("Cookie", "session=cookie_val_456"),
            ],
            req_body=b'{"password": "secret_pass_789"}',
            req_content_type="application/json",
        )

        # 1. Verify boundary redaction in DB
        ex = db.get_exchange(eid)
        for h in ex["headers"]["request"]:
            assert "sensitive_jwt_token_123" not in h["value"]
            assert "cookie_val_456" not in h["value"]
        assert b"secret_pass_789" not in ex["bodies"]["request"]
        assert b"[REDACTED]" in ex["bodies"]["request"]
        assert "secret123" not in str(ex["query"])

        # 2. Verify auth snapshot has metadata only
        snap = db.latest_auth_snapshot("edge_example_com")
        assert snap is not None
        assert snap["auth_type"] == "bearer"
        assert "Authorization" in snap["header_names"]
        assert "session" in snap["cookie_names"]
        assert snap["headers"]["Authorization"] == "[REDACTED]"

        # 3. Test rebuild_derived with batch_size=0 (no crash)
        res = db.rebuild_derived(batch_size=0)
        assert res["exchanges_processed"] == 1

        # 4. Test zero limit queries (no crash, returns empty list)
        assert db.exchanges_around(eid, limit=0) == []
        assert db.exchanges_in_range(start_ts="2020-01-01", end_ts="2030-01-01", limit=0) == []

        # 5. Test session_slice with limit=0 and noise filtering
        slice_res = db.session_slice(eid, limit=0)
        assert slice_res["items"] == []

        # 6. Test session_slice on noise-only / non-matching items (no crash)
        slice_res_normal = db.session_slice(eid, limit=10, filter_noise=True)
        assert len(slice_res_normal["items"]) == 1
    finally:
        db.close()

