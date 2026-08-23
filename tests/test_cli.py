"""Tests for CLI commands: show, cat, export."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from motim.cli.main import cli
from motim.exchange_db import ExchangeDB, HeaderField


@pytest.fixture
def db_with_exchange(tmp_path: Path, monkeypatch):
    """Create a DB with one exchange and patch config to use it."""
    db_path = tmp_path / "motim.sqlite3"
    db = ExchangeDB(db_path)
    eid = db.put_exchange(
        scheme="https",
        host="api.example.com",
        port=443,
        method="POST",
        path="/v1/users",
        query="active=true",
        url="https://api.example.com/v1/users?active=true",
        status=201,
        graphql_operation=None,
        req_headers=[
            HeaderField("Content-Type", "application/json"),
            HeaderField("Authorization", "Bearer tok123"),
            HeaderField("Host", "api.example.com"),
        ],
        resp_headers=[
            HeaderField("Content-Type", "application/json"),
            HeaderField("X-Request-Id", "abc"),
        ],
        req_body=b'{"name":"Alice"}',
        resp_body=b'{"id":1,"name":"Alice"}',
        req_content_type="application/json",
        resp_content_type="application/json",
    )
    db.close()
    return db_path, eid


@pytest.fixture
def db_with_graphql(tmp_path: Path):
    """Create a DB with a GraphQL exchange."""
    db_path = tmp_path / "motim.sqlite3"
    db = ExchangeDB(db_path)
    eid = db.put_exchange(
        scheme="https",
        host="api.example.com",
        port=443,
        method="POST",
        path="/graphql",
        query=None,
        url="https://api.example.com/graphql",
        status=200,
        graphql_operation="GetUser",
        req_headers=[HeaderField("Content-Type", "application/json")],
        resp_headers=[HeaderField("Content-Type", "application/json")],
        req_body=b'{"query":"query GetUser { user { id } }"}',
        resp_body=b'{"data":{"user":{"id":"1"}}}',
        req_content_type="application/json",
        resp_content_type="application/json",
    )
    db.close()
    return db_path, eid


class TestShowCommand:
    def test_show_text(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["show", str(eid), "--db", str(db_path)])
        assert result.exit_code == 0
        assert "=== Request ===" in result.output
        assert "POST /v1/users?active=true HTTP/1.1" in result.output
        assert "=== Response ===" in result.output
        assert "HTTP/1.1 201" in result.output
        assert '"name": "Alice"' in result.output

    def test_show_json(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["show", str(eid), "--db", str(db_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "request" in data
        assert "response" in data
        assert data["request"]["method"] == "POST"
        assert data["response"]["status"] == 201

    def test_show_request_only(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["show", str(eid), "--db", str(db_path), "--request-only"])
        assert result.exit_code == 0
        assert "=== Request ===" in result.output
        assert "=== Response ===" not in result.output

    def test_show_response_only(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["show", str(eid), "--db", str(db_path), "--response-only"])
        assert result.exit_code == 0
        assert "=== Request ===" not in result.output
        assert "=== Response ===" in result.output

    def test_show_raw(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["show", str(eid), "--db", str(db_path), "--raw"])
        assert result.exit_code == 0
        # Raw should not pretty-print (no indentation)
        assert '{"name":"Alice"}' in result.output


class TestCatCommand:
    def test_cat_response(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["cat", str(eid), "--db", str(db_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["id"] == 1
        assert data["name"] == "Alice"

    def test_cat_request(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["cat", str(eid), "--db", str(db_path), "--request"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Alice"

    def test_cat_raw(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["cat", str(eid), "--db", str(db_path), "--raw"])
        assert result.exit_code == 0
        # Raw mode: no pretty-printing
        assert '{"id":1,"name":"Alice"}' in result.output


class TestExportCommand:
    def test_export_curl(self, db_with_exchange):
        db_path, eid = db_with_exchange
        runner = CliRunner()
        result = runner.invoke(cli, ["export", str(eid), "--db", str(db_path)])
        assert result.exit_code == 0
        assert "curl -X 'POST'" in result.output
        assert "-H 'Content-Type: application/json'" in result.output
        assert "-H 'Authorization: Bearer [REDACTED]'" in result.output
        # Host should be skipped (hop-by-hop)
        assert "-H 'Host:" not in result.output
        assert "--data-raw" in result.output
        assert "https://api.example.com/v1/users?active=true" in result.output


    def test_export_curl_no_body(self, tmp_path: Path):
        db_path = tmp_path / "motim.sqlite3"
        db = ExchangeDB(db_path)
        eid = db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="GET",
            path="/v1/users",
            query=None,
            url="https://api.example.com/v1/users",
            status=200,
            req_headers=[HeaderField("Accept", "application/json")],
            resp_headers=[HeaderField("Content-Type", "application/json")],
        )
        db.close()
        runner = CliRunner()
        result = runner.invoke(cli, ["export", str(eid), "--db", str(db_path)])
        assert result.exit_code == 0
        assert "curl -X 'GET'" in result.output
        assert "--data-raw" not in result.output


class TestSearchDisplay:
    def test_search_with_size_and_graphql(self, db_with_graphql):
        db_path, eid = db_with_graphql
        runner = CliRunner()
        result = runner.invoke(cli, ["search", "--db", str(db_path)])
        assert result.exit_code == 0
        assert "(GetUser)" in result.output

    def test_search_json_includes_new_fields(self, db_with_graphql):
        db_path, eid = db_with_graphql
        runner = CliRunner()
        result = runner.invoke(cli, ["search", "--db", str(db_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1
        assert "resp_body_len" in data[0]
        assert "graphql_operation" in data[0]


class TestCliSanitizationDefenseInDepth:
    """Test that all CLI display/export commands redact sensitive credentials even if DB has raw secrets."""

    @pytest.fixture
    def unredacted_raw_db(self, tmp_path: Path):
        import sqlite3
        db_path = tmp_path / "raw_unredacted.sqlite3"
        db = ExchangeDB(db_path)
        db.close()

        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO exchanges (id, ts, scheme, host, port, method, path, query, url, status, service_key)
            VALUES (1, '2026-08-23T10:00:00Z', 'https', 'api.test.com', 443, 'POST',
                    '/v1/tokens', 'api_secret=QUERY_RAW_SECRET_111',
                    'https://api.test.com/v1/tokens?api_secret=QUERY_RAW_SECRET_111', 200, 'api_test_com')
            """
        )
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'request', 0, 'Authorization', 'Bearer RAW_AUTH_SECRET_222')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'request', 1, 'Cookie', 'session=RAW_COOKIE_SECRET_333; user=alice')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'request', 2, 'X-API-Key', 'RAW_API_KEY_444')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'request', 3, 'Content-Type', 'application/json')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'response', 0, 'Set-Cookie', 'auth_token=RAW_RESP_COOKIE_555')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (1, 'response', 1, 'Content-Type', 'application/json')")
        cur.execute(
            "INSERT INTO bodies (exchange_id, side, raw) VALUES (1, 'request', ?)",
            (b'{"password": "RAW_PASSWORD_666", "token": "RAW_TOKEN_777", "public": "safe"}',),
        )
        cur.execute(
            "INSERT INTO bodies (exchange_id, side, raw) VALUES (1, 'response', ?)",
            (b'{"access_token": "RAW_ACCESS_TOKEN_888", "status": "ok"}',),
        )

        cur.execute(
            """
            INSERT INTO exchanges (id, ts, scheme, host, port, method, path, query, url, status, service_key)
            VALUES (2, '2026-08-23T10:05:00Z', 'https', 'api.test.com', 443, 'POST',
                    '/v1/tokens', 'api_secret=QUERY_RAW_SECRET_111',
                    'https://api.test.com/v1/tokens?api_secret=QUERY_RAW_SECRET_111', 200, 'api_test_com')
            """
        )
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (2, 'request', 0, 'Authorization', 'Bearer RAW_AUTH_SECRET_NEW')")
        cur.execute("INSERT INTO headers (exchange_id, side, idx, name, value) VALUES (2, 'request', 1, 'Content-Type', 'application/json')")

        conn.commit()
        conn.close()
        return db_path

    def test_export_redacts_all_secrets(self, unredacted_raw_db):
        runner = CliRunner()
        res = runner.invoke(cli, ["export", "1", "--db", str(unredacted_raw_db)])
        assert res.exit_code == 0
        out = res.output
        assert "RAW_AUTH_SECRET_222" not in out
        assert "RAW_COOKIE_SECRET_333" not in out
        assert "RAW_API_KEY_444" not in out
        assert "RAW_PASSWORD_666" not in out
        assert "RAW_TOKEN_777" not in out
        assert "QUERY_RAW_SECRET_111" not in out
        assert "Bearer [REDACTED]" in out
        assert "[REDACTED]" in out

    def test_show_redacts_all_secrets_text_and_json(self, unredacted_raw_db):
        runner = CliRunner()
        res_text = runner.invoke(cli, ["show", "1", "--db", str(unredacted_raw_db)])
        assert res_text.exit_code == 0
        out_text = res_text.output
        assert "RAW_AUTH_SECRET_222" not in out_text
        assert "RAW_COOKIE_SECRET_333" not in out_text
        assert "RAW_API_KEY_444" not in out_text
        assert "RAW_PASSWORD_666" not in out_text
        assert "RAW_TOKEN_777" not in out_text
        assert "RAW_RESP_COOKIE_555" not in out_text
        assert "RAW_ACCESS_TOKEN_888" not in out_text
        assert "QUERY_RAW_SECRET_111" not in out_text
        assert "[REDACTED]" in out_text

        res_json = runner.invoke(cli, ["show", "1", "--db", str(unredacted_raw_db), "--json"])
        assert res_json.exit_code == 0
        out_json = res_json.output
        assert "RAW_AUTH_SECRET_222" not in out_json
        assert "RAW_PASSWORD_666" not in out_json
        assert "QUERY_RAW_SECRET_111" not in out_json

    def test_cat_redacts_secrets(self, unredacted_raw_db):
        runner = CliRunner()
        res_req = runner.invoke(cli, ["cat", "1", "--request", "--db", str(unredacted_raw_db)])
        assert res_req.exit_code == 0
        assert "RAW_PASSWORD_666" not in res_req.output
        assert "RAW_TOKEN_777" not in res_req.output
        assert "[REDACTED]" in res_req.output

        res_resp = runner.invoke(cli, ["cat", "1", "--db", str(unredacted_raw_db)])
        assert res_resp.exit_code == 0
        assert "RAW_ACCESS_TOKEN_888" not in res_resp.output
        assert "[REDACTED]" in res_resp.output

    def test_diff_redacts_secrets(self, unredacted_raw_db):
        runner = CliRunner()
        res = runner.invoke(cli, ["diff", "1", "2", "--db", str(unredacted_raw_db), "--json"])
        assert res.exit_code == 0
        out = res.output
        assert "RAW_AUTH_SECRET_222" not in out
        assert "RAW_AUTH_SECRET_NEW" not in out
        assert "QUERY_RAW_SECRET_111" not in out

    def test_search_and_session_redact_secrets(self, unredacted_raw_db):
        runner = CliRunner()
        res_search = runner.invoke(cli, ["search", "--db", str(unredacted_raw_db), "--json"])
        assert res_search.exit_code == 0
        assert "QUERY_RAW_SECRET_111" not in res_search.output

        res_session = runner.invoke(cli, ["session", "1", "--db", str(unredacted_raw_db), "--json"])
        assert res_session.exit_code == 0
        assert "QUERY_RAW_SECRET_111" not in res_session.output

