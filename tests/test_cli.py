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
