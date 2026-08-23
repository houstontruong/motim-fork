"""Tests for diff utility."""

from pathlib import Path

from motim.diff import diff_exchanges
from motim.exchange_db import ExchangeDB


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
