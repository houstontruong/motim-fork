"""Tests for buffered exchange writer."""

import time
from pathlib import Path

from motim.exchange_db import ExchangeDB
from motim.exchange_writer import BufferedExchangeWriter


def test_buffered_writer_persists(tmp_path: Path):
    db_path = tmp_path / "motim.sqlite3"
    writer = BufferedExchangeWriter(
        db_path,
        queue_max=100,
        batch_size=10,
        flush_interval_ms=50,
    )
    # Enqueue a few items
    for i in range(5):
        writer.enqueue(
            {
                "scheme": "https",
                "host": "example.com",
                "port": 443,
                "method": "GET",
                "path": f"/v1/{i}",
                "query": None,
                "url": f"https://example.com/v1/{i}",
                "status": 200,
                "req_headers": (),
                "resp_headers": (),
                "req_body": None,
                "resp_body": b"ok",
                "req_content_type": None,
                "resp_content_type": "text/plain",
            }
        )

    # Allow worker to flush.
    time.sleep(0.2)
    writer.close()

    db = ExchangeDB(db_path)
    try:
        results = db.search_exchanges(host="example.com", limit=100)
        assert len(results) == 5
    finally:
        db.close()
