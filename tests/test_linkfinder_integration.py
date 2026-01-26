from __future__ import annotations

from pathlib import Path

from motim.exchange_db import ExchangeDB
from motim.linkfinder import extract_links


def test_extract_links_basic():
    js = """
    fetch('/api/challenges/containers/start');
    const u = "https://example.com/v1/users/me";
    const rel = "../api/test";
    """
    links = extract_links(js, unique=True)
    assert "/api/challenges/containers/start" in links
    assert "https://example.com/v1/users/me" in links
    assert "../api/test" in links


def test_exchange_db_linkfinder_js(tmp_path: Path):
    db = ExchangeDB(tmp_path / "motim.sqlite3")
    try:
        js = b"var x='/api/challenges/containers/start';"
        db.put_exchange(
            scheme="https",
            host="ctf.hackthebox.com",
            port=443,
            method="GET",
            path="/build/assets/app.js",
            query=None,
            url="https://ctf.hackthebox.com/build/assets/app.js",
            status=200,
            resp_body=js,
            resp_content_type="application/javascript",
        )
        out = db.linkfinder_js(host="ctf.hackthebox.com", filter_regex=r"^/api/")
        assert out
        assert out[0]["link"] == "/api/challenges/containers/start"
    finally:
        db.close()
