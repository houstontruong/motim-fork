"""Unit tests for redaction-before-persistence engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from motim.exchange_db import ExchangeDB, HeaderField
from motim.exchange_writer import BufferedExchangeWriter
from motim.proxy.pipeline import CapturePipeline
from motim.redact import Redactor, get_redactor
from motim.store import Store


def test_redactor_header_redaction():
    redactor = Redactor(profile="strict")

    # Bearer header
    auth_bearer = redactor.redact_header_value("Authorization", "Bearer eyJhbGciOi...")
    assert auth_bearer == "Bearer [REDACTED]"

    # Basic header
    auth_basic = redactor.redact_header_value("Authorization", "Basic dXNlcjpwYXNz")
    assert auth_basic == "Basic [REDACTED]"

    # Other API key headers
    api_key = redactor.redact_header_value("X-API-Key", "sk_live_123456789")
    assert api_key == "[REDACTED]"

    token_h = redactor.redact_header_value("X-Auth-Token", "secret-token-xyz")
    assert token_h == "[REDACTED]"

    # Cookies: keys preserved, values masked
    cookie = redactor.redact_header_value("Cookie", "session_id=abc123xyz; user_pref=dark")
    assert "session_id=[REDACTED]" in cookie
    assert "user_pref=[REDACTED]" in cookie
    assert "abc123xyz" not in cookie

    # Non-sensitive header
    ct = redactor.redact_header_value("Content-Type", "application/json")
    assert ct == "application/json"


def test_redactor_query_param_redaction():
    redactor = Redactor(profile="strict")

    query = "foo=bar&token=secret123&api_key=my_key&page=2"
    redacted = redactor.redact_query_string(query)
    assert redacted is not None
    assert "foo=bar" in redacted
    assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted
    assert "page=2" in redacted
    assert "secret123" not in redacted
    assert "my_key" not in redacted

    url = "https://api.example.com/v1/data?token=secret123&client_id=123"
    redacted_url = redactor.redact_url(url)
    assert redacted_url is not None
    assert "secret123" not in redacted_url
    assert "client_id=123" in redacted_url


def test_redactor_json_body_redaction():
    redactor = Redactor(profile="strict")

    payload = {
        "user": {
            "name": "Alice",
            "password": "supersecretpassword",
            "tokens": ["tok_123456789", "tok_987654321"],
            "api_key": "sk-12345678",
        },
        "metadata": {"public_info": "ok"},
    }

    redacted = redactor.redact_data_structure(payload)
    assert redacted["user"]["name"] == "Alice"
    assert redacted["user"]["password"] == "[REDACTED]"
    assert redacted["user"]["api_key"] == "[REDACTED]"
    assert redacted["metadata"]["public_info"] == "ok"


def test_redactor_raw_body_bytes_redaction():
    redactor = Redactor(profile="strict")

    # JSON bytes
    raw_json = json.dumps({"password": "p123", "data": "val"}).encode("utf-8")
    redacted_b = redactor.redact_body_bytes(raw_json, "application/json")
    assert redacted_b is not None
    parsed = json.loads(redacted_b.decode("utf-8"))
    assert parsed["password"] == "[REDACTED]"
    assert parsed["data"] == "val"

    # Form urlencoded bytes
    raw_form = b"username=alice&password=secretpass123&scope=read"
    redacted_form_b = redactor.redact_body_bytes(raw_form, "application/x-www-form-urlencoded")
    assert redacted_form_b is not None
    assert b"secretpass123" not in redacted_form_b
    assert b"username=alice" in redacted_form_b

    # Malformed / unparseable JSON (fail closed)
    malformed_json = b'{"password": "secret", "incomplete'
    redacted_malformed = redactor.redact_body_bytes(malformed_json, "application/json")
    assert b"secret" not in redacted_malformed
    assert b"[REDACTED" in redacted_malformed

    # Non-string dictionary keys
    mixed_dict = {123: "val", "token": "secret_tok_456"}
    redacted_mixed = redactor.redact_data_structure(mixed_dict)
    assert redacted_mixed[123] == "val"
    assert redacted_mixed["token"] == "[REDACTED]"


def test_redactor_separator_normalization_headers():
    """Verify headers with underscores, hyphens, and mixed case are properly redacted."""
    redactor = Redactor(profile="strict")

    # Nonce variants
    assert redactor.redact_header_value("nonce", "val_1") == "[REDACTED]"
    assert redactor.redact_header_value("n_o_n_c_e", "val_2") == "[REDACTED]"
    assert redactor.redact_header_value("n-o-n-c-e", "val_3") == "[REDACTED]"
    assert redactor.redact_header_value("x-n-o-n-c-e", "val_4") == "[REDACTED]"
    assert redactor.redact_header_value("x_n_o_n_c_e", "val_5") == "[REDACTED]"
    assert redactor.redact_header_value("X-N-O-N-C-E", "val_6") == "[REDACTED]"
    assert redactor.redact_header_value("N_O_N_C_E", "val_7") == "[REDACTED]"
    assert redactor.redact_header_value("request_nonce", "val_8") == "[REDACTED]"
    assert redactor.redact_header_value("api_nonce", "val_9") == "[REDACTED]"

    # Other sensitive header variants
    assert redactor.redact_header_value("s_e_c_r_e_t", "val_10") == "[REDACTED]"
    assert redactor.redact_header_value("t_o_k_e_n", "val_11") == "[REDACTED]"
    assert redactor.redact_header_value("a_p_i_k_e_y", "val_12") == "[REDACTED]"
    assert redactor.redact_header_value("p_a_s_s_w_o_r_d", "val_13") == "[REDACTED]"
    assert redactor.redact_header_value("a_u_t_h", "val_14") == "[REDACTED]"

    # Non-sensitive header preserved
    assert redactor.redact_header_value("Content-Type", "application/json") == "application/json"
    assert redactor.redact_header_value("Accept-Encoding", "gzip, deflate") == "gzip, deflate"


def test_redactor_separator_normalization_query_string():
    """Verify query strings with separator-split keys are sanitized."""
    redactor = Redactor(profile="strict")

    qs = "n_o_n_c_e=sec_nonce_1&n-o-n-c-e=sec_nonce_2&x_n_o_n_c_e=sec_nonce_3&public_param=ok_val"
    redacted = redactor.redact_query_string(qs)
    assert redacted is not None
    assert "sec_nonce_1" not in redacted
    assert "sec_nonce_2" not in redacted
    assert "sec_nonce_3" not in redacted
    assert "public_param=ok_val" in redacted
    assert "n_o_n_c_e=%5BREDACTED%5D" in redacted or "n_o_n_c_e=[REDACTED]" in redacted
    assert "n-o-n-c-e=%5BREDACTED%5D" in redacted or "n-o-n-c-e=[REDACTED]" in redacted

    url = "https://api.example.com/v1/query?n_o_n_c_e=top_secret_123&regular=hello"
    redacted_url = redactor.redact_url(url)
    assert redacted_url is not None
    assert "top_secret_123" not in redacted_url
    assert "regular=hello" in redacted_url


def test_redactor_separator_normalization_data_structure():
    """Verify nested data structures containing split-nonce and sensitive keys are redacted."""
    redactor = Redactor(profile="strict")

    payload = {
        "response": {
            "body": {
                "result": {"positions": [{"symbol": "BTCUSDT", "size": "1.0"}]},
                "metadata": {
                    "nonce": "sec_normal_nonce",
                    "n_o_n_c_e": "sec_split_nonce_1",
                    "n-o-n-c-e": "sec_split_nonce_2",
                    "x_n_o_n_c_e": "sec_split_nonce_3",
                    "x-n-o-n-c-e": "sec_split_nonce_4",
                    "s_e_c_r_e_t": "sec_split_secret",
                    "p_a_s_s_w_o_r_d": "sec_split_password",
                    "t_o_k_e_n": "sec_split_token",
                    "normal_field": "safe_data",
                },
            }
        }
    }

    redacted = redactor.redact_data_structure(payload)
    meta = redacted["response"]["body"]["metadata"]
    assert meta["nonce"] == "[REDACTED]"
    assert meta["n_o_n_c_e"] == "[REDACTED]"
    assert meta["n-o-n-c-e"] == "[REDACTED]"
    assert meta["x_n_o_n_c_e"] == "[REDACTED]"
    assert meta["x-n-o-n-c-e"] == "[REDACTED]"
    assert meta["s_e_c_r_e_t"] == "[REDACTED]"
    assert meta["p_a_s_s_w_o_r_d"] == "[REDACTED]"
    assert meta["t_o_k_e_n"] == "[REDACTED]"
    assert meta["normal_field"] == "safe_data"
    assert redacted["response"]["body"]["result"]["positions"][0]["symbol"] == "BTCUSDT"

    # Also test byte payload redaction
    json_bytes = json.dumps(payload).encode("utf-8")
    redacted_bytes = redactor.redact_body_bytes(json_bytes, "application/json")
    assert redacted_bytes is not None
    assert b"sec_split_nonce_1" not in redacted_bytes
    assert b"sec_split_nonce_2" not in redacted_bytes
    assert b"sec_split_secret" not in redacted_bytes
    assert b"safe_data" in redacted_bytes



def test_pipeline_redaction_before_persistence(tmp_path: Path):
    spec_dir = tmp_path / "specs"
    store = Store(specs_dir=spec_dir)
    db_path = tmp_path / "motim.sqlite3"
    writer = BufferedExchangeWriter(db_path, flush_interval_ms=10, queue_max=100)
    redactor = Redactor(profile="strict")

    pipeline = CapturePipeline(
        store=store,
        exchange_writer=writer,
        redactor=redactor,
    )
    pipeline.start()

    try:
        raw_secret_body = json.dumps(
            {"auth_token": "SUPER_SECRET_TOKEN_999", "public_id": "item_123"}
        ).encode("utf-8")

        pipeline.enqueue(
            "http",
            {
                "scheme": "https",
                "host": "api.example.com",
                "port": 443,
                "method": "POST",
                "status": 200,
                "path": "/v1/auth/login?token=QUERY_SECRET_TOKEN",
                "path_only": "/v1/auth/login",
                "query": "token=QUERY_SECRET_TOKEN",
                "query_params": {"token": "QUERY_SECRET_TOKEN"},
                "url": "https://api.example.com/v1/auth/login?token=QUERY_SECRET_TOKEN",
                "service_key": "api_example_com",
                "request_headers": {
                    "Authorization": "Bearer HEADER_SECRET_TOKEN",
                    "Cookie": "session=COOKIE_SECRET_TOKEN",
                    "Content-Type": "application/json",
                },
                "response_headers": {"Content-Type": "application/json"},
                "req_fields": [
                    HeaderField("Authorization", "Bearer HEADER_SECRET_TOKEN"),
                    HeaderField("Cookie", "session=COOKIE_SECRET_TOKEN"),
                ],
                "resp_fields": [],
                "req_body": raw_secret_body,
                "resp_body": b'{"status": "authenticated"}',
                "req_content_type": "application/json",
                "resp_content_type": "application/json",
            },
        )

        pipeline.stop(timeout=3.0)
        writer.close()

        # Check YAML Spec file
        store.flush()
        spec = store.load("api_example_com")
        assert spec is not None
        spec_text = (spec_dir / "api_example_com.yaml").read_text()
        assert "SUPER_SECRET_TOKEN_999" not in spec_text
        assert "HEADER_SECRET_TOKEN" not in spec_text
        assert "COOKIE_SECRET_TOKEN" not in spec_text
        assert "QUERY_SECRET_TOKEN" not in spec_text

        # Check SQLite DB
        db = ExchangeDB(db_path)
        try:
            ex = db.get_exchange(1)
            assert ex is not None
            # Check headers
            for h in ex["headers"]["request"]:
                assert "HEADER_SECRET_TOKEN" not in h["value"]
                assert "COOKIE_SECRET_TOKEN" not in h["value"]

            # Check raw body in DB
            req_body_db = ex["bodies"]["request"]
            assert req_body_db is not None
            assert b"SUPER_SECRET_TOKEN_999" not in req_body_db
            assert b"[REDACTED]" in req_body_db

            # Check auth_snapshots
            snap = db.latest_auth_snapshot("api_example_com")
            if snap:
                snap_str = json.dumps(snap)
                assert "HEADER_SECRET_TOKEN" not in snap_str
                assert "COOKIE_SECRET_TOKEN" not in snap_str
        finally:
            db.close()

    finally:
        writer.close()


def test_redactor_url_userinfo_redaction():
    """Verify Redactor.redact_url() properly redacts userinfo credentials with or without query strings."""
    redactor = Redactor(profile="strict")

    # 1. URL with username:password and no query string
    url_noparams = "https://admin:super_secret_password_123@api.example.com/v1/positions"
    redacted = redactor.redact_url(url_noparams)
    assert redacted is not None
    assert "super_secret_password_123" not in redacted
    assert "admin:[REDACTED]@api.example.com" in redacted
    assert "/v1/positions" in redacted

    # 2. URL with sensitive username / API key in userinfo
    url_apikey = "https://sk_live_canary_key_9988@api.example.com/v1/data"
    redacted_apikey = redactor.redact_url(url_apikey)
    assert redacted_apikey is not None
    assert "sk_live_canary_key_9988" not in redacted_apikey
    assert "[REDACTED]@api.example.com" in redacted_apikey

    # 3. URL with userinfo and query parameters
    url_full = "https://user:mypassword@api.example.com:8443/data?token=secret_tok_456&client_id=123"
    redacted_full = redactor.redact_url(url_full)
    assert redacted_full is not None
    assert "mypassword" not in redacted_full
    assert "secret_tok_456" not in redacted_full
    assert "client_id=123" in redacted_full
    assert "user:[REDACTED]@api.example.com:8443" in redacted_full

    # 4. Schemeless URL with userinfo
    url_schemeless = "user:secretpass789@example.com/positions"
    redacted_schemeless = redactor.redact_url(url_schemeless)
    assert redacted_schemeless is not None
    assert "secretpass789" not in redacted_schemeless
    assert "user:[REDACTED]@example.com/positions" in redacted_schemeless

    # 5. Clean URL without userinfo or query params preserved
    url_clean = "https://api.example.com/v1/public/ping"
    assert redactor.redact_url(url_clean) == url_clean


def test_redactor_recursive_containers_data_structure():
    """Verify Redactor.redact_data_structure() recursively redacts tuples, sets, frozensets, and mappings."""
    redactor = Redactor(profile="strict")

    # 1. Tuple containing sensitive dict and strings
    data_tuple = ("safe_first", {"password": "top_secret_pass", "safe_k": "val"}, ("Bearer CANARY_TUPLE_TOKEN_123",))
    redacted_tuple = redactor.redact_data_structure(data_tuple)
    assert isinstance(redacted_tuple, tuple)
    assert redacted_tuple[0] == "safe_first"
    assert redacted_tuple[1]["password"] == "[REDACTED]"
    assert redacted_tuple[1]["safe_k"] == "val"
    assert "top_secret_pass" not in str(redacted_tuple)
    assert "CANARY_TUPLE_TOKEN_123" not in str(redacted_tuple)
    assert redacted_tuple[2] == ("Bearer [REDACTED]",)

    # 2. Set containing sensitive tokens
    data_set = {"public_tag", "Bearer CANARY_SET_TOKEN_456", "ghp_CANARY_GITHUB_PAT_789"}
    redacted_set = redactor.redact_data_structure(data_set)
    assert isinstance(redacted_set, set)
    assert "public_tag" in redacted_set
    assert "CANARY_SET_TOKEN_456" not in str(redacted_set)
    assert "CANARY_GITHUB_PAT_789" not in str(redacted_set)
    assert "[REDACTED]" in redacted_set or "Bearer [REDACTED]" in redacted_set

    # 3. Frozenset containing sensitive values
    data_frozenset = frozenset(["clean_entry", "sk_live_CANARY_FROZEN_999"])
    redacted_frozenset = redactor.redact_data_structure(data_frozenset)
    assert isinstance(redacted_frozenset, frozenset)
    assert "clean_entry" in redacted_frozenset
    assert "CANARY_FROZEN_999" not in str(redacted_frozenset)

    # 4. Deeply nested mixed container tree
    complex_tree = {
        "outer_key": [
            (
                "item_name",
                frozenset([("n_o_n_c_e", "secret_nonce_val"), ("api_key", "sec_key_val")]),
                {"nested_set": {"Bearer CANARY_DEEP_TOKEN_000", "safe_val"}},
            )
        ]
    }
    redacted_tree = redactor.redact_data_structure(complex_tree)
    assert "secret_nonce_val" not in str(redacted_tree)
    assert "sec_key_val" not in str(redacted_tree)
    assert "CANARY_DEEP_TOKEN_000" not in str(redacted_tree)


def test_redactor_body_bytes_unknown_content_type_fail_closed():
    """Verify Redactor.redact_body_bytes() fail-closed sanitizes form-shaped credentials when content_type is unknown."""
    redactor = Redactor(profile="strict")

    # 1. Single form field: password with unknown content-type
    b1 = b"password=my_super_secret_password_1122"
    r1 = redactor.redact_body_bytes(b1, None)
    assert r1 is not None
    assert b"my_super_secret_password_1122" not in r1
    assert b"password=" in r1
    assert b"[REDACTED]" in r1 or b"%5BREDACTED%5D" in r1

    # 2. Single auth field: token with empty content-type
    b2 = b"token=secret_token_val_3344"
    r2 = redactor.redact_body_bytes(b2, "")
    assert r2 is not None
    assert b"secret_token_val_3344" not in r2
    assert b"token=" in r2

    # 3. Single field: api_key with octet-stream content-type
    b3 = b"api_key=sk_live_canary_key_5566"
    r3 = redactor.redact_body_bytes(b3, "application/octet-stream")
    assert r3 is not None
    assert b"sk_live_canary_key_5566" not in r3
    assert b"api_key=" in r3

    # 4. Single field: split-nonce with unknown content-type
    b4 = b"n_o_n_c_e=secret_split_nonce_7788"
    r4 = redactor.redact_body_bytes(b4, None)
    assert r4 is not None
    assert b"secret_split_nonce_7788" not in r4
    assert b"n_o_n_c_e=" in r4

    # 5. Multi-line key-value body with unknown / text content-type
    b5 = b"username=alice\npassword=top_secret_line_pass\npublic_flag=true"
    r5 = redactor.redact_body_bytes(b5, "text/plain")
    assert r5 is not None
    assert b"top_secret_line_pass" not in r5
    assert b"username=alice" in r5
    assert b"public_flag=true" in r5

    # 6. Benign content preserved
    b6 = b"status=ok&count=5&name=Alice"
    r6 = redactor.redact_body_bytes(b6, None)
    assert r6 == b"status=ok&count=5&name=Alice"

