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


def test_redactor_body_bytes_utf16_and_encodings():
    """Verify Redactor.redact_body_bytes() properly redacts UTF-16 encoded payloads and preserves benign content."""
    redactor = Redactor(profile="strict")

    # 1. UTF-16-LE with BOM containing password
    canary_utf16_1 = "CANARY_UTF16_PW_LE_1122"
    raw_utf16_le = f"password: {canary_utf16_1}\nuser: alice".encode("utf-16-le")
    # Add BOM
    bom_le = b"\xff\xfe" + raw_utf16_le
    red_le = redactor.redact_body_bytes(bom_le, "text/plain; charset=utf-16")
    assert red_le is not None
    assert canary_utf16_1.encode("utf-16-le") not in red_le
    assert canary_utf16_1.encode("utf-8") not in red_le
    decoded_le = red_le.decode("utf-16")
    assert "[REDACTED]" in decoded_le
    assert "user: alice" in decoded_le

    # 2. UTF-16-BE with BOM containing api_key
    canary_utf16_2 = "CANARY_UTF16_KEY_BE_3344"
    raw_utf16_be = f"api_key: {canary_utf16_2}\nstatus: ok".encode("utf-16-be")
    bom_be = b"\xfe\xff" + raw_utf16_be
    red_be = redactor.redact_body_bytes(bom_be, None)
    assert red_be is not None
    assert canary_utf16_2.encode("utf-16-be") not in red_be
    decoded_be = red_be.decode("utf-16")
    assert "[REDACTED]" in decoded_be
    assert "status: ok" in decoded_be

    # 3. Benign UTF-16 content preserved
    benign_utf16 = "item: widget\ncount: 10".encode("utf-16")
    red_benign = redactor.redact_body_bytes(benign_utf16, "text/plain")
    assert red_benign is not None
    assert "item: widget" in red_benign.decode("utf-16")
    assert "count: 10" in red_benign.decode("utf-16")


def test_redactor_body_bytes_generic_colon_text_redaction():
    """Verify Redactor.redact_body_bytes() sanitizes colon, equals, and walrus separated generic text."""
    redactor = Redactor(profile="strict")

    # 1. Plain colon text
    canary_colon_1 = "CANARY_COLON_PW_5566"
    b1 = f"password: {canary_colon_1}".encode("utf-8")
    r1 = redactor.redact_body_bytes(b1, "text/plain")
    assert r1 is not None
    assert canary_colon_1.encode("utf-8") not in r1
    assert b"password: [REDACTED]" in r1

    # 2. Quoted colon text
    canary_colon_2 = "CANARY_COLON_KEY_7788"
    b2 = f'api_key: "{canary_colon_2}"'.encode("utf-8")
    r2 = redactor.redact_body_bytes(b2, None)
    assert r2 is not None
    assert canary_colon_2.encode("utf-8") not in r2
    assert b'api_key: "[REDACTED]"' in r2

    # 3. Equals text with spaces
    canary_colon_3 = "CANARY_COLON_TOK_9900"
    b3 = f"token = '{canary_colon_3}'".encode("utf-8")
    r3 = redactor.redact_body_bytes(b3, None)
    assert r3 is not None
    assert canary_colon_3.encode("utf-8") not in r3
    assert b"token = '[REDACTED]'" in r3

    # 4. Walrus := operator
    canary_colon_4 = "CANARY_COLON_SEC_1133"
    b4 = f"secret := {canary_colon_4}".encode("utf-8")
    r4 = redactor.redact_body_bytes(b4, None)
    assert r4 is not None
    assert canary_colon_4.encode("utf-8") not in r4
    assert b"secret := [REDACTED]" in r4

    # 5. Split-nonce in colon format
    canary_colon_5 = "CANARY_COLON_NONCE_5577"
    b5 = f"n_o_n_c_e: {canary_colon_5}".encode("utf-8")
    r5 = redactor.redact_body_bytes(b5, None)
    assert r5 is not None
    assert canary_colon_5.encode("utf-8") not in r5
    assert b"n_o_n_c_e: [REDACTED]" in r5

    # 6. Percent-encoded key in colon format
    canary_colon_6 = "CANARY_COLON_PCT_9911"
    b6 = f"api%5Fkey: {canary_colon_6}".encode("utf-8")
    r6 = redactor.redact_body_bytes(b6, None)
    assert r6 is not None
    assert canary_colon_6.encode("utf-8") not in r6
    assert b"api%5Fkey: [REDACTED]" in r6

    # 7. Multiline YAML-like payload preserving benign fields
    canary_yaml_pw = "CANARY_YAML_SECRET_PASS_2244"
    canary_yaml_key = "CANARY_YAML_SECRET_KEY_6688"
    yaml_text = (
        f"user: alice\n"
        f"password: {canary_yaml_pw}\n"
        f"role: admin\n"
        f"api_key: '{canary_yaml_key}'\n"
        f"status: 200\n"
    )
    r7 = redactor.redact_body_bytes(yaml_text.encode("utf-8"), "application/x-yaml")
    assert r7 is not None
    assert canary_yaml_pw.encode("utf-8") not in r7
    assert canary_yaml_key.encode("utf-8") not in r7
    decoded_yaml = r7.decode("utf-8")
    assert "user: alice" in decoded_yaml
    assert "password: [REDACTED]" in decoded_yaml
    assert "role: admin" in decoded_yaml
    assert "api_key: '[REDACTED]'" in decoded_yaml
    assert "status: 200" in decoded_yaml


def test_redactor_body_bytes_unparseable_binary_and_compressed_fail_closed():
    """Verify Redactor.redact_body_bytes() fails closed on compressed and unparseable binary data."""
    import gzip
    redactor = Redactor(profile="strict")

    # 1. Gzip compressed payload with canary
    canary_gzip = "CANARY_GZIP_SECRET_998811"
    gzip_bytes = gzip.compress(f"password={canary_gzip}".encode("utf-8"))
    r_gzip = redactor.redact_body_bytes(gzip_bytes, "application/gzip")
    assert r_gzip == b"[REDACTED: unparseable binary body]"
    assert canary_gzip.encode("utf-8") not in r_gzip

    # 2. Deflate / compressed content type
    canary_deflate = "CANARY_DEFLATE_SECRET_223344"
    r_deflate = redactor.redact_body_bytes(b"\x78\x9c\x01" + canary_deflate.encode("utf-8"), "application/x-deflate")
    assert r_deflate == b"[REDACTED: unparseable binary body]"
    assert canary_deflate.encode("utf-8") not in r_deflate

    # 3. Arbitrary non-UTF-8 / non-UTF-16 binary data containing canary
    canary_bin = "CANARY_RAW_BINARY_SECRET_556677"
    raw_bin = b"\x00\x80\xff\xfe\x00\x81\x92" + canary_bin.encode("utf-8") + b"\xff\xff\x00\x00"
    r_bin = redactor.redact_body_bytes(raw_bin, None)
    assert r_bin == b"[REDACTED: unparseable binary body]"
    assert canary_bin.encode("utf-8") not in r_bin


def test_persistence_path_utf16_colon_and_binary_redaction(tmp_path: Path):
    """Verify ExchangeDB persistence sanitizes UTF-16, colon text, and binary payloads before disk storage."""
    import gzip
    db_path = tmp_path / "motim_persist.sqlite3"
    db = ExchangeDB(db_path)

    canary_persist_utf16 = "CANARY_PERSIST_UTF16_0011"
    canary_persist_colon = "CANARY_PERSIST_COLON_2233"
    canary_persist_bin = "CANARY_PERSIST_BINARY_4455"

    try:
        # 1. Insert exchange with UTF-16 body
        utf16_body = f"password: {canary_persist_utf16}".encode("utf-16")
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/auth",
            query=None,
            url="https://api.example.com/v1/auth",
            status=200,
            req_body=utf16_body,
            req_content_type="text/plain; charset=utf-16",
        )

        # 2. Insert exchange with colon generic text body
        colon_body = f"user: alice\napi_key: {canary_persist_colon}".encode("utf-8")
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/key",
            query=None,
            url="https://api.example.com/v1/key",
            status=200,
            req_body=colon_body,
            req_content_type="text/plain",
        )

        # 3. Insert exchange with gzip compressed body
        bin_body = gzip.compress(f"secret={canary_persist_bin}".encode("utf-8"))
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/upload",
            query=None,
            url="https://api.example.com/v1/upload",
            status=200,
            req_body=bin_body,
            req_content_type="application/gzip",
        )

        # Verify all exchanges in database
        for ex_id in (1, 2, 3):
            ex = db.get_exchange(ex_id)
            assert ex is not None
            req_body = ex["bodies"]["request"]
            assert req_body is not None

            # Assert zero canary leaks in persisted raw bytes
            for canary in (canary_persist_utf16, canary_persist_colon, canary_persist_bin):
                assert canary.encode("utf-8") not in req_body
                assert canary.encode("utf-16") not in req_body
                assert canary.encode("utf-16-le") not in req_body
                assert canary.encode("utf-16-be") not in req_body

        # Assert no canary strings in entire SQLite file
        db_bytes = db_path.read_bytes()
        for canary in (canary_persist_utf16, canary_persist_colon, canary_persist_bin):
            assert canary.encode("utf-8") not in db_bytes
            assert canary.encode("utf-16") not in db_bytes
            assert canary.encode("utf-16-le") not in db_bytes
            assert canary.encode("utf-16-be") not in db_bytes

    finally:
        db.close()


def test_redactor_bomless_utf16_and_nul_handling():
    """Verify Redactor.redact_body_bytes() handles BOM-less UTF-16LE/BE and fails closed on NUL-bearing binary."""
    redactor = Redactor(profile="strict")

    # 1. BOM-less UTF-16LE with missing content type (None)
    canary_le_none = "CANARY_BOMLESS_LE_NONE_1122"
    raw_le_none = f"password: {canary_le_none}".encode("utf-16-le")
    r_le_none = redactor.redact_body_bytes(raw_le_none, None)
    assert r_le_none is not None
    assert canary_le_none.encode("utf-8") not in r_le_none
    assert canary_le_none.encode("utf-16-le") not in r_le_none
    decoded_le = r_le_none.decode("utf-16-le")
    assert "[REDACTED]" in decoded_le

    # 2. BOM-less UTF-16LE with generic content type (text/plain and application/octet-stream)
    canary_le_plain = "CANARY_BOMLESS_LE_PLAIN_3344"
    raw_le_plain = f'api_key: "{canary_le_plain}"\nuser: alice'.encode("utf-16-le")
    r_le_plain = redactor.redact_body_bytes(raw_le_plain, "text/plain")
    assert r_le_plain is not None
    assert canary_le_plain.encode("utf-8") not in r_le_plain
    assert canary_le_plain.encode("utf-16-le") not in r_le_plain
    decoded_le_plain = r_le_plain.decode("utf-16-le")
    assert '[REDACTED]' in decoded_le_plain
    assert "user: alice" in decoded_le_plain

    # 3. BOM-less UTF-16BE with missing content type (None)
    canary_be_none = "CANARY_BOMLESS_BE_NONE_5566"
    raw_be_none = f"secret: {canary_be_none}".encode("utf-16-be")
    r_be_none = redactor.redact_body_bytes(raw_be_none, None)
    assert r_be_none is not None
    assert canary_be_none.encode("utf-8") not in r_be_none
    assert canary_be_none.encode("utf-16-be") not in r_be_none
    decoded_be = r_be_none.decode("utf-16-be")
    assert "[REDACTED]" in decoded_be

    # 4. BOM-less UTF-16BE with generic content type (application/octet-stream)
    canary_be_octet = "CANARY_BOMLESS_BE_OCTET_7788"
    raw_be_octet = f"token: '{canary_be_octet}'\nstatus: ok".encode("utf-16-be")
    r_be_octet = redactor.redact_body_bytes(raw_be_octet, "application/octet-stream")
    assert r_be_octet is not None
    assert canary_be_octet.encode("utf-8") not in r_be_octet
    assert canary_be_octet.encode("utf-16-be") not in r_be_octet
    decoded_be_octet = r_be_octet.decode("utf-16-be")
    assert "[REDACTED]" in decoded_be_octet
    assert "status: ok" in decoded_be_octet

    # 5. Benign BOM-less UTF-16LE / UTF-16BE content preservation
    benign_le = "status: ok\ncount: 10".encode("utf-16-le")
    r_benign_le = redactor.redact_body_bytes(benign_le, None)
    assert r_benign_le is not None
    assert r_benign_le.decode("utf-16-le") == "status: ok\ncount: 10"

    benign_be = "status: ok\ncount: 10".encode("utf-16-be")
    r_benign_be = redactor.redact_body_bytes(benign_be, "text/plain")
    assert r_benign_be is not None
    assert r_benign_be.decode("utf-16-be") == "status: ok\ncount: 10"

    # 6. Arbitrary NUL-bearing non-UTF-16 binary data: fails closed
    canary_bin_nul = "CANARY_NUL_BINARY_SECRET_9900"
    raw_bin_nul = b"\x00\x01\x02\x03\x00\xff" + canary_bin_nul.encode("utf-8") + b"\x00\x00\xfe"
    r_bin_nul = redactor.redact_body_bytes(raw_bin_nul, None)
    assert r_bin_nul == b"[REDACTED: unparseable binary body]"
    assert canary_bin_nul.encode("utf-8") not in r_bin_nul


def test_persistence_path_bomless_utf16_redaction(tmp_path: Path):
    """Verify ExchangeDB persistence sanitizes BOM-less UTF-16LE/BE and NUL binary payloads."""
    db_path = tmp_path / "motim_bomless_persist.sqlite3"
    db = ExchangeDB(db_path)

    canary_le = "CANARY_PERSIST_BOMLESS_LE_1133"
    canary_be = "CANARY_PERSIST_BOMLESS_BE_3355"
    canary_bin = "CANARY_PERSIST_NUL_BIN_5577"

    try:
        # 1. BOM-less UTF-16LE with None content-type
        body_le = f"password: {canary_le}".encode("utf-16-le")
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/le",
            query=None,
            url="https://api.example.com/v1/le",
            status=200,
            req_body=body_le,
            req_content_type=None,
        )

        # 2. BOM-less UTF-16BE with text/plain content-type
        body_be = f"user: alice\napi_key: {canary_be}".encode("utf-16-be")
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/be",
            query=None,
            url="https://api.example.com/v1/be",
            status=200,
            req_body=body_be,
            req_content_type="text/plain",
        )

        # 3. NUL-bearing binary with application/octet-stream
        body_bin = b"\x00\x01\x02\x03\x00\xff" + canary_bin.encode("utf-8") + b"\x00\x00\xfe"
        db.put_exchange(
            scheme="https",
            host="api.example.com",
            port=443,
            method="POST",
            path="/v1/bin",
            query=None,
            url="https://api.example.com/v1/bin",
            status=200,
            req_body=body_bin,
            req_content_type="application/octet-stream",
        )

        # Verify all exchanges in database
        for ex_id in (1, 2, 3):
            ex = db.get_exchange(ex_id)
            assert ex is not None
            req_body = ex["bodies"]["request"]
            assert req_body is not None

            for canary in (canary_le, canary_be, canary_bin):
                assert canary.encode("utf-8") not in req_body
                assert canary.encode("utf-16") not in req_body
                assert canary.encode("utf-16-le") not in req_body
                assert canary.encode("utf-16-be") not in req_body

        # Assert no canary strings in entire SQLite file
        db_bytes = db_path.read_bytes()
        for canary in (canary_le, canary_be, canary_bin):
            assert canary.encode("utf-8") not in db_bytes
            assert canary.encode("utf-16") not in db_bytes
            assert canary.encode("utf-16-le") not in db_bytes
            assert canary.encode("utf-16-be") not in db_bytes

    finally:
        db.close()



