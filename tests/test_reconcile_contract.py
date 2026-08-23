"""Contract tests for motim.account_read.v1 and motim.sanitized_exchange.v1 (Gate 1)."""

from __future__ import annotations

import json
from pathlib import Path
from decimal import Decimal
import pytest

from motim.reconcile import (
    AccountReadResult,
    Fact,
    FactType,
    Issue,
    IssueCode,
    Outcome,
    Severity,
    reconcile,
    to_canonical_decimal_str,
)
from motim.reconcile.validator import (
    ValidationError,
    contains_auth_elements,
    parse_rfc3339_z,
    validate_sanitized_exchange,
)
from motim.reconcile.dedup import deduplicate_facts, compute_dedup_key
from motim.reconcile.staleness import check_staleness


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reconciliation"


class TestGate1ContractRequirements:
    """Gate 1: Contract verification for sanitized exchange input and account read output."""

    def test_canonical_decimal_strings(self):
        """All quantities, prices, fees, and PnL values are canonical base-10 decimal strings."""
        assert to_canonical_decimal_str("0.5000") == "0.5"
        assert to_canonical_decimal_str("100.00") == "100"
        assert to_canonical_decimal_str("0.00000001") == "0.00000001"
        assert to_canonical_decimal_str(0.0) == "0"
        assert to_canonical_decimal_str("-0.00") == "0"
        assert to_canonical_decimal_str("-10.50") == "-10.5"
        assert to_canonical_decimal_str(100) == "100"
        assert to_canonical_decimal_str(Decimal("12345.67890")) == "12345.6789"

        with pytest.raises(ValueError):
            to_canonical_decimal_str("invalid_number")
        with pytest.raises(ValueError):
            to_canonical_decimal_str(True)
        with pytest.raises(ValueError):
            to_canonical_decimal_str(None)

    def test_parse_rfc3339_z(self):
        """RFC3339 timestamps must end with 'Z'."""
        dt = parse_rfc3339_z("2026-08-23T14:00:00Z")
        assert dt.year == 2026
        assert dt.month == 8
        assert dt.day == 23

        with pytest.raises(ValueError):
            parse_rfc3339_z("2026-08-23 14:00:00")  # missing T and Z
        with pytest.raises(ValueError):
            parse_rfc3339_z("2026-08-23T14:00:00+00:00")  # must use Z
        with pytest.raises(ValueError):
            parse_rfc3339_z("invalid")

    def test_strict_mode_rejects_unknown_top_level_fields(self):
        """Strict mode rejects unknown top-level fields."""
        invalid_exchange = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "ex-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {"status": 200, "content_type": "application/json", "body": {}},
            "extra_forbidden_field": "disallowed",
        }
        with pytest.raises(ValidationError) as exc:
            validate_sanitized_exchange(invalid_exchange, expected_provider="bybit", strict=True)
        assert "extra_forbidden_field" in str(exc.value)

        # In non-strict mode, extra top-level field is tolerated
        validated = validate_sanitized_exchange(invalid_exchange, expected_provider="bybit", strict=False)
        assert validated["exchange_id"] == "ex-001"

    def test_reject_duplicate_exchange_ids_in_batch(self):
        """Exchange IDs must be unique within an input file/batch."""
        seen = set()
        exchange1 = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "dup-id-1",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {"status": 200, "body": {}},
        }
        validate_sanitized_exchange(exchange1, expected_provider="bybit", strict=True, seen_exchange_ids=seen)
        with pytest.raises(ValidationError) as exc:
            validate_sanitized_exchange(exchange1, expected_provider="bybit", strict=True, seen_exchange_ids=seen)
        assert "Duplicate exchange_id" in str(exc.value)

    def test_reject_auth_shaped_fields_with_redacted_error(self):
        """Auth-shaped fields anywhere in the tree are rejected without echoing the value."""
        secret_canary = "SUPER_SECRET_CANARY_VALUE_XYZ"
        secret_exchange = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "auth-ex-001",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {
                "method": "GET",
                "route_key": "positions",
                "authorization": f"Bearer {secret_canary}",
            },
            "response": {"status": 200, "body": {}},
        }
        assert contains_auth_elements(secret_exchange) is True
        with pytest.raises(ValidationError) as exc:
            validate_sanitized_exchange(secret_exchange, expected_provider="bybit")

        # Must not echo secret in message
        assert secret_canary not in str(exc.value)
        assert "[REDACTED]" in str(exc.value)

    def test_source_traceability(self):
        """Facts must preserve source_exchange_ids pointing back to inputs."""
        fixture_path = FIXTURES_DIR / "bybit_all_facts.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")
        assert result.outcome == Outcome.OK.value
        assert len(result.facts) >= 5
        for fact in result.facts:
            assert len(fact.source_exchange_ids) > 0
            assert all(isinstance(s_id, str) for s_id in fact.source_exchange_ids)

    def test_deterministic_staleness(self):
        """Staleness is deterministic relative to as_of and max_age_seconds."""
        fixture_path = FIXTURES_DIR / "bybit_stale.jsonl"
        # 4 hours difference: 14:00:00Z vs 10:00:00Z = 14400s
        # With max_age_seconds=0, it should be flagged as stale
        result_stale = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:00:00Z", max_age_seconds=0)
        assert result_stale.outcome == Outcome.OK.value
        assert len(result_stale.facts) == 1
        stale_issues = [i for i in result_stale.issues if i.code == IssueCode.STALE_FACT.value]
        assert len(stale_issues) == 1
        assert stale_issues[0].source_exchange_id == "bybit-stale-001"

        # With max_age_seconds=20000, it is fresh (no stale issue)
        result_fresh = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:00:00Z", max_age_seconds=20000)
        stale_issues_fresh = [i for i in result_fresh.issues if i.code == IssueCode.STALE_FACT.value]
        assert len(stale_issues_fresh) == 0

    def test_exact_vs_conflicting_deduplication(self):
        """Exact duplicates collapse into one fact; conflicting records are omitted."""
        fixture_path = FIXTURES_DIR / "bybit_duplicates.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        # Outcome is partial because of the conflicting duplicate
        assert result.outcome == Outcome.PARTIAL.value

        # BTCUSDT was exact duplicate -> merged into 1 fact with 2 source IDs
        btc_facts = [f for f in result.facts if f.data.get("symbol") == "BTCUSDT"]
        assert len(btc_facts) == 1
        assert sorted(btc_facts[0].source_exchange_ids) == ["bybit-dup-001", "bybit-dup-002"]

        # ETHUSDT was conflicting -> omitted
        eth_facts = [f for f in result.facts if f.data.get("symbol") == "ETHUSDT"]
        assert len(eth_facts) == 0

        # Issues should contain both duplicate_event and conflicting_duplicate
        dup_issues = [i for i in result.issues if i.code == IssueCode.DUPLICATE_EVENT.value]
        conf_issues = [i for i in result.issues if i.code == IssueCode.CONFLICTING_DUPLICATE.value]
        assert len(dup_issues) == 1
        assert len(conf_issues) == 1

    def test_non_finite_decimals_rejected(self):
        """Non-finite values (NaN, Infinity, -Infinity) are rejected in decimal util and JSON parse."""
        for non_finite in ("NaN", "Infinity", "-Infinity", float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
            with pytest.raises(ValueError, match="Non-finite decimal value"):
                to_canonical_decimal_str(non_finite)

        # In JSON Lines string parsing
        for const in ("NaN", "Infinity", "-Infinity"):
            bad_jsonl = (
                f'{{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "nf-1", '
                f'"provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", '
                f'"request": {{"method": "GET", "route_key": "positions"}}, '
                f'"response": {{"status": 200, "body": {{"result": {{"list": [{{"symbol": "BTCUSDT", "size": {const}}}]}}}}}}}}'
            )
            res = reconcile(bad_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
            assert res.outcome == Outcome.INVALID_INPUT.value
            assert len(res.facts) == 0
            assert any("Non-finite" in i.message or "syntax error" in i.message for i in res.issues)

    def test_response_status_boolean_rejected(self):
        """Boolean response.status (e.g. true) is rejected as invalid integer."""
        bool_exchange = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "bool-status-1",
            "provider": "bybit",
            "captured_at": "2026-08-23T14:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {"status": True, "body": {}},
        }
        with pytest.raises(ValidationError, match="response.status"):
            validate_sanitized_exchange(bool_exchange, expected_provider="bybit")

        # Via JSONL string with literal true
        bool_jsonl = (
            '{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "bool-status-2", '
            '"provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", '
            '"request": {"method": "GET", "route_key": "positions"}, '
            '"response": {"status": true, "body": {}}}'
        )
        res = reconcile(bool_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0

    def test_deduplication_order_independence_and_staleness(self):
        """Exact duplicates retain the latest observed_at fact regardless of input file/list order."""
        rec_early = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "ex-early",
            "provider": "bybit",
            "captured_at": "2026-08-23T10:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5", "entryPrice": "50000", "markPrice": "51000"}]}},
            },
        }
        rec_late = {
            "schema_version": "motim.sanitized_exchange.v1",
            "exchange_id": "ex-late",
            "provider": "bybit",
            "captured_at": "2026-08-23T12:00:00Z",
            "request": {"method": "GET", "route_key": "positions"},
            "response": {
                "status": 200,
                "body": {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5", "entryPrice": "50000", "markPrice": "51000"}]}},
            },
        }

        # As-of is 12:05:00Z, max_age_seconds is 600 (10 min).
        # rec_early alone is 2h5m old (stale), rec_late is 5m old (fresh).
        # Merged result MUST be fresh (using 12:00:00Z) regardless of input order.
        res_forward = reconcile([rec_early, rec_late], "bybit", as_of="2026-08-23T12:05:00Z", max_age_seconds=600)
        res_reverse = reconcile([rec_late, rec_early], "bybit", as_of="2026-08-23T12:05:00Z", max_age_seconds=600)

        assert res_forward.outcome == Outcome.OK.value
        assert res_reverse.outcome == Outcome.OK.value

        assert len(res_forward.facts) == 1
        assert len(res_reverse.facts) == 1

        fact_f = res_forward.facts[0]
        fact_r = res_reverse.facts[0]

        assert fact_f.observed_at == "2026-08-23T12:00:00Z"
        assert fact_r.observed_at == "2026-08-23T12:00:00Z"
        assert fact_f.source_exchange_ids == ["ex-early", "ex-late"]
        assert fact_r.source_exchange_ids == ["ex-early", "ex-late"]
        assert fact_f.to_dict() == fact_r.to_dict()

        # Check issues: no stale fact issue in either
        assert not any(i.code == IssueCode.STALE_FACT.value for i in res_forward.issues)
        assert not any(i.code == IssueCode.STALE_FACT.value for i in res_reverse.issues)

    def test_reconcile_negative_max_age_seconds(self):
        """Negative max_age_seconds returns structured invalid_input result."""
        fixture_path = FIXTURES_DIR / "bybit_all_facts.jsonl"
        res = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z", max_age_seconds=-10)
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0
        assert any(i.code == IssueCode.INVALID_INPUT.value for i in res.issues)

    def test_direct_jsonl_long_string_and_special_chars(self):
        """Direct JSONL strings with long content and special characters do not throw OSError."""
        long_body = "x" * 500
        special_str = "<test>:|?*"
        direct_jsonl = (
            f'{{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "direct-long-1", '
            f'"provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", '
            f'"request": {{"method": "GET", "route_key": "positions"}}, '
            f'"response": {{"status": 200, "body": {{"result": {{"list": [{{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5", "entryPrice": "50000", "markPrice": "51000", "padding": "{long_body}", "special": "{special_str}"}}]}}}}}}}}'
        )
        res = reconcile(direct_jsonl, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.OK.value
        assert len(res.facts) == 1

        # Also test arbitrary long string that is not a valid file path or valid JSON
        arbitrary_long = "foo_bar_not_a_path_" + ("z" * 400)
        res_bad = reconcile(arbitrary_long, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res_bad.outcome == Outcome.INVALID_INPUT.value
        assert len(res_bad.facts) == 0

    def test_source_line_numbering_with_leading_blank_lines(self):
        """Preserve source line numbering when leading blank lines precede a syntax error."""
        content = "\n\n\n{invalid json on line 4"
        res = reconcile(content, "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.INVALID_INPUT.value
        assert len(res.facts) == 0
        assert len(res.issues) >= 1
        assert "line 4" in res.issues[0].message

    def test_iterable_dict_non_finite_rejection(self):
        """Direct iterable/dict inputs carrying nested non-finite values are rejected with invalid_input."""
        non_finite_values = [
            float("nan"),
            float("inf"),
            float("-inf"),
            Decimal("NaN"),
            Decimal("Infinity"),
            Decimal("-Infinity"),
        ]
        for nf_val in non_finite_values:
            # Nested in response body
            exchange_dict = {
                "schema_version": "motim.sanitized_exchange.v1",
                "exchange_id": "nf-dict-test",
                "provider": "bybit",
                "captured_at": "2026-08-23T14:00:00Z",
                "request": {"method": "GET", "route_key": "positions"},
                "response": {
                    "status": 200,
                    "body": {
                        "result": {
                            "list": [
                                {
                                    "symbol": "BTCUSDT",
                                    "side": "Buy",
                                    "size": nf_val,
                                    "entryPrice": "50000",
                                }
                            ]
                        }
                    },
                },
            }

            # Direct list input
            res_list = reconcile([exchange_dict], "bybit", as_of="2026-08-23T14:05:00Z")
            assert res_list.outcome == Outcome.INVALID_INPUT.value
            assert len(res_list.facts) == 0
            assert any("non-finite" in i.message.lower() for i in res_list.issues)

            # Direct generator / iterable input
            res_iter = reconcile((ex for ex in [exchange_dict]), "bybit", as_of="2026-08-23T14:05:00Z")
            assert res_iter.outcome == Outcome.INVALID_INPUT.value
            assert len(res_iter.facts) == 0

    def test_reconcile_max_age_seconds_rejects_floats_and_non_finites(self):
        """max_age_seconds must be a non-negative integer; floats and non-finites return invalid_input."""
        fixture_path = FIXTURES_DIR / "bybit_all_facts.jsonl"
        bad_max_ages = [
            10.5,
            float("nan"),
            float("inf"),
            float("-inf"),
            Decimal("10"),
            "10",
            True,
            False,
            -1,
            -100,
        ]
        for bad_age in bad_max_ages:
            res = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z", max_age_seconds=bad_age)  # type: ignore[arg-type]
            assert res.outcome == Outcome.INVALID_INPUT.value
            assert len(res.facts) == 0
            assert any(i.code == IssueCode.INVALID_INPUT.value for i in res.issues)

    def test_path_handling_with_brackets_and_special_names(self, tmp_path: Path):
        """Existing file paths starting with '{' or containing brackets are read as files rather than literal JSON."""
        valid_jsonl = (
            '{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "bracket-path-1", '
            '"provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", '
            '"request": {"method": "GET", "route_key": "positions"}, '
            '"response": {"status": 200, "body": {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5", "entryPrice": "50000", "markPrice": "51000"}]}}}}\n'
        )
        bracket_file = tmp_path / "{bybit_bracket_test}.jsonl"
        bracket_file.write_text(valid_jsonl, encoding="utf-8")

        # Pass path as string
        res = reconcile(str(bracket_file), "bybit", as_of="2026-08-23T14:05:00Z")
        assert res.outcome == Outcome.OK.value
        assert len(res.facts) == 1
        assert res.facts[0].source_exchange_ids == ["bracket-path-1"]
