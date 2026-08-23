"""Adapter tests for Bybit and Lighter reconciliation (Gate 2)."""

from __future__ import annotations

from pathlib import Path
import pytest

from motim.reconcile import (
    FactType,
    IssueCode,
    Outcome,
    reconcile,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reconciliation"


class TestGate2Adapters:
    """Gate 2: Adapter tests for Bybit and Lighter across all 6 fact types and edge cases."""

    def test_bybit_all_six_fact_types(self):
        """Bybit adapter produces position, fill, funding, balance, equity, and pnl facts."""
        fixture_path = FIXTURES_DIR / "bybit_all_facts.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.OK.value
        fact_types = {f.fact_type for f in result.facts}
        expected_types = {
            FactType.POSITION.value,
            FactType.FILL.value,
            FactType.FUNDING.value,
            FactType.BALANCE.value,
            FactType.EQUITY.value,
            FactType.PNL.value,
        }
        assert expected_types.issubset(fact_types)

        # Inspect Position Fact
        pos = next(f for f in result.facts if f.fact_type == FactType.POSITION.value)
        assert pos.data["symbol"] == "BTCUSDT"
        assert pos.data["side"] == "Buy"
        assert pos.data["size"] == "0.5"
        assert pos.data["entry_price"] == "50000"
        assert pos.data["mark_price"] == "51000"

        # Inspect Fill Fact
        fill = next(f for f in result.facts if f.fact_type == FactType.FILL.value)
        assert fill.data["exec_id"] == "exec-bybit-101"
        assert fill.data["price"] == "50000"
        assert fill.data["qty"] == "0.5"
        assert fill.data["fee_currency"] == "USDT"

        # Inspect Funding Fact
        fund = next(f for f in result.facts if f.fact_type == FactType.FUNDING.value)
        assert fund.data["symbol"] == "BTCUSDT"
        assert fund.data["funding_rate"] == "0.0001"
        assert fund.data["funding_fee"] == "-2.5"

        # Inspect Balance Fact
        bal = next(f for f in result.facts if f.fact_type == FactType.BALANCE.value)
        assert bal.data["coin"] == "USDT"
        assert bal.data["wallet_balance"] == "10000"
        assert bal.data["available_balance"] == "7500"

        # Inspect Equity Fact
        eq = next(f for f in result.facts if f.fact_type == FactType.EQUITY.value)
        assert eq.data["coin"] == "USDT"
        assert eq.data["equity"] == "10500"

        # Inspect PnL Fact
        pnl = next(f for f in result.facts if f.fact_type == FactType.PNL.value)
        assert pnl.data["symbol"] == "BTCUSDT"
        assert pnl.data["closed_pnl"] == "250"
        assert pnl.data["closed_size"] == "0.5"

    def test_lighter_all_six_fact_types(self):
        """Lighter adapter produces position, fill, funding, balance, equity, and pnl facts."""
        fixture_path = FIXTURES_DIR / "lighter_all_facts.jsonl"
        result = reconcile(fixture_path, "lighter", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.OK.value
        fact_types = {f.fact_type for f in result.facts}


        expected_types = {
            FactType.POSITION.value,
            FactType.FILL.value,
            FactType.FUNDING.value,
            FactType.BALANCE.value,
            FactType.EQUITY.value,
            FactType.PNL.value,
        }
        assert expected_types.issubset(fact_types)

        # Inspect Position Fact
        pos = next(f for f in result.facts if f.fact_type == FactType.POSITION.value)
        assert pos.data["symbol"] == "BTC-PERP"
        assert pos.data["side"] == "LONG"
        assert pos.data["size"] == "0.5"

        # Inspect Fill Fact
        fill = next(f for f in result.facts if f.fact_type == FactType.FILL.value)
        assert fill.data["exec_id"] == "tx-lighter-101"
        assert fill.data["fee_currency"] == "USDC"

        # Inspect Funding Fact
        fund = next(f for f in result.facts if f.fact_type == FactType.FUNDING.value)
        assert fund.data["funding_rate"] == "0.00015"
        assert fund.data["funding_fee"] == "-1.25"

        # Inspect Balance Fact
        bal = next(f for f in result.facts if f.fact_type == FactType.BALANCE.value)
        assert bal.data["coin"] == "USDC"
        assert bal.data["wallet_balance"] == "5000"

        # Inspect Equity Fact
        eq = next(f for f in result.facts if f.fact_type == FactType.EQUITY.value)
        assert eq.data["coin"] == "USDC"
        assert eq.data["equity"] == "5250"

        # Inspect PnL Fact
        pnl = next(f for f in result.facts if f.fact_type == FactType.PNL.value)
        assert pnl.data["symbol"] == "BTC-PERP"
        assert pnl.data["closed_pnl"] == "150"

    def test_malformed_record_handling(self):
        """Malformed record in recognized route emits issue and results in partial outcome."""
        fixture_path = FIXTURES_DIR / "bybit_malformed.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.PARTIAL.value
        assert len(result.facts) == 1
        assert result.facts[0].data["symbol"] == "ETHUSDT"

        malformed_issues = [i for i in result.issues if i.code == IssueCode.MALFORMED_RECORD.value]
        assert len(malformed_issues) == 1
        assert malformed_issues[0].source_exchange_id == "bybit-malformed-001"

    def test_unknown_route_schema(self):
        """Unsupported route schema produces outcome unsupported_schema."""
        fixture_path = FIXTURES_DIR / "unknown_route.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.UNSUPPORTED_SCHEMA.value
        assert len(result.facts) == 0
        unsupported_issues = [i for i in result.issues if i.code == IssueCode.UNSUPPORTED_SCHEMA.value]
        assert len(unsupported_issues) == 1

    def test_mixed_recognized_and_unsupported_exchanges(self):
        """Mixed input produces recognized facts with partial outcome naming unsupported route."""
        fixture_path = FIXTURES_DIR / "bybit_mixed.jsonl"
        result = reconcile(fixture_path, "bybit", as_of="2026-08-23T14:05:00Z")

        assert result.outcome == Outcome.PARTIAL.value
        assert len(result.facts) == 1
        assert result.facts[0].data["symbol"] == "BTCUSDT"

        unsupported_issues = [i for i in result.issues if i.code == IssueCode.UNSUPPORTED_SCHEMA.value]
        assert len(unsupported_issues) == 1
        assert unsupported_issues[0].source_exchange_id == "bybit-unknown-002"
