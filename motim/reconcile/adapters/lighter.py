"""Lighter synthetic fixture reconciliation adapter."""

from __future__ import annotations

from typing import Any

from motim.reconcile.decimal_util import normalize_asset, to_canonical_decimal_str
from motim.reconcile.models import Fact, FactType, Issue, IssueCode, Severity
from .base import AdapterResult, BaseAdapter

SUPPORTED_ROUTES = frozenset(
    {"positions", "account_positions", "trades", "fills", "account_trades", "funding_payments", "funding", "account", "balances", "pnl", "account_pnl"}
)


class LighterAdapter(BaseAdapter):
    provider = "lighter"

    def supports_route(self, route_key: str) -> bool:
        return route_key in SUPPORTED_ROUTES

    def reconcile_exchange(self, exchange: dict[str, Any]) -> AdapterResult:
        route_key = exchange["request"]["route_key"]
        ex_id = exchange["exchange_id"]
        observed_at = exchange["captured_at"]
        body = exchange["response"]["body"]
        account_scope = exchange.get("account_scope") or "default"

        if not self.supports_route(route_key):
            clean_route = route_key.split("?")[0].split("@")[-1]
            return AdapterResult(
                facts=[],
                issues=[
                    Issue(
                        code=IssueCode.UNSUPPORTED_SCHEMA.value,
                        provider=self.provider,
                        source_exchange_id=ex_id,
                        severity=Severity.WARNING.value,
                        message=f"Lighter route '{clean_route}' is not supported",
                    )
                ],
                is_supported=False,
            )

        # Extract items from Lighter response body
        items: list[dict[str, Any]] = []
        if isinstance(body, list):
            items = [item for item in body if isinstance(item, dict)]
        elif isinstance(body, dict):
            # Check Lighter structure: {"code": 200, "data": {...}} or direct dict
            data = body.get("data")
            if isinstance(data, list):
                items = [item for item in data if isinstance(item, dict)]
            elif isinstance(data, dict):
                # Could be {"positions": [...]}, {"trades": [...]}, {"balances": [...]}
                sub_list = (
                    data.get("positions")
                    or data.get("trades")
                    or data.get("funding_payments")
                    or data.get("balances")
                    or data.get("items")
                )
                if isinstance(sub_list, list):
                    items = [item for item in sub_list if isinstance(item, dict)]
                elif any(k in data for k in ("market_id", "symbol", "trade_id", "asset", "total_balance")):
                    items = [data]
            elif "positions" in body and isinstance(body["positions"], list):
                items = [item for item in body["positions"] if isinstance(item, dict)]
            elif "trades" in body and isinstance(body["trades"], list):
                items = [item for item in body["trades"] if isinstance(item, dict)]
            elif "balances" in body and isinstance(body["balances"], list):
                items = [item for item in body["balances"] if isinstance(item, dict)]
            elif any(k in body for k in ("market_id", "symbol", "trade_id", "asset", "total_balance")):
                items = [body]

        if not items and isinstance(body, dict) and not any(k in body for k in ("data", "positions", "trades", "balances")):
            return AdapterResult(
                facts=[],
                issues=[
                    Issue(
                        code=IssueCode.UNSUPPORTED_SCHEMA.value,
                        provider=self.provider,
                        source_exchange_id=ex_id,
                        severity=Severity.WARNING.value,
                        message=f"Unsupported Lighter response body structure for route '{route_key}'",
                    )
                ],
                is_supported=False,
            )

        facts: list[tuple[Fact, str | None]] = []
        issues: list[Issue] = []

        if route_key in ("positions", "account_positions"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("market_id") or item.get("symbol"))
                    if not symbol:
                        raise ValueError("Missing market_id or symbol")
                    side = str(item.get("side", item.get("sign", "LONG"))).strip()
                    size = to_canonical_decimal_str(item.get("size", item.get("position_size", "0")))
                    entry_price = to_canonical_decimal_str(item.get("entry_price", item.get("avg_price", "0")))
                    mark_price = to_canonical_decimal_str(item.get("mark_price", "0"))
                    unrealized_pnl = to_canonical_decimal_str(item.get("unrealized_pnl", "0"))
                    leverage = to_canonical_decimal_str(item.get("leverage", "1"))
                    pos_val = to_canonical_decimal_str(item.get("position_value", "0"))

                    native_id = f"{symbol}:{side}"
                    fact = Fact(
                        fact_id=f"lighter:position:{symbol}:{side}",
                        fact_type=FactType.POSITION.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "symbol": symbol,
                            "side": side,
                            "size": size,
                            "entry_price": entry_price,
                            "mark_price": mark_price,
                            "unrealized_pnl": unrealized_pnl,
                            "leverage": leverage,
                            "position_value": pos_val,
                        },
                    )
                    facts.append((fact, native_id))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Lighter position record: {e}",
                        )
                    )

        elif route_key in ("trades", "fills", "account_trades"):
            for item in items:
                try:
                    trade_id = str(item.get("trade_id") or item.get("id") or item.get("exec_id") or "").strip()
                    symbol = normalize_asset(item.get("market_id") or item.get("symbol"))
                    if not trade_id or not symbol:
                        raise ValueError("Missing trade_id or market_id")
                    order_id = str(item.get("order_id", "")).strip()
                    side = str(item.get("side", "")).strip()
                    price = to_canonical_decimal_str(item.get("price", "0"))
                    qty = to_canonical_decimal_str(item.get("size", item.get("qty", "0")))
                    fee = to_canonical_decimal_str(item.get("fee", "0"))
                    fee_currency = normalize_asset(item.get("fee_asset", item.get("fee_currency", "USDC")))
                    exec_time = str(item.get("timestamp", item.get("trade_time", ""))).strip()

                    fact = Fact(
                        fact_id=f"lighter:fill:{trade_id}",
                        fact_type=FactType.FILL.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "exec_id": trade_id,
                            "order_id": order_id,
                            "symbol": symbol,
                            "side": side,
                            "price": price,
                            "qty": qty,
                            "fee": fee,
                            "fee_currency": fee_currency,
                            "exec_time": exec_time,
                        },
                    )
                    facts.append((fact, trade_id))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Lighter fill record: {e}",
                        )
                    )

        elif route_key in ("funding_payments", "funding"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("market_id") or item.get("symbol"))
                    funding_time = str(item.get("timestamp") or item.get("funding_time") or "").strip()
                    if not symbol:
                        raise ValueError("Missing market_id or symbol")
                    funding_rate = to_canonical_decimal_str(item.get("funding_rate", "0"))
                    funding_fee = to_canonical_decimal_str(item.get("payment", item.get("funding_fee", "0")))

                    native_id = f"{symbol}:{funding_time}" if funding_time else None
                    fact = Fact(
                        fact_id=f"lighter:funding:{symbol}:{funding_time or '0'}",
                        fact_type=FactType.FUNDING.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "symbol": symbol,
                            "funding_rate": funding_rate,
                            "funding_fee": funding_fee,
                            "funding_time": funding_time,
                        },
                    )
                    facts.append((fact, native_id))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Lighter funding record: {e}",
                        )
                    )

        elif route_key in ("account", "balances"):
            for item in items:
                try:
                    asset = normalize_asset(item.get("asset") or item.get("coin") or item.get("currency"))
                    if not asset:
                        raise ValueError("Missing asset")
                    total_bal = to_canonical_decimal_str(item.get("total_balance", item.get("balance", "0")))
                    avail_bal = to_canonical_decimal_str(item.get("available_balance", total_bal))
                    equity_val = to_canonical_decimal_str(item.get("equity", total_bal))

                    # Emit balance fact
                    bal_fact = Fact(
                        fact_id=f"lighter:balance:{asset}",
                        fact_type=FactType.BALANCE.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "coin": asset,
                            "wallet_balance": total_bal,
                            "available_balance": avail_bal,
                        },
                    )
                    facts.append((bal_fact, asset))

                    # Emit equity fact
                    eq_fact = Fact(
                        fact_id=f"lighter:equity:{asset}",
                        fact_type=FactType.EQUITY.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "coin": asset,
                            "equity": equity_val,
                        },
                    )
                    facts.append((eq_fact, asset))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Lighter balance record: {e}",
                        )
                    )

        elif route_key in ("pnl", "account_pnl"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("market_id") or item.get("symbol"))
                    order_id = str(item.get("trade_id") or item.get("order_id") or "").strip()
                    if not symbol:
                        raise ValueError("Missing market_id or symbol")
                    closed_pnl = to_canonical_decimal_str(item.get("realized_pnl", item.get("pnl", "0")))
                    avg_entry_price = to_canonical_decimal_str(item.get("avg_entry_price", "0"))
                    avg_exit_price = to_canonical_decimal_str(item.get("avg_exit_price", "0"))
                    closed_size = to_canonical_decimal_str(item.get("closed_volume", item.get("size", "0")))
                    closed_time = str(item.get("timestamp", "")).strip()

                    native_id = f"{symbol}:{order_id}" if order_id else None
                    fact = Fact(
                        fact_id=f"lighter:pnl:{symbol}:{order_id or '0'}",
                        fact_type=FactType.PNL.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "symbol": symbol,
                            "order_id": order_id,
                            "closed_pnl": closed_pnl,
                            "avg_entry_price": avg_entry_price,
                            "avg_exit_price": avg_exit_price,
                            "closed_size": closed_size,
                            "closed_time": closed_time,
                        },
                    )
                    facts.append((fact, native_id))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Lighter PnL record: {e}",
                        )
                    )

        return AdapterResult(facts=facts, issues=issues, is_supported=True)
