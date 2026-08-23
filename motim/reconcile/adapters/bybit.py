"""Bybit synthetic fixture reconciliation adapter."""

from __future__ import annotations

from typing import Any

from motim.reconcile.decimal_util import normalize_asset, to_canonical_decimal_str
from motim.reconcile.models import Fact, FactType, Issue, IssueCode, Severity
from .base import AdapterResult, BaseAdapter

SUPPORTED_ROUTES = frozenset(
    {"positions", "position_list", "execution_list", "fills", "funding_history", "funding", "wallet_balance", "balance", "closed_pnl", "pnl"}
)


class BybitAdapter(BaseAdapter):
    provider = "bybit"

    def supports_route(self, route_key: str) -> bool:
        return route_key in SUPPORTED_ROUTES

    def reconcile_exchange(self, exchange: dict[str, Any]) -> AdapterResult:
        route_key = exchange["request"]["route_key"]
        ex_id = exchange["exchange_id"]
        observed_at = exchange["captured_at"]
        body = exchange["response"]["body"]
        account_scope = exchange.get("account_scope") or "default"

        if not self.supports_route(route_key):
            return AdapterResult(
                facts=[],
                issues=[
                    Issue(
                        code=IssueCode.UNSUPPORTED_SCHEMA.value,
                        provider=self.provider,
                        source_exchange_id=ex_id,
                        severity=Severity.WARNING.value,
                        message=f"Bybit route '{route_key}' is not supported",
                    )
                ],
                is_supported=False,
            )

        # Extract items list from Bybit response body structure
        items: list[dict[str, Any]] = []
        if isinstance(body, list):
            items = [item for item in body if isinstance(item, dict)]
        elif isinstance(body, dict):
            # Check Bybit v5 result.list or result.rows or direct list
            res = body.get("result")
            if isinstance(res, dict):
                sub_list = res.get("list") or res.get("rows")
                if isinstance(sub_list, list):
                    items = [item for item in sub_list if isinstance(item, dict)]
                elif any(k in res for k in ("coin", "walletBalance", "symbol", "execId")):
                    items = [res]
            elif isinstance(res, list):
                items = [item for item in res if isinstance(item, dict)]
            elif "list" in body and isinstance(body["list"], list):
                items = [item for item in body["list"] if isinstance(item, dict)]
            elif any(k in body for k in ("coin", "walletBalance", "symbol", "execId")):
                items = [body]

        if not items and isinstance(body, dict) and not any(k in body for k in ("result", "list")):
            # Unknown body schema
            return AdapterResult(
                facts=[],
                issues=[
                    Issue(
                        code=IssueCode.UNSUPPORTED_SCHEMA.value,
                        provider=self.provider,
                        source_exchange_id=ex_id,
                        severity=Severity.WARNING.value,
                        message=f"Unsupported Bybit response body structure for route '{route_key}'",
                    )
                ],
                is_supported=False,
            )

        facts: list[tuple[Fact, str | None]] = []
        issues: list[Issue] = []

        if route_key in ("positions", "position_list"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("symbol"))
                    side = str(item.get("side", "None")).strip()
                    if not symbol:
                        raise ValueError("Missing symbol")
                    size = to_canonical_decimal_str(item.get("size", "0"))
                    entry_price = to_canonical_decimal_str(item.get("entryPrice", item.get("avgPrice", "0")))
                    mark_price = to_canonical_decimal_str(item.get("markPrice", "0"))
                    unrealized_pnl = to_canonical_decimal_str(item.get("unrealisedPnl", item.get("unrealizedPnl", "0")))
                    leverage = to_canonical_decimal_str(item.get("leverage", "1"))
                    pos_val = to_canonical_decimal_str(item.get("positionValue", "0"))

                    native_id = f"{symbol}:{side}"
                    fact = Fact(
                        fact_id=f"bybit:position:{symbol}:{side}",
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
                            message=f"Malformed Bybit position record: {e}",
                        )
                    )

        elif route_key in ("execution_list", "fills"):
            for item in items:
                try:
                    exec_id = str(item.get("execId") or item.get("tradeId") or "").strip()
                    symbol = normalize_asset(item.get("symbol"))
                    if not exec_id or not symbol:
                        raise ValueError("Missing execId or symbol")
                    order_id = str(item.get("orderId", "")).strip()
                    side = str(item.get("side", "")).strip()
                    price = to_canonical_decimal_str(item.get("execPrice", item.get("price", "0")))
                    qty = to_canonical_decimal_str(item.get("execQty", item.get("qty", "0")))
                    fee = to_canonical_decimal_str(item.get("execFee", item.get("fee", "0")))
                    fee_currency = normalize_asset(item.get("feeCurrency", item.get("feeCoin", "USDT")))
                    exec_time = str(item.get("execTime", "")).strip()

                    fact = Fact(
                        fact_id=f"bybit:fill:{exec_id}",
                        fact_type=FactType.FILL.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "exec_id": exec_id,
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
                    facts.append((fact, exec_id))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Bybit fill record: {e}",
                        )
                    )

        elif route_key in ("funding_history", "funding"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("symbol"))
                    funding_time = str(item.get("fundingTime") or item.get("funding_time") or "").strip()
                    if not symbol:
                        raise ValueError("Missing symbol")
                    funding_rate = to_canonical_decimal_str(item.get("fundingRate", item.get("funding_rate", "0")))
                    funding_fee = to_canonical_decimal_str(item.get("fundingFee", item.get("funding_fee", "0")))

                    native_id = f"{symbol}:{funding_time}" if funding_time else None
                    fact = Fact(
                        fact_id=f"bybit:funding:{symbol}:{funding_time or '0'}",
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
                            message=f"Malformed Bybit funding record: {e}",
                        )
                    )

        elif route_key in ("wallet_balance", "balance"):
            for item in items:
                try:
                    coin = normalize_asset(item.get("coin") or item.get("currency"))
                    if not coin:
                        raise ValueError("Missing coin/currency")
                    wallet_bal = to_canonical_decimal_str(item.get("walletBalance", item.get("balance", "0")))
                    avail_bal = to_canonical_decimal_str(item.get("availableToWithdraw", item.get("availableBalance", wallet_bal)))
                    equity_val = to_canonical_decimal_str(item.get("equity", item.get("totalEquity", wallet_bal)))

                    # Emit balance fact
                    bal_fact = Fact(
                        fact_id=f"bybit:balance:{coin}",
                        fact_type=FactType.BALANCE.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "coin": coin,
                            "wallet_balance": wallet_bal,
                            "available_balance": avail_bal,
                        },
                    )
                    facts.append((bal_fact, coin))

                    # Emit equity fact
                    eq_fact = Fact(
                        fact_id=f"bybit:equity:{coin}",
                        fact_type=FactType.EQUITY.value,
                        provider=self.provider,
                        account_scope=account_scope,
                        observed_at=observed_at,
                        source_exchange_ids=[ex_id],
                        data={
                            "coin": coin,
                            "equity": equity_val,
                        },
                    )
                    facts.append((eq_fact, coin))
                except Exception as e:
                    issues.append(
                        Issue(
                            code=IssueCode.MALFORMED_RECORD.value,
                            provider=self.provider,
                            source_exchange_id=ex_id,
                            severity=Severity.WARNING.value,
                            message=f"Malformed Bybit balance record: {e}",
                        )
                    )

        elif route_key in ("closed_pnl", "pnl"):
            for item in items:
                try:
                    symbol = normalize_asset(item.get("symbol"))
                    order_id = str(item.get("orderId", "")).strip()
                    if not symbol:
                        raise ValueError("Missing symbol")
                    closed_pnl = to_canonical_decimal_str(item.get("closedPnl", item.get("pnl", "0")))
                    avg_entry_price = to_canonical_decimal_str(item.get("avgEntryPrice", "0"))
                    avg_exit_price = to_canonical_decimal_str(item.get("avgExitPrice", "0"))
                    closed_size = to_canonical_decimal_str(item.get("closedSize", item.get("qty", "0")))
                    closed_time = str(item.get("updatedTime", item.get("execTime", ""))).strip()

                    native_id = f"{symbol}:{order_id}" if order_id else None
                    fact = Fact(
                        fact_id=f"bybit:pnl:{symbol}:{order_id or '0'}",
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
                            message=f"Malformed Bybit PnL record: {e}",
                        )
                    )

        return AdapterResult(facts=facts, issues=issues, is_supported=True)
