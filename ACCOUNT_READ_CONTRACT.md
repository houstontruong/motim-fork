# Motim Account-Read Reconciliation Contract (v1)

**Schema Version:** `motim.account_read.v1` / `motim.sanitized_exchange.v1`  
**Scope:** Pure offline-only, deterministic parser and reconciler. Zero network access, zero credential replay, zero auth reconstruction.

---

## 1. Overview & Safety Guarantees

The Motim Account-Read Reconciliation layer translates local, pre-sanitized exchange exports (`motim.sanitized_exchange.v1`) into structured, traceable account facts (`motim.account_read.v1`).

### Non-Negotiable Safety Constraints:
- **Offline Only:** Production modules contain no network imports (`socket`, `requests`, `httpx`, `urllib`, `aiohttp`, `websocket`, `mitmproxy`).
- **No Auth / Secrets:** Input files are scanned recursively for auth-shaped fields (`authorization`, `cookie`, `token`, `secret`, `password`, `passphrase`, `signature`, `session_id`, `credentials`, `nonce`, JWTs, Bearer tokens). Any matching field or key anywhere in the input tree causes immediate rejection (`invalid_input`, exit code 4) with redacted error messages that never echo secret values.
- **Read-Only HTTP Methods:** Only normalized `GET` is accepted for `request.method`; mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) are rejected with `invalid_input` (exit 4).
- **Deterministic & Pure:** All calculations (decimal conversions, hashing, staleness) are deterministic and depend solely on explicit arguments. No system clock or environment access.
- **Traceability:** Every produced fact maintains an explicit list of `source_exchange_ids` linking it back to the input fixture records.

---

## 2. Input Specification: `motim.sanitized_exchange.v1`

Input is formatted as **JSON Lines (`.jsonl`)** where each line represents one validated, sanitized exchange object.

### Schema:
```json
{
  "schema_version": "motim.sanitized_exchange.v1",
  "exchange_id": "fixture-bybit-001",
  "provider": "bybit",
  "captured_at": "2026-08-23T14:00:00Z",
  "request": {
    "method": "GET",
    "route_key": "positions"
  },
  "response": {
    "status": 200,
    "content_type": "application/json",
    "body": {}
  }
}
```

### Field Definitions & Rules:
- `schema_version` *(string, required)*: Exactly `"motim.sanitized_exchange.v1"`.
- `exchange_id` *(string, required)*: Unique identifier within the input file.
- `provider` *(string, required)*: Exactly `"bybit"` or `"lighter"`.
- `captured_at` *(string, required)*: RFC3339 UTC timestamp ending with `"Z"` (e.g. `2026-08-23T14:00:00Z`).
- `request.method` *(string, required)*: Normalized HTTP method string. Only `"GET"` is accepted for account-read reconciliation; mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) are rejected with `invalid_input`.
- `request.route_key` *(string, required)*: Synthetic adapter route key (e.g. `"positions"`, `"fills"`, `"wallet_balance"`, `"funding_history"`, `"closed_pnl"`). Any credential-bearing URL, userinfo, or query material in `route_key` is strictly rejected at ingest (`auth_field_detected` / `invalid_input`) with zero facts and redacted errors.
- `response.status` *(integer, required)*: HTTP response status code (e.g. `200`).
- `response.body` *(JSON object/array, required)*: Pre-sanitized response body payload.

---

## 3. Output Specification: `motim.account_read.v1`

`motim reconcile` produces a single JSON object on `stdout`:

```json
{
  "schema_version": "motim.account_read.v1",
  "provider": "bybit",
  "as_of": "2026-08-23T14:05:00Z",
  "outcome": "ok",
  "facts": [],
  "issues": []
}
```

### Fact Model:
Each fact inside `facts` represents an atomic account fact:
```json
{
  "fact_id": "bybit:position:BTCUSDT:Buy",
  "fact_type": "position",
  "provider": "bybit",
  "account_scope": "default",
  "observed_at": "2026-08-23T14:00:00Z",
  "source_exchange_ids": ["bybit-pos-001"],
  "data": {
    "symbol": "BTCUSDT",
    "side": "Buy",
    "size": "0.5",
    "entry_price": "50000",
    "mark_price": "51000",
    "unrealized_pnl": "500",
    "leverage": "10",
    "position_value": "25000"
  }
}
```

#### Fact Types (`fact_type`):
- `position`: Current open derivative or spot positions (`symbol`, `side`, `size`, `entry_price`, `mark_price`, `unrealized_pnl`, `leverage`, `position_value`).
- `fill`: Executed trade fills (`exec_id`, `order_id`, `symbol`, `side`, `price`, `qty`, `fee`, `fee_currency`, `exec_time`).
- `funding`: Funding payments and rates (`symbol`, `funding_rate`, `funding_fee`, `funding_time`).
- `balance`: Wallet account balance (`coin`, `wallet_balance`, `available_balance`).
- `equity`: Total equity (`coin`, `equity`).
- `pnl`: Realized / closed PnL (`symbol`, `order_id`, `closed_pnl`, `closed_size`, `avg_entry_price`, `avg_exit_price`, `updated_time`).

#### Data Canonicalization Rules:
1. **Numbers:** All quantities, prices, fees, and PnL values are converted to canonical base-10 decimal strings (e.g. `"100.5"`, `"0"`, `"0.00000001"`). Floats and scientific notation are forbidden.
2. **Symbols/Assets:** Standardized to uppercase strings (e.g. `"BTCUSDT"`, `"USDC"`, `"BTC-PERP"`).

---

## 4. Deduplication & Conflict Resolution

- **Deduplication Key:** `provider:account_scope:fact_type:native_id`. Where a schema has no native ID, the SHA-256 hash of deterministic canonical JSON bytes of semantic fields is used.
- **Exact Duplicates:** Records with identical deduplication key and identical data payload collapse into a single fact preserving all `source_exchange_ids` and emit an informational `duplicate_event` issue.
- **Conflicting Duplicates:** Records with identical deduplication key but conflicting data values are omitted completely and generate a warning `conflicting_duplicate` issue.

---

## 5. Deterministic Staleness

- Given an explicit `--as-of <RFC3339Z>` parameter:
- A fact is stale when `(as_of - observed_at) > max_age_seconds`.
- Stale facts are retained in `facts` and tagged with a `stale_fact` issue.
- Default `max_age_seconds` is `0` (only equal-time records are fresh).

---

## 6. Outcome Taxonomy & Exit Codes

| Outcome | Exit Code | Description |
| :--- | :---: | :--- |
| `ok` | **0** | All selected exchanges valid and recognized; facts emitted. (May include harmless exact duplicates or staleness issues). |
| `partial` | **2** | Known-schema records contained malformed data, conflicts, or unknown routes alongside recognized facts. |
| `unsupported_schema` | **3** | No selected exchange produced recognized facts due to unsupported route or body structure. |
| `invalid_input` | **4** | Input violates sanitized exchange schema, contains auth/secret elements, or failed JSON parsing. No facts emitted. |

---

## 7. CLI & Python API Usage

### CLI Commands:
```bash
# Reconcile exchange exports
motim reconcile --input fixtures/bybit_all_facts.jsonl --provider bybit --as-of 2026-08-23T14:05:00Z

# Filter facts from reconciliation output
motim facts --result result.json --type position

# Filter issues from reconciliation output
motim issues --result result.json --code duplicate_event
```

### Python API:
```python
from motim.reconcile import reconcile

result = reconcile(
    "fixtures/bybit_all_facts.jsonl",
    provider="bybit",
    as_of="2026-08-23T14:05:00Z",
    max_age_seconds=300,
    strict=True,
)

print(result.outcome)  # 'ok'
for fact in result.facts:
    print(fact.fact_type, fact.data)
```

---

## 8. Redacted Fixture & Output Example

### Sanitized Input (`bybit_fixture.jsonl`):
```json
{"schema_version": "motim.sanitized_exchange.v1", "exchange_id": "bybit-pos-001", "provider": "bybit", "captured_at": "2026-08-23T14:00:00Z", "request": {"method": "GET", "route_key": "positions"}, "response": {"status": 200, "content_type": "application/json", "body": {"result": {"list": [{"symbol": "BTCUSDT", "side": "Buy", "size": "0.5000", "entryPrice": "50000.00", "markPrice": "51000.00", "unrealisedPnl": "500.00", "leverage": "10", "positionValue": "25000.00"}]}}}}
```

### Result Object (`motim reconcile ...`):
```json
{
  "schema_version": "motim.account_read.v1",
  "provider": "bybit",
  "as_of": "2026-08-23T14:05:00Z",
  "outcome": "ok",
  "facts": [
    {
      "fact_id": "bybit:position:BTCUSDT:Buy",
      "fact_type": "position",
      "provider": "bybit",
      "account_scope": "default",
      "observed_at": "2026-08-23T14:00:00Z",
      "source_exchange_ids": [
        "bybit-pos-001"
      ],
      "data": {
        "symbol": "BTCUSDT",
        "side": "Buy",
        "size": "0.5",
        "entry_price": "50000",
        "mark_price": "51000",
        "unrealized_pnl": "500",
        "leverage": "10",
        "position_value": "25000"
      }
    }
  ],
  "issues": []
}
```
