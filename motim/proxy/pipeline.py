"""Buffered capture pipeline for MOTIM proxy.

Mitmproxy hooks run on a hot path. Heavy work (body parsing, GraphQL extraction,
spec update, DB enqueue) can make browsing feel slow.

This pipeline lets the addon do minimal work:
- normalize flow into plain Python primitives
- enqueue to a worker thread
- worker performs parsing + Store.update + (optional) ExchangeDB enqueue
"""

from __future__ import annotations

import json
import queue
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping

from motim.exchange_db import HeaderField
from motim.exchange_writer import BufferedExchangeWriter
from motim.normalize import templatize_path
from motim.store import Store


@dataclass(frozen=True)
class CaptureEvent:
    kind: str  # "http" | "ws"
    payload: dict[str, Any]


def _decode_header_fields(raw_fields: list[tuple[bytes, bytes]] | None) -> list[HeaderField]:
    fields: list[HeaderField] = []
    if not raw_fields:
        return fields
    for name_b, value_b in raw_fields:
        try:
            name = name_b.decode("latin-1")
        except Exception:
            name = str(name_b)
        try:
            value = value_b.decode("latin-1")
        except Exception:
            value = str(value_b)
        fields.append(HeaderField(name=name, value=value))
    return fields


def _parse_body(content: bytes, content_type: str, *, max_parse_bytes: int) -> Any:
    from urllib.parse import parse_qs

    if max_parse_bytes > 0 and len(content) > max_parse_bytes:
        return f"<body: {len(content)} bytes (skipped parse)>"

    try:
        if "json" in content_type:
            return json.loads(content)

        if "x-www-form-urlencoded" in content_type:
            form_data = parse_qs(content.decode("utf-8", errors="replace"))
            return {k: v[0] if len(v) == 1 else v for k, v in form_data.items()}

        if "multipart/form-data" in content_type:
            return "<multipart: omitted>"

        if any(t in content_type for t in ["text/", "xml", "javascript", "html"]):
            return content.decode("utf-8", errors="replace")

        # Try to decode as text
        try:
            text = content.decode("utf-8")
            if text.strip().startswith(("{", "[")):
                return json.loads(text)
            if "=" in text and "&" in text:
                form_data = parse_qs(text)
                return {k: v[0] if len(v) == 1 else v for k, v in form_data.items()}
            return text
        except Exception:
            pass

        return f"<binary: {len(content)} bytes>"

    except Exception as e:
        return f"<parse error: {str(e)[:50]}>"


def _graphql_operation(request_body: Any) -> str | None:
    if not isinstance(request_body, dict):
        return None
    if "operationName" in request_body and isinstance(request_body.get("operationName"), str):
        return request_body.get("operationName")
    if "query" in request_body:
        q = str(request_body.get("query") or "")
        match = re.search(r"(?:query|mutation|subscription)\s+(\w+)", q)
        if match:
            return match.group(1)
    return None


class CapturePipeline:
    def __init__(
        self,
        *,
        store: Store,
        exchange_writer: BufferedExchangeWriter | None,
        write_specs: bool = True,
        max_parse_bytes: int = 200_000,
        queue_max: int = 5_000,
        drop_when_full: bool = True,
        profile_enabled: bool = False,
        profile_every_n: int = 200,
    ):
        self.store = store
        self.exchange_writer = exchange_writer
        self.write_specs = write_specs
        self.max_parse_bytes = max_parse_bytes
        self.drop_when_full = drop_when_full
        self.profile_enabled = profile_enabled
        self.profile_every_n = max(1, int(profile_every_n))

        self._q: queue.Queue[CaptureEvent] = queue.Queue(maxsize=queue_max)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._started = False

        self.enqueued = 0
        self.dropped = 0
        self.processed = 0

        # Profiling counters (worker thread only)
        self._t_parse_ms = 0.0
        self._t_store_ms = 0.0
        self._t_db_enqueue_ms = 0.0
        self._t_total_ms = 0.0

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._thread.start()

    def close(self) -> None:
        if not self._started:
            return
        self._stop.set()
        try:
            self._thread.join(timeout=5)
        except Exception:
            pass
        self._started = False

    def enqueue(self, kind: str, payload: Mapping[str, Any]) -> bool:
        if not self._started:
            self.start()
        evt = CaptureEvent(kind=kind, payload=dict(payload))
        try:
            if self.drop_when_full:
                self._q.put_nowait(evt)
            else:
                self._q.put(evt)
            self.enqueued += 1
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def stats(self) -> dict[str, int]:
        """Lightweight stats snapshot for profiling/logging."""
        return {
            "qsize": self._q.qsize(),
            "enqueued": int(self.enqueued),
            "dropped": int(self.dropped),
            "processed": int(self.processed),
        }

    def _run(self) -> None:
        while True:
            try:
                evt = self._q.get(timeout=0.2)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue

            t0 = time.perf_counter()
            try:
                if evt.kind == "http":
                    self._process_http(evt.payload)
                elif evt.kind == "ws":
                    self._process_ws(evt.payload)
            except Exception:
                # Never crash the proxy for pipeline issues.
                pass
            finally:
                self._t_total_ms += (time.perf_counter() - t0) * 1000.0
                self.processed += 1

            if self.profile_enabled and (self.processed % self.profile_every_n == 0):
                qsize = self._q.qsize()
                avg_parse = self._t_parse_ms / max(1, self.profile_every_n)
                avg_store = self._t_store_ms / max(1, self.profile_every_n)
                avg_db = self._t_db_enqueue_ms / max(1, self.profile_every_n)
                avg_total = self._t_total_ms / max(1, self.profile_every_n)
                print(
                    "[motim profile] "
                    f"processed={self.processed} q={qsize} "
                    f"enq={self.enqueued} drop={self.dropped} "
                    f"avg_ms(total={avg_total:.2f} parse={avg_parse:.2f} "
                    f"store={avg_store:.2f} dbq={avg_db:.2f})"
                )
                # reset window
                self._t_parse_ms = 0.0
                self._t_store_ms = 0.0
                self._t_db_enqueue_ms = 0.0
                self._t_total_ms = 0.0

            if self._stop.is_set() and self._q.empty():
                break

    def _process_http(self, p: dict[str, Any]) -> None:
        host = str(p["host"])
        scheme = p.get("scheme")
        method = str(p["method"])
        status = int(p.get("status") or 0)
        path_only = str(p["path_only"])

        req_content_type = str(p.get("req_content_type") or "")
        resp_content_type = str(p.get("resp_content_type") or "")

        req_body_raw: bytes | None = p.get("req_body")
        resp_body_raw: bytes | None = p.get("resp_body")

        request_body = None
        response_body = None
        if req_body_raw:
            t = time.perf_counter()
            request_body = _parse_body(
                req_body_raw, req_content_type, max_parse_bytes=self.max_parse_bytes
            )
            self._t_parse_ms += (time.perf_counter() - t) * 1000.0
        if resp_body_raw:
            t = time.perf_counter()
            response_body = _parse_body(
                resp_body_raw, resp_content_type, max_parse_bytes=self.max_parse_bytes
            )
            self._t_parse_ms += (time.perf_counter() - t) * 1000.0

        graphql_op = _graphql_operation(request_body)
        templ_path = templatize_path(path_only)

        # Update YAML spec store (buffered to disk) if enabled.
        if self.write_specs:
            t_store = time.perf_counter()
            self.store.update(
                host=host,
                scheme=scheme,
                method=method,
                path=templ_path,
                query_params=p.get("query_params"),
                request_headers=p.get("request_headers") or {},
                response_headers=p.get("response_headers"),
                request_body=request_body,
                response_body=response_body,
                status_code=status,
                graphql_operation=graphql_op,
            )
            self._t_store_ms += (time.perf_counter() - t_store) * 1000.0

        # Enqueue to exchange DB writer (already buffered to SQLite).
        if self.exchange_writer is not None:
            endpoint = f"{method} {templ_path}"
            if graphql_op is not None:
                endpoint = f"{endpoint} ({graphql_op})"
            t_dbq = time.perf_counter()
            self.exchange_writer.enqueue(
                {
                    "scheme": scheme,
                    "host": host,
                    "port": p.get("port"),
                    "method": method,
                    "path": path_only,
                    "query": p.get("query"),
                    "url": p.get("url"),
                    "status": status,
                    "graphql_operation": graphql_op,
                    "endpoint": endpoint,
                    "service_key": p.get("service_key"),
                    "req_headers": _decode_header_fields(p.get("req_fields")),
                    "resp_headers": _decode_header_fields(p.get("resp_fields")),
                    "req_body": req_body_raw,
                    "resp_body": resp_body_raw,
                    "req_content_type": req_content_type,
                    "resp_content_type": resp_content_type,
                }
            )
            self._t_db_enqueue_ms += (time.perf_counter() - t_dbq) * 1000.0

    def _process_ws(self, p: dict[str, Any]) -> None:
        host = str(p["host"])
        scheme = p.get("scheme")
        path_only = str(p["path_only"])
        templ_path = templatize_path(path_only)

        raw: bytes | None = p.get("message")
        parsed: Any = None
        if raw:
            try:
                parsed = json.loads(raw)
            except Exception:
                try:
                    parsed = raw.decode("utf-8", errors="replace")
                except Exception:
                    parsed = f"<binary: {len(raw)} bytes>"

        direction = p.get("direction")
        if self.write_specs:
            self.store.update(
                host=host,
                scheme=scheme,
                method="WS",
                path=templ_path,
                query_params=None,
                request_headers=p.get("request_headers") or {},
                response_headers=None,
                request_body=parsed if direction == "send" else None,
                response_body=parsed if direction == "recv" else None,
                status_code=0,
                graphql_operation=None,
                is_websocket=True,
                ws_direction=direction,
            )

        if self.exchange_writer is not None:
            self.exchange_writer.enqueue(
                {
                    "scheme": scheme,
                    "host": host,
                    "port": p.get("port"),
                    "method": "WS",
                    "path": templ_path,
                    "query": None,
                    "url": p.get("url"),
                    "status": 0,
                    "endpoint": f"WS {templ_path}",
                    "service_key": p.get("service_key"),
                    "req_headers": _decode_header_fields(p.get("req_fields")),
                    "resp_headers": (),
                    "req_body": raw if direction == "send" else None,
                    "resp_body": raw if direction == "recv" else None,
                    "req_content_type": "websocket",
                    "resp_content_type": "websocket",
                }
            )
