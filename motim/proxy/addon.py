"""mitmproxy addon that captures API traffic.

This addon is responsible for observing request/response flows and writing
sanitized summaries, samples, and auth headers into the MOTIM spec store.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime

from mitmproxy import http

from motim.config import get_config
from motim.exchange_db import ExchangeDB, HeaderField
from motim.exchange_writer import BufferedExchangeWriter
from motim.proxy.filters import should_capture_with_config
from motim.proxy.pipeline import CapturePipeline
from motim.store import Store

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GRAY = "\033[90m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"


class MotimAddon:
    """Mitmproxy addon that observes traffic and writes specs."""

    def __init__(self):
        self.verbose = os.environ.get("MOTIM_VERBOSE", "0") == "1"
        self.captured_count = 0
        self.skipped_count = 0
        self._store: Store | None = None
        self._exchange_db: ExchangeDB | None = None
        self._exchange_writer: BufferedExchangeWriter | None = None
        self._pipeline: CapturePipeline | None = None
        self._config = None

        # Hot-path profiling accumulators
        self._hp_n = 0
        self._hp_t_total_ms = 0.0
        self._hp_t_filter_ms = 0.0
        self._hp_t_extract_ms = 0.0
        self._hp_t_enqueue_ms = 0.0
        self._hp_req_bytes = 0
        self._hp_resp_bytes = 0

    @property
    def store(self) -> Store:
        """Lazy-load store."""
        if self._store is None:
            self._config = get_config()
            self._store = Store(config=self._config)
        return self._store

    @property
    def config(self):
        """Lazy-load config."""
        if self._config is None:
            self._config = get_config()
        return self._config

    @property
    def exchange_db(self) -> ExchangeDB | None:
        """Lazy-load SQLite exchange DB if enabled."""
        if not self.config.capture.store_exchanges:
            return None
        if self._exchange_db is None:
            from pathlib import Path

            db_path = Path(self.config.capture.exchange_db_path).expanduser()
            self._exchange_db = ExchangeDB(
                db_path,
                max_body_bytes=self.config.capture.max_body_bytes,
            )
        return self._exchange_db

    @property
    def exchange_writer(self) -> BufferedExchangeWriter | None:
        """Lazy-load buffered exchange writer if enabled."""
        if not self.config.capture.store_exchanges:
            return None
        if not self.config.capture.exchange_db_buffered:
            return None
        if self._exchange_writer is None:
            from pathlib import Path

            db_path = Path(self.config.capture.exchange_db_path).expanduser()
            self._exchange_writer = BufferedExchangeWriter(
                db_path,
                max_body_bytes=self.config.capture.max_body_bytes,
                queue_max=self.config.capture.exchange_db_queue_max,
                batch_size=self.config.capture.exchange_db_batch_size,
                flush_interval_ms=self.config.capture.exchange_db_flush_interval_ms,
                drop_when_full=True,
            )
        return self._exchange_writer

    @property
    def pipeline(self) -> CapturePipeline | None:
        """Background capture pipeline (parsing + store/db updates)."""
        if not self.config.capture.pipeline_enabled:
            return None
        if self._pipeline is None:
            self._pipeline = CapturePipeline(
                store=self.store,
                exchange_writer=self.exchange_writer,
                write_specs=self.config.capture.write_specs,
                max_parse_bytes=self.config.capture.pipeline_max_parse_bytes,
                queue_max=self.config.capture.pipeline_queue_max,
                drop_when_full=self.config.capture.pipeline_drop_when_full,
                profile_enabled=self.config.capture.profile_enabled,
                profile_every_n=self.config.capture.profile_every_n,
            )
        return self._pipeline

    @staticmethod
    def _header_fields(headers_obj) -> list[HeaderField]:
        """Convert mitmproxy Headers into an ordered header field list."""
        fields: list[HeaderField] = []
        # mitmproxy Headers stores raw fields in bytes; decode with latin-1 per RFC.
        for name_b, value_b in getattr(headers_obj, "fields", []):
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

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received."""
        prof = bool(getattr(self.config.capture, "profile_enabled", False))
        t0 = time.perf_counter() if prof else 0.0

        request = flow.request
        response = flow.response
        if response is None:
            return

        host = request.host
        scheme = getattr(request, "scheme", None)
        if not scheme:
            port = getattr(request, "port", None)
            scheme = "https" if port == 443 else "http"
        path = request.path
        path_only = request.path.split("?")[0]
        query_string = request.query
        content_type = response.headers.get("content-type", "")
        method = request.method
        status = response.status_code

        # Filter noise
        t_filter = time.perf_counter() if prof else 0.0
        allowed = should_capture_with_config(host, path_only, content_type, self.config)
        if prof:
            self._hp_t_filter_ms += (time.perf_counter() - t_filter) * 1000.0
        if not allowed:
            self.skipped_count += 1
            if self.verbose:
                self._log_skipped(method, host, path, "filtered")
            return

        # Extract headers (dicts used for spec updates; raw fields preserve ordering for DB).
        t_extract = time.perf_counter() if prof else 0.0
        request_headers = dict(request.headers)
        response_headers = dict(response.headers)
        req_fields = list(getattr(request.headers, "fields", []))
        resp_fields = list(getattr(response.headers, "fields", []))
        req_content_type = request.headers.get("content-type", "")
        req_body = request.content
        resp_body = response.content
        if prof:
            self._hp_req_bytes += len(req_body or b"")
            self._hp_resp_bytes += len(resp_body or b"")
            self._hp_t_extract_ms += (time.perf_counter() - t_extract) * 1000.0

        # Offload parsing + spec/db updates to background pipeline.
        if self.pipeline is not None:
            qs = request.path.split("?", 1)[1] if "?" in request.path else None
            t_enq = time.perf_counter() if prof else 0.0
            ok = self.pipeline.enqueue(
                "http",
                {
                    "scheme": scheme,
                    "host": host,
                    "port": getattr(request, "port", None),
                    "method": method,
                    "status": status,
                    "path": request.path,
                    "path_only": path_only,
                    "query": qs,
                    "query_params": dict(query_string) if query_string else None,
                    "url": f"{scheme}://{host}{request.path}",
                    "service_key": host.replace(".", "_").replace(":", "_"),
                    "request_headers": request_headers,
                    "response_headers": response_headers,
                    "req_fields": req_fields,
                    "resp_fields": resp_fields,
                    "req_body": req_body,
                    "resp_body": resp_body,
                    "req_content_type": req_content_type,
                    "resp_content_type": content_type,
                },
            )
            if prof:
                self._hp_t_enqueue_ms += (time.perf_counter() - t_enq) * 1000.0
            self.captured_count += 1
            if self.verbose and ok:
                # Lightweight log; detailed info is stored in DB/specs.
                self._log_captured(method, host, self._templatize_path(path_only), status, None)
            elif self.verbose and not ok:
                self._log_skipped(method, host, path, "pipeline queue full")
        else:
            # Fallback: legacy synchronous behavior.
            templatized_path = self._templatize_path(path_only)
            self.store.update(
                host=host,
                scheme=scheme,
                method=method,
                path=templatized_path,
                query_params=dict(query_string) if query_string else None,
                request_headers=request_headers,
                response_headers=response_headers,
                request_body=None,
                response_body=None,
                status_code=status,
                graphql_operation=None,
            )
            self.captured_count += 1
            self._log_captured(method, host, templatized_path, status, None)

        if not self.verbose:
            every = max(1, int(getattr(self.config.capture, "log_every_n", 25)))
            if self.captured_count % every == 0:
                ts = datetime.now().strftime("%H:%M:%S")
                print(
                    f"{GRAY}{ts}{RESET} captured {self.captured_count} "
                    f"(skipped {self.skipped_count})"
                )
                sys.stdout.flush()

        if prof:
            self._hp_n += 1
            self._hp_t_total_ms += (time.perf_counter() - t0) * 1000.0
            every = max(1, int(getattr(self.config.capture, "profile_every_n", 200)))
            if self._hp_n % every == 0:
                avg_total = self._hp_t_total_ms / every
                avg_filter = self._hp_t_filter_ms / every
                avg_extract = self._hp_t_extract_ms / every
                avg_enq = self._hp_t_enqueue_ms / every
                avg_req_kb = (self._hp_req_bytes / every) / 1024.0
                avg_resp_kb = (self._hp_resp_bytes / every) / 1024.0

                pipe_stats = self.pipeline.stats() if self.pipeline is not None else {}
                w = self.exchange_writer
                w_stats = w.stats() if w is not None else {}
                print(
                    "[motim hotpath] "
                    f"n={self._hp_n} avg_ms(total={avg_total:.2f} filter={avg_filter:.2f} "
                    f"extract={avg_extract:.2f} enqueue={avg_enq:.2f}) "
                    f"avg_kb(req={avg_req_kb:.1f} resp={avg_resp_kb:.1f}) "
                    f"pipe={pipe_stats} writer={w_stats}"
                )
                # reset window
                self._hp_t_total_ms = 0.0
                self._hp_t_filter_ms = 0.0
                self._hp_t_extract_ms = 0.0
                self._hp_t_enqueue_ms = 0.0
                self._hp_req_bytes = 0
                self._hp_resp_bytes = 0

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Called when a WebSocket message is received."""
        assert flow.websocket is not None

        host = flow.request.host
        path = flow.request.path.split("?")[0]

        message = flow.websocket.messages[-1]

        direction_symbol = "→" if message.from_client else "←"
        direction = "send" if message.from_client else "recv"

        if self.pipeline is not None:
            scheme = getattr(flow.request, "scheme", None) or "https"
            req_fields = list(getattr(flow.request.headers, "fields", []))
            self.pipeline.enqueue(
                "ws",
                {
                    "scheme": scheme,
                    "host": host,
                    "port": getattr(flow.request, "port", None),
                    "path": flow.request.path,
                    "path_only": path,
                    "url": f"{scheme}://{host}{flow.request.path}",
                    "service_key": host.replace(".", "_").replace(":", "_"),
                    "request_headers": dict(flow.request.headers),
                    "req_fields": req_fields,
                    "message": message.content,
                    "direction": direction,
                },
            )
            if self.verbose:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(
                    f"{GRAY}{timestamp}{RESET} {BLUE}websocket{RESET} "
                    f"{direction_symbol} {host}{path[:30]}"
                )
                sys.stdout.flush()

    def _log_captured(
        self,
        method: str,
        host: str,
        path: str,
        status: int,
        graphql_op: str | None = None,
    ) -> None:
        """Log a captured request."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        spec_file = f"{host.replace('.', '_')}.yaml"

        display_path = path if len(path) <= 40 else path[:37] + "..."
        op_str = f" ({graphql_op})" if graphql_op else ""

        if status < 300:
            status_color = GREEN
        elif status < 400:
            status_color = YELLOW
        else:
            status_color = RED

        print(
            f"{GRAY}{timestamp}{RESET} "
            f"{GREEN}captured{RESET} "
            f"{BOLD}{method:6}{RESET} "
            f"{status_color}{status}{RESET} "
            f"{host}{display_path}{op_str} "
            f"{GRAY}→ {spec_file}{RESET}"
        )
        sys.stdout.flush()

    def _log_skipped(self, method: str, host: str, path: str, reason: str) -> None:
        """Log a skipped request (verbose mode only)."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        display_path = path if len(path) <= 40 else path[:37] + "..."

        print(f"{GRAY}{timestamp} skipped  {method:6} {host}{display_path} ({reason}){RESET}")
        sys.stdout.flush()

    def _parse_body(self, content: bytes, content_type: str):
        """Parse request/response body based on content type."""
        from urllib.parse import parse_qs

        try:
            if "json" in content_type:
                return json.loads(content)

            if "x-www-form-urlencoded" in content_type:
                form_data = parse_qs(content.decode("utf-8", errors="replace"))
                return {k: v[0] if len(v) == 1 else v for k, v in form_data.items()}

            if "multipart/form-data" in content_type:
                return self._parse_multipart(content, content_type)

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

    def _parse_multipart(self, content: bytes, content_type: str):
        """Parse multipart form data."""
        try:
            boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
            if not boundary_match:
                return "<multipart: no boundary>"

            boundary = boundary_match.group(1).encode()
            parts = content.split(b"--" + boundary)

            result = {}
            for part in parts:
                if not part or part == b"--" or part == b"--\r\n":
                    continue

                if b"\r\n\r\n" in part:
                    headers_bytes, body = part.split(b"\r\n\r\n", 1)
                    headers_text = headers_bytes.decode("utf-8", errors="replace")

                    name_match = re.search(r'name="([^"]+)"', headers_text)
                    if name_match:
                        field_name = name_match.group(1)

                        filename_match = re.search(r'filename="([^"]+)"', headers_text)
                        if filename_match:
                            result[field_name] = (
                                f"<file: {filename_match.group(1)}, {len(body)} bytes>"
                            )
                        else:
                            try:
                                result[field_name] = body.rstrip(b"\r\n").decode("utf-8")
                            except Exception:
                                result[field_name] = f"<binary: {len(body)} bytes>"

            return result if result else "<multipart: empty>"

        except Exception as e:
            return f"<multipart parse error: {str(e)[:50]}>"

    def _templatize_path(self, path: str) -> str:
        """Replace IDs in path with placeholders."""
        # UUID pattern
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{id}",
            path,
            flags=re.IGNORECASE,
        )
        # Long hex strings (20+ chars)
        path = re.sub(r"/[a-f0-9]{20,}", "/{id}", path, flags=re.IGNORECASE)
        # Numeric IDs (6+ digits)
        path = re.sub(r"/\d{6,}", "/{id}", path)
        return path


# Export for mitmproxy
addons = [MotimAddon()]
