"""Buffered exchange writer for the SQLite exchange DB.

Proxy capture happens on a hot path. Writing to SQLite synchronously (and committing
per request) can make browsing feel sluggish.

This module provides a buffered writer:
- capture thread enqueues exchange payloads quickly
- a background worker batches inserts in a single transaction
- commits happen every `batch_size` items or `flush_interval_ms`
"""

from __future__ import annotations

import atexit
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .exchange_db import ExchangeDB


@dataclass(frozen=True)
class EnqueueResult:
    accepted: bool
    dropped: bool = False


class BufferedExchangeWriter:
    """Asynchronous, batched writer for `ExchangeDB.put_exchange()` payloads."""

    def __init__(
        self,
        db_path: Path,
        *,
        max_body_bytes: int = 1_000_000,
        queue_max: int = 10_000,
        batch_size: int = 100,
        flush_interval_ms: int = 250,
        drop_when_full: bool = True,
    ):
        self.db_path = Path(db_path).expanduser()
        self.max_body_bytes = max_body_bytes
        self.queue_max = queue_max
        self.batch_size = batch_size
        self.flush_interval_ms = flush_interval_ms
        self.drop_when_full = drop_when_full

        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_max)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._started = False

        # Basic counters (best-effort; not atomic but good enough for telemetry/logging).
        self.enqueued = 0
        self.dropped = 0
        self.written = 0
        self.flushes = 0
        self.flush_ms_total = 0.0

        atexit.register(self.close)

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._thread.start()

    def flush(self, timeout: float = 5.0) -> None:
        """Wait until current queue items are processed."""
        deadline = time.monotonic() + timeout
        while (not self._q.empty() or self.written < self.enqueued) and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.05)

    def close(self) -> None:
        """Stop the worker and flush remaining items."""
        if not self._started:
            return
        self._stop.set()
        try:
            self._thread.join(timeout=5)
        except Exception:
            pass
        self._started = False

    def enqueue(self, payload: Mapping[str, Any]) -> EnqueueResult:
        """Enqueue an exchange payload.

        Payload must match `ExchangeDB.put_exchange()` keyword arguments.
        """
        if not self._started:
            self.start()

        item = dict(payload)
        try:
            if self.drop_when_full:
                self._q.put_nowait(item)
            else:
                self._q.put(item)
            self.enqueued += 1
            return EnqueueResult(accepted=True, dropped=False)
        except queue.Full:
            self.dropped += 1
            return EnqueueResult(accepted=False, dropped=True)

    def stats(self) -> dict[str, float]:
        """Lightweight stats snapshot for profiling/logging."""
        avg_flush_ms = self.flush_ms_total / self.flushes if self.flushes else 0.0
        return {
            "qsize": float(self._q.qsize()),
            "enqueued": float(self.enqueued),
            "dropped": float(self.dropped),
            "written": float(self.written),
            "flushes": float(self.flushes),
            "avg_flush_ms": float(avg_flush_ms),
        }

    def _run(self) -> None:
        db = ExchangeDB(self.db_path, max_body_bytes=self.max_body_bytes)
        try:
            flush_interval = max(1, int(self.flush_interval_ms)) / 1000.0
            batch: list[dict[str, Any]] = []
            last_flush = time.monotonic()

            while True:
                timeout = max(0.0, flush_interval - (time.monotonic() - last_flush))
                try:
                    item = self._q.get(timeout=timeout)
                    batch.append(item)
                except queue.Empty:
                    item = None

                should_flush = False
                if batch and (len(batch) >= self.batch_size):
                    should_flush = True
                if batch and (time.monotonic() - last_flush) >= flush_interval:
                    should_flush = True
                if self._stop.is_set() and (batch or self._q.empty()):
                    should_flush = True

                if should_flush and batch:
                    t = time.perf_counter()
                    self._flush_batch(db, batch)
                    self.flush_ms_total += (time.perf_counter() - t) * 1000.0
                    self.flushes += 1
                    self.written += len(batch)
                    batch = []
                    last_flush = time.monotonic()

                if self._stop.is_set() and self._q.empty() and not batch:
                    break
        finally:
            db.close()

    @staticmethod
    def _flush_batch(db: ExchangeDB, batch: list[dict[str, Any]]) -> None:
        cur = db._conn.cursor()  # noqa: SLF001 (internal use for batching)
        try:
            cur.execute("BEGIN;")
            for payload in batch:
                db._put_exchange_no_commit(  # type: ignore[arg-type, attr-defined]
                    cur,
                    **payload,
                )
            db._conn.commit()  # noqa: SLF001
        except Exception:
            db._conn.rollback()  # noqa: SLF001
        finally:
            try:
                cur.close()
            except Exception:
                pass
