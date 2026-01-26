"""Replay and diff helpers for agent workflows.

These functions sit on top of `ExchangeDB` and provide primitives for:
- building a replay request from a stored exchange
- applying mutations (headers/body/origin)
- re-sending via httpx and storing the resulting exchange
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse, urlunparse

import httpx

from .exchange_db import ExchangeDB, HeaderField

_HOP_BY_HOP_HEADERS = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
    "host",
    "accept-encoding",
}


@dataclass(frozen=True)
class ReplayPlan:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes | None
    notes: list[str]


def _lower_set(values: Sequence[str]) -> set[str]:
    return {v.lower() for v in values}


def _json_merge_patch(target: Any, patch: Any) -> Any:
    """Apply JSON Merge Patch (RFC 7396-ish) semantics."""
    if not isinstance(patch, dict):
        return patch
    if not isinstance(target, dict):
        target = {}
    out = dict(target)
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = _json_merge_patch(out.get(k), v)
    return out


def patch_json_body(body: bytes | None, patches: Sequence[Any]) -> bytes | None:
    """Apply one or more JSON merge patches to a request body."""
    if not patches:
        return body

    base_obj: Any
    if body is None or body == b"":
        base_obj = {}
    else:
        try:
            base_obj = json.loads(body.decode("utf-8"))
        except Exception as e:  # pragma: no cover
            raise ValueError("body is not valid UTF-8 JSON; cannot apply --patch-json") from e

    for p in patches:
        base_obj = _json_merge_patch(base_obj, p)

    return json.dumps(base_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_replay_plan(
    exchange: Mapping,
    *,
    origin: str | None = None,
    set_headers: Sequence[str] = (),
    drop_headers: Sequence[str] = (),
    body: bytes | None = None,
    json_patches: Sequence[Any] = (),
    keep_hop_by_hop: bool = False,
) -> ReplayPlan:
    """Build a replay request from an `ExchangeDB.get_exchange()` record.

    set_headers: list of "Name=Value"
    drop_headers: list of "Name"
    origin: if provided, overrides scheme://host[:port]
    """
    method = str(exchange.get("method") or "GET").upper()
    url = str(exchange.get("url") or "")
    if not url:
        # Fall back to parts.
        scheme = exchange.get("scheme") or "https"
        host = exchange.get("host") or ""
        path = exchange.get("path") or "/"
        query = exchange.get("query") or None
        netloc = host
        if exchange.get("port"):
            netloc = f"{netloc}:{int(exchange['port'])}"
        url = urlunparse((scheme, netloc, path, "", query or "", ""))

    parsed = urlparse(url)
    notes: list[str] = []

    if origin:
        origin_parsed = urlparse(origin)
        if not origin_parsed.scheme or not origin_parsed.netloc:
            raise ValueError("origin must be like 'https://example.com' (optionally with :port)")
        url = urlunparse(
            (
                origin_parsed.scheme,
                origin_parsed.netloc,
                parsed.path,
                "",
                parsed.query,
                "",
            )
        )
        notes.append(f"origin overridden to {origin_parsed.scheme}://{origin_parsed.netloc}")

    # Headers as captured (ordered).
    req_headers_raw = exchange.get("headers", {}).get("request", []) or []
    headers: list[tuple[str, str]] = [(h["name"], h["value"]) for h in req_headers_raw]

    drop = _lower_set(drop_headers)
    if not keep_hop_by_hop:
        drop |= _HOP_BY_HOP_HEADERS

    # Apply drop list.
    if drop:
        headers = [(k, v) for (k, v) in headers if k.lower() not in drop]

    # Apply set headers (override semantics: drop existing same-name, then append).
    for item in set_headers:
        if "=" not in item:
            raise ValueError(f"set_headers must be NAME=VALUE, got: {item!r}")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        headers = [(k, v) for (k, v) in headers if k.lower() != name.lower()]
        headers.append((name, value))

    # Body: override if provided, else use captured raw request body.
    if body is None:
        body = exchange.get("bodies", {}).get("request")

    if json_patches:
        body = patch_json_body(body, json_patches)
        notes.append(f"applied {len(json_patches)} json patch(es)")

    return ReplayPlan(method=method, url=url, headers=headers, body=body, notes=notes)


@dataclass(frozen=True)
class ReplayResult:
    original_id: int
    replay_id: int
    status: int
    url: str
    notes: list[str]
    replay_record_id: int | None = None


def _send_request(
    *,
    transport: str,
    impersonate: str | None,
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
    timeout: float,
    http2: bool,
) -> tuple[int, list[tuple[str, str]], bytes]:
    if transport == "httpx":
        with httpx.Client(http2=http2, timeout=timeout, follow_redirects=False) as client:
            resp = client.request(method, url, headers=headers, content=body)
        status = int(resp.status_code)
        resp_headers = list(resp.headers.multi_items())
        resp_body = bytes(resp.content)
        return status, resp_headers, resp_body

    if transport == "curl":
        try:
            from curl_cffi import requests as curl_requests
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "curl_cffi is not installed. Install with: pip install 'motim[curl]'"
            ) from e

        req_headers = dict(headers)
        # curl_cffi timeout is seconds; accept float.
        resp = curl_requests.request(  # type: ignore[call-arg]
            method,  # type: ignore[arg-type]
            url,
            headers=req_headers,
            data=body,
            timeout=timeout,
            impersonate=(impersonate or "chrome"),  # type: ignore[arg-type]
        )
        status = int(resp.status_code)
        # Best-effort header extraction (may lose duplicates).
        resp_headers = [(str(k), str(v)) for k, v in dict(resp.headers).items()]
        resp_body = bytes(resp.content or b"")
        return status, resp_headers, resp_body

    raise ValueError(f"unknown transport: {transport!r}")


def replay_exchange(
    db: ExchangeDB,
    exchange_id: int,
    *,
    tag: str | None = None,
    transport: str = "httpx",
    impersonate: str | None = None,
    origin: str | None = None,
    set_headers: Sequence[str] = (),
    drop_headers: Sequence[str] = (),
    body: bytes | None = None,
    json_patches: Sequence[Any] = (),
    keep_hop_by_hop: bool = False,
    timeout: float = 30.0,
    http2: bool = True,
) -> ReplayResult:
    """Replay a stored exchange and store the result as a new exchange in the DB."""
    ex = db.get_exchange(exchange_id)
    plan = build_replay_plan(
        ex,
        origin=origin,
        set_headers=set_headers,
        drop_headers=drop_headers,
        body=body,
        json_patches=json_patches,
        keep_hop_by_hop=keep_hop_by_hop,
    )

    status, resp_headers, resp_body = _send_request(
        transport=transport,
        impersonate=impersonate,
        method=plan.method,
        url=plan.url,
        headers=plan.headers,
        body=plan.body,
        timeout=timeout,
        http2=http2,
    )
    plan.notes.append(
        f"transport={transport}" + (f" impersonate={impersonate}" if impersonate else "")
    )

    # Store response as a new exchange.
    parsed = urlparse(plan.url)
    req_fields = [HeaderField(name=k, value=v) for k, v in plan.headers]
    resp_fields = [HeaderField(name=k, value=v) for k, v in resp_headers]
    replay_id = db.put_exchange(
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=parsed.port,
        method=plan.method,
        path=parsed.path,
        query=parsed.query or None,
        url=plan.url,
        status=status,
        endpoint=ex.get("endpoint"),
        service_key=ex.get("service_key"),
        req_headers=req_fields,
        resp_headers=resp_fields,
        req_body=plan.body,
        resp_body=resp_body,
        req_content_type=next((v for k, v in plan.headers if k.lower() == "content-type"), None),
        resp_content_type=next((v for k, v in resp_headers if k.lower() == "content-type"), None),
    )

    replay_record_id = None
    try:
        replay_record_id = db.record_replay(
            original_exchange_id=exchange_id,
            replay_exchange_id=replay_id,
            tag=tag,
            origin=origin,
            set_headers=set_headers,
            drop_headers=drop_headers,
            json_patches=list(json_patches),
            notes=plan.notes,
        )
    except Exception:
        # Recording metadata should never prevent the replay itself.
        replay_record_id = None

    return ReplayResult(
        original_id=exchange_id,
        replay_id=replay_id,
        status=status,
        url=plan.url,
        notes=plan.notes,
        replay_record_id=replay_record_id,
    )


def diff_exchanges(a: Mapping, b: Mapping) -> dict:
    """Produce a structured diff between two exchanges."""

    def _multi(hlist: Sequence[Mapping[str, str]]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for h in hlist:
            out.setdefault(h["name"].lower(), []).append(h["value"])
        return out

    a_req = _multi((a.get("headers", {}).get("request") or []))
    b_req = _multi((b.get("headers", {}).get("request") or []))
    a_resp = _multi((a.get("headers", {}).get("response") or []))
    b_resp = _multi((b.get("headers", {}).get("response") or []))

    def _diff_headers(x: dict[str, list[str]], y: dict[str, list[str]]) -> dict:
        keys = set(x) | set(y)
        added = {k: y[k] for k in keys - set(x)}
        removed = {k: x[k] for k in keys - set(y)}
        changed = {k: {"from": x[k], "to": y[k]} for k in keys & set(x) & set(y) if x[k] != y[k]}
        return {"added": added, "removed": removed, "changed": changed}

    return {
        "a": {
            "id": a.get("id"),
            "method": a.get("method"),
            "url": a.get("url"),
            "status": a.get("status"),
        },
        "b": {
            "id": b.get("id"),
            "method": b.get("method"),
            "url": b.get("url"),
            "status": b.get("status"),
        },
        "request_headers": _diff_headers(a_req, b_req),
        "response_headers": _diff_headers(a_resp, b_resp),
        "bodies": {
            "request": {
                "a_len": a.get("req_body_len"),
                "b_len": b.get("req_body_len"),
                "a_sha256": a.get("req_body_sha256"),
                "b_sha256": b.get("req_body_sha256"),
                "a_truncated": a.get("req_body_truncated"),
                "b_truncated": b.get("req_body_truncated"),
            },
            "response": {
                "a_len": a.get("resp_body_len"),
                "b_len": b.get("resp_body_len"),
                "a_sha256": a.get("resp_body_sha256"),
                "b_sha256": b.get("resp_body_sha256"),
                "a_truncated": a.get("resp_body_truncated"),
                "b_truncated": b.get("resp_body_truncated"),
            },
        },
    }
