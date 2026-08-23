"""Diff helpers for comparing captured exchanges.

This module provides pure static comparison utilities for analyzing differences
between stored exchanges (headers, status codes, payload hashes) without any
network transport or replay capabilities.
"""

from __future__ import annotations

from typing import Mapping, Sequence


def diff_exchanges(a: Mapping, b: Mapping) -> dict:
    """Produce a structured diff between two captured exchanges."""

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
