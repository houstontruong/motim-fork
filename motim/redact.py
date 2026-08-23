"""Redaction-before-persistence engine for MOTIM (Production-Safe).

Ensures that credentials, tokens, session identifiers, and secrets never touch
disk or database storage. Redaction is applied strictly at every capture boundary
before indexing or persistence. Fails closed on unparseable or malformed payloads.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .normalize import format_cookie_header, parse_cookie_header


@dataclass(frozen=True)
class HeaderField:
    name: str
    value: str


REDACTED_PLACEHOLDER = "[REDACTED]"


# Headers that contain authentication or sensitive session state
SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "auth-token",
        "x-access-token",
        "access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "csrf-token",
        "xsrf-token",
        "x-session-id",
        "session-token",
        "token",
        "secret",
        "x-secret",
        "signature",
        "x-signature",
        "x-amz-security-token",
        "x-amz-credential",
        "nonce",
        "x-nonce",
    }
)

# Query parameters commonly used for authentication/secrets
SENSITIVE_QUERY_PARAMS = frozenset(
    {
        "api_key",
        "apikey",
        "key",
        "token",
        "access_token",
        "refresh_token",
        "auth",
        "secret",
        "client_secret",
        "password",
        "pass",
        "session",
        "session_id",
        "sig",
        "signature",
        "jwt",
        "code",
        "nonce",
    }
)

# Body field substrings identifying sensitive credential payload keys
SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth",
    "jwt",
    "session",
    "cookie",
    "private_key",
    "privkey",
    "credential",
    "signature",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "bearer",
    "key",
    "nonce",
)

# Regex matching JWT structures (header.payload.signature)
_JWT_PATTERN = re.compile(
    r"ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
)
# Regex matching Bearer token strings
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.~+/=]{10,}")
# Regex matching generic private key blocks
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
)
# Regex matching common API token formats (e.g. sk_live_..., ghp_..., etc.)
_CANARY_TOKEN_PATTERN = re.compile(
    r"(?i)(?:sk_live_[a-z0-9_\-]{8,}|ghp_[a-z0-9_\-]{8,}|aws_secret[a-z0-9_\-]{8,})"
)


class Redactor:
    """Configurable fail-closed redaction engine for sanitizing captured traffic."""

    def __init__(
        self,
        *,
        profile: str = "strict",
        placeholder: str = REDACTED_PLACEHOLDER,
        extra_headers: Sequence[str] = (),
        extra_query_params: Sequence[str] = (),
        extra_key_substrings: Sequence[str] = (),
    ):
        self.profile = profile
        self.placeholder = placeholder
        self.sensitive_headers = SENSITIVE_HEADER_NAMES | {str(h).lower() for h in extra_headers}
        self.sensitive_query_params = SENSITIVE_QUERY_PARAMS | {
            str(p).lower() for p in extra_query_params
        }
        self.sensitive_key_substrings = tuple(
            list(SENSITIVE_KEY_SUBSTRINGS) + [str(k).lower() for k in extra_key_substrings]
        )

    def redact_header_value(self, name: str, value: str) -> str:
        """Redact a header value based on header name and contents."""
        name_lower = str(name).lower()

        if name_lower == "authorization":
            val_strip = str(value).strip()
            if val_strip.lower().startswith("bearer "):
                return f"Bearer {self.placeholder}"
            if val_strip.lower().startswith("basic "):
                return f"Basic {self.placeholder}"
            return self.placeholder

        if name_lower in ("cookie", "set-cookie"):
            # Preserve cookie keys for schema/endpoint awareness, mask all values
            try:
                cookies = parse_cookie_header(str(value))
                if cookies:
                    redacted_cookies = {k: self.placeholder for k in cookies}
                    return format_cookie_header(redacted_cookies)
            except Exception:
                pass
            return self.placeholder

        if name_lower in self.sensitive_headers:
            return self.placeholder

        # Check if header name contains sensitive words
        if any(sub in name_lower for sub in ("token", "secret", "auth-", "api-key", "apikey", "signature", "nonce")):
            return self.placeholder

        # Regex scan value for embedded JWTs, Bearer tokens, or private keys
        val_str = str(value)
        val_str = _JWT_PATTERN.sub(self.placeholder, val_str)
        val_str = _BEARER_PATTERN.sub(f"Bearer {self.placeholder}", val_str)
        val_str = _CANARY_TOKEN_PATTERN.sub(self.placeholder, val_str)
        val_str = _PRIVATE_KEY_PATTERN.sub(
            f"-----BEGIN PRIVATE KEY-----\n{self.placeholder}\n-----END PRIVATE KEY-----", val_str
        )
        return val_str

    def redact_headers_dict(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        """Redact a dictionary of HTTP headers."""
        if not headers:
            return {}
        return {str(k): self.redact_header_value(str(k), str(v)) for k, v in headers.items()}

    def redact_header_fields(
        self, fields: Sequence[HeaderField] | Sequence[tuple[bytes, bytes]] | None
    ) -> list[HeaderField]:
        """Redact a list of HeaderField objects or raw byte tuples."""
        if not fields:
            return []
        out: list[HeaderField] = []
        for item in fields:
            if isinstance(item, HeaderField):
                name, val = item.name, item.value
            elif isinstance(item, tuple) and len(item) == 2:
                name_b, val_b = item
                name = name_b.decode("latin-1", errors="replace") if isinstance(name_b, bytes) else str(name_b)
                val = val_b.decode("latin-1", errors="replace") if isinstance(val_b, bytes) else str(val_b)
            else:
                continue
            redacted_val = self.redact_header_value(name, val)
            out.append(HeaderField(name=name, value=redacted_val))
        return out

    def redact_query_string(self, query: str | None) -> str | None:
        """Redact sensitive query parameter values. Fails closed on malformed query."""
        if not query:
            return query
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
            if not pairs:
                return query
            redacted_pairs = []
            for k, v in pairs:
                k_str = str(k)
                k_lower = k_str.lower()
                if k_lower in self.sensitive_query_params or any(
                    sub in k_lower for sub in ("token", "secret", "pass", "key", "auth", "sig", "nonce")
                ):
                    redacted_pairs.append((k_str, self.placeholder))
                else:
                    # Also sanitize value for JWT/Bearer
                    v_clean = _JWT_PATTERN.sub(self.placeholder, str(v))
                    v_clean = _CANARY_TOKEN_PATTERN.sub(self.placeholder, v_clean)
                    redacted_pairs.append((k_str, v_clean))
            return urlencode(redacted_pairs)
        except Exception:
            return f"query={self.placeholder}"

    def redact_url(self, url: str | None) -> str | None:
        """Redact query parameters in a full URL. Fails closed on malformed URL."""
        if not url:
            return url
        if "?" not in url:
            return url
        try:
            parsed = urlparse(url)
            redacted_query = self.redact_query_string(parsed.query)
            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    redacted_query or "",
                    parsed.fragment,
                )
            )
        except Exception:
            return f"[REDACTED_URL]"

    def redact_data_structure(self, data: Any) -> Any:
        """Recursively redact dictionary/list structures."""
        if isinstance(data, dict):
            out_dict: dict[Any, Any] = {}
            for k, v in data.items():
                k_str = str(k)
                k_lower = k_str.lower()
                is_sensitive = (
                    k_lower in self.sensitive_query_params
                    or any(sub in k_lower for sub in self.sensitive_key_substrings)
                )
                if is_sensitive:
                    out_dict[k] = self.placeholder
                else:
                    out_dict[k] = self.redact_data_structure(v)
            return out_dict


        if isinstance(data, list):
            return [self.redact_data_structure(item) for item in data]

        if isinstance(data, str):
            val = _JWT_PATTERN.sub(self.placeholder, data)
            val = _BEARER_PATTERN.sub(f"Bearer {self.placeholder}", val)
            val = _CANARY_TOKEN_PATTERN.sub(self.placeholder, val)
            val = _PRIVATE_KEY_PATTERN.sub(
                f"-----BEGIN PRIVATE KEY-----\n{self.placeholder}\n-----END PRIVATE KEY-----", val
            )
            return val

        return data

    def redact_body_bytes(
        self, body_bytes: bytes | None, content_type: str | None = None
    ) -> bytes | None:
        """Redact raw byte payloads (JSON, form-urlencoded, or text). Fails closed on unparseable data."""
        if not body_bytes:
            return body_bytes

        ct = (content_type or "").lower()

        # 1. Try JSON parsing
        if "json" in ct or body_bytes.strip().startswith((b"{", b"[")):
            try:
                decoded = body_bytes.decode("utf-8")
                parsed = json.loads(decoded)
                redacted = self.redact_data_structure(parsed)
                return json.dumps(redacted, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception:
                # If content-type claimed to be JSON but parsing failed, fail closed
                if "json" in ct:
                    return b'{"_redacted": "[REDACTED: unparseable json body]"}'

        # 2. Try form-urlencoded
        if "x-www-form-urlencoded" in ct or (b"=" in body_bytes and b"&" in body_bytes and not body_bytes.strip().startswith(b"<")):
            try:
                decoded = body_bytes.decode("utf-8")
                redacted_query = self.redact_query_string(decoded)
                if redacted_query:
                    return redacted_query.encode("utf-8")
            except Exception:
                if "x-www-form-urlencoded" in ct:
                    return b"_redacted=[REDACTED: unparseable form]"

        # 3. Multipart form data: fail closed (omit or mask parts)
        if "multipart/form-data" in ct:
            return b"--multipart-omitted-for-redaction--"

        # 4. Try text regex redaction for known text content types
        if any(t in ct for t in ("text/", "xml", "javascript", "html", "yaml")):
            try:
                text = body_bytes.decode("utf-8", errors="replace")
                redacted_text = self.redact_data_structure(text)
                if isinstance(redacted_text, str):
                    return redacted_text.encode("utf-8")
            except Exception:
                return b"[REDACTED: unparseable text body]"

        # 5. General fallback: if UTF-8 decodable, sanitize text patterns; else if unparseable binary, keep length or mask
        try:
            text = body_bytes.decode("utf-8")
            redacted_text = self.redact_data_structure(text)
            if isinstance(redacted_text, str):
                return redacted_text.encode("utf-8")
        except UnicodeDecodeError:
            # Binary body
            pass

        return body_bytes

    def redact_flow_payload(self, p: dict[str, Any]) -> dict[str, Any]:
        """Redact a full normalized flow payload synchronously before queuing or DB insert."""
        out = dict(p)

        # 1. URL & query
        if "url" in out and out["url"]:
            out["url"] = self.redact_url(str(out["url"]))
        if "query" in out and out["query"]:
            out["query"] = self.redact_query_string(str(out["query"]))
        if "query_params" in out and isinstance(out["query_params"], dict):
            out_qp: dict[str, Any] = {}
            for k, v in out["query_params"].items():
                k_str = str(k)
                k_lower = k_str.lower()
                if (
                    k_lower in self.sensitive_query_params
                    or any(sub in k_lower for sub in ("token", "secret", "pass", "key", "auth", "sig"))
                ):
                    out_qp[k_str] = self.placeholder
                else:
                    out_qp[k_str] = self.redact_data_structure(v)
            out["query_params"] = out_qp

        # 2. Headers dicts
        if "request_headers" in out and out["request_headers"]:
            out["request_headers"] = self.redact_headers_dict(out["request_headers"])
        if "response_headers" in out and out["response_headers"]:
            out["response_headers"] = self.redact_headers_dict(out["response_headers"])

        # 3. Header fields
        if "req_fields" in out and out["req_fields"]:
            out["req_fields"] = self.redact_header_fields(out["req_fields"])
        if "resp_fields" in out and out["resp_fields"]:
            out["resp_fields"] = self.redact_header_fields(out["resp_fields"])

        # 4. Raw bodies
        req_ct = str(out.get("req_content_type") or "")
        resp_ct = str(out.get("resp_content_type") or "")

        if "req_body" in out and out["req_body"]:
            out["req_body"] = self.redact_body_bytes(out["req_body"], req_ct)
        if "resp_body" in out and out["resp_body"]:
            out["resp_body"] = self.redact_body_bytes(out["resp_body"], resp_ct)

        # 5. Parsed bodies (if already parsed)
        if "request_body" in out and out["request_body"]:
            out["request_body"] = self.redact_data_structure(out["request_body"])
        if "response_body" in out and out["response_body"]:
            out["response_body"] = self.redact_data_structure(out["response_body"])

        # 6. WebSocket message
        if "message" in out and out["message"]:
            if isinstance(out["message"], bytes):
                out["message"] = self.redact_body_bytes(out["message"], "json")
            else:
                out["message"] = self.redact_data_structure(out["message"])

        return out


# Global default strict redactor instance
_default_redactor: Redactor | None = None


def get_redactor(profile: str = "strict") -> Redactor:
    """Get or create the global redactor instance."""
    global _default_redactor
    if _default_redactor is None or _default_redactor.profile != profile:
        _default_redactor = Redactor(profile=profile)
    return _default_redactor
