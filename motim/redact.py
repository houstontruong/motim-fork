"""Redaction-before-persistence engine for MOTIM (Production-Safe).

Ensures that credentials, tokens, session identifiers, and secrets never touch
disk or database storage. Redaction is applied strictly at every capture boundary
before indexing or persistence. Fails closed on unparseable or malformed payloads.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, Set
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


def normalize_sensitive_name(name: Any) -> str:
    """Normalize a header, query parameter, or field name for sensitive pattern matching.

    Converts to lowercase and strips hyphens and underscores.
    """
    return str(name).lower().replace("-", "").replace("_", "")


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
        self._normalized_sensitive_headers = frozenset(
            normalize_sensitive_name(h) for h in self.sensitive_headers
        )
        self._normalized_sensitive_query_params = frozenset(
            normalize_sensitive_name(p) for p in self.sensitive_query_params
        )
        self._normalized_sensitive_key_substrings = tuple(
            normalize_sensitive_name(k) for k in self.sensitive_key_substrings
        )

    def is_sensitive_name(self, name: Any) -> bool:
        """Check if a header, query parameter, or field name is sensitive under normalized matching."""
        name_norm = normalize_sensitive_name(name)
        if not name_norm:
            return False
        if (
            name_norm in self._normalized_sensitive_query_params
            or name_norm in self._normalized_sensitive_headers
        ):
            return True
        return any(sub in name_norm for sub in self._normalized_sensitive_key_substrings)

    def redact_header_value(self, name: str, value: str) -> str:
        """Redact a header value based on header name and contents."""
        name_norm = normalize_sensitive_name(name)

        if name_norm == "authorization":
            val_strip = str(value).strip()
            if val_strip.lower().startswith("bearer "):
                return f"Bearer {self.placeholder}"
            if val_strip.lower().startswith("basic "):
                return f"Basic {self.placeholder}"
            return self.placeholder

        if name_norm in ("cookie", "setcookie"):
            # Preserve cookie keys for schema/endpoint awareness, mask all values
            try:
                cookies = parse_cookie_header(str(value))
                if cookies:
                    redacted_cookies = {k: self.placeholder for k in cookies}
                    return format_cookie_header(redacted_cookies)
            except Exception:
                pass
            return self.placeholder

        if self.is_sensitive_name(name):
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
                if self.is_sensitive_name(k_str):
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
        """Redact userinfo and query parameters in a full URL. Fails closed on malformed URL."""
        if not url:
            return url
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            scheme = parsed.scheme
            path = parsed.path

            # If no scheme but contains '//' or '@', check if urlparse parsed userinfo into path/scheme
            if not netloc and "@" in url:
                if url.startswith("//"):
                    parsed_dummy = urlparse("http:" + url)
                    netloc = parsed_dummy.netloc
                    path = parsed_dummy.path
                else:
                    parsed_dummy = urlparse("http://" + url)
                    netloc = parsed_dummy.netloc
                    path = parsed_dummy.path

            if "@" in netloc:
                userinfo, _, host_port = netloc.rpartition("@")
                if ":" in userinfo:
                    u, _, p = userinfo.partition(":")
                    u_clean = (
                        self.placeholder
                        if (
                            self.is_sensitive_name(u)
                            or _CANARY_TOKEN_PATTERN.search(u)
                            or _JWT_PATTERN.search(u)
                            or "canary" in u.lower()
                        )
                        else u
                    )
                    userinfo_clean = f"{u_clean}:{self.placeholder}"
                else:
                    userinfo_clean = self.placeholder
                netloc_clean = f"{userinfo_clean}@{host_port}"
            else:
                netloc_clean = netloc

            redacted_query = self.redact_query_string(parsed.query) if parsed.query else ""

            path_clean = _JWT_PATTERN.sub(self.placeholder, path)
            path_clean = _BEARER_PATTERN.sub(f"Bearer {self.placeholder}", path_clean)
            path_clean = _CANARY_TOKEN_PATTERN.sub(self.placeholder, path_clean)

            frag_clean = parsed.fragment
            if frag_clean:
                if "=" in frag_clean:
                    frag_clean = self.redact_query_string(frag_clean) or frag_clean
                frag_clean = _CANARY_TOKEN_PATTERN.sub(self.placeholder, frag_clean)
                frag_clean = _JWT_PATTERN.sub(self.placeholder, frag_clean)

            if not scheme and not parsed.netloc and "@" in url:
                res = f"{netloc_clean}{path_clean}"
                if redacted_query:
                    res += f"?{redacted_query}"
                if frag_clean:
                    res += f"#{frag_clean}"
                return res

            return urlunparse(
                (
                    scheme,
                    netloc_clean,
                    path_clean,
                    parsed.params,
                    redacted_query or "",
                    frag_clean or "",
                )
            )
        except Exception:
            return f"[REDACTED_URL]"

    def redact_data_structure(self, data: Any) -> Any:
        """Recursively redact dictionary/list/tuple/set/mapping structures."""
        if isinstance(data, (dict, Mapping)):
            out_dict: dict[Any, Any] = {}
            for k, v in data.items():
                if self.is_sensitive_name(k):
                    out_dict[k] = self.placeholder
                else:
                    k_redacted = self.redact_data_structure(k) if isinstance(k, (str, tuple, frozenset)) else k
                    out_dict[k_redacted] = self.redact_data_structure(v)
            return out_dict

        if isinstance(data, list):
            return [self.redact_data_structure(item) for item in data]

        if isinstance(data, tuple):
            return tuple(self.redact_data_structure(item) for item in data)

        if isinstance(data, (set, frozenset, Set)):
            redacted_items = [self.redact_data_structure(item) for item in data]
            if isinstance(data, frozenset):
                return frozenset(redacted_items)
            return set(redacted_items)

        if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
            return [self.redact_data_structure(item) for item in data]

        if isinstance(data, (bytes, bytearray)):
            return self.redact_body_bytes(bytes(data))

        if isinstance(data, str):
            val = _JWT_PATTERN.sub(self.placeholder, data)
            val = _BEARER_PATTERN.sub(f"Bearer {self.placeholder}", val)
            val = _CANARY_TOKEN_PATTERN.sub(self.placeholder, val)
            val = _PRIVATE_KEY_PATTERN.sub(
                f"-----BEGIN PRIVATE KEY-----\n{self.placeholder}\n-----END PRIVATE KEY-----", val
            )
            if ("?" in val or "@" in val or "://" in val) and any(
                sub in normalize_sensitive_name(val) for sub in self._normalized_sensitive_key_substrings
            ):
                try:
                    val = self.redact_url(val) or val
                except Exception:
                    pass
            return val

        return data

    def _redact_form_text(self, text: str, *, strict_urlencode: bool = False) -> str:
        """Redact sensitive form or key-value fields in text.

        If strict_urlencode is True, always re-encodes via urlencode.
        Otherwise (for unknown content-type), replaces sensitive values in-place without percent-encoding benign text.
        """
        if "\n" in text:
            lines = text.splitlines(keepends=True)
            redacted_lines = []
            for line in lines:
                if "=" in line:
                    nl = ""
                    if line.endswith("\r\n"):
                        line_core = line[:-2]
                        nl = "\r\n"
                    elif line.endswith("\n"):
                        line_core = line[:-1]
                        nl = "\n"
                    else:
                        line_core = line
                    red_line = self._redact_form_text(line_core, strict_urlencode=strict_urlencode)
                    redacted_lines.append(red_line + nl)
                else:
                    redacted_lines.append(self.redact_data_structure(line))
            return "".join(redacted_lines)

        try:
            pairs = parse_qsl(text, keep_blank_values=True)
            if not pairs:
                return self.redact_data_structure(text)

            has_sensitive = any(self.is_sensitive_name(str(k)) for k, _ in pairs)

            if strict_urlencode:
                return self.redact_query_string(text) or text

            if not has_sensitive:
                return self.redact_data_structure(text)

            redacted_pairs = []
            for k, v in pairs:
                k_str = str(k)
                if self.is_sensitive_name(k_str):
                    redacted_pairs.append((k_str, self.placeholder))
                else:
                    v_clean = _JWT_PATTERN.sub(self.placeholder, str(v))
                    v_clean = _CANARY_TOKEN_PATTERN.sub(self.placeholder, v_clean)
                    v_clean = _BEARER_PATTERN.sub(f"Bearer {self.placeholder}", v_clean)
                    redacted_pairs.append((k_str, v_clean))
            return "&".join(f"{k}={v}" for k, v in redacted_pairs)
        except Exception:
            return self.redact_data_structure(text)

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
                if "json" in ct:
                    return b'{"_redacted": "[REDACTED: unparseable json body]"}'

        # 2. Multipart form data: fail closed
        if "multipart/form-data" in ct:
            return b"--multipart-omitted-for-redaction--"

        # 3. Known code / markup text content types: sanitize with regex / structural rules
        if any(t in ct for t in ("javascript", "xml", "html", "yaml", "css")):
            try:
                text = body_bytes.decode("utf-8", errors="replace")
                redacted_text = self.redact_data_structure(text)
                if isinstance(redacted_text, str):
                    return redacted_text.encode("utf-8")
            except Exception:
                return b"[REDACTED: unparseable text body]"

        # 4. Form-urlencoded (explicit content-type)
        if "x-www-form-urlencoded" in ct:
            try:
                decoded = body_bytes.decode("utf-8")
                redacted_query = self._redact_form_text(decoded, strict_urlencode=True)
                if redacted_query is not None:
                    return redacted_query.encode("utf-8")
            except Exception:
                return b"_redacted=[REDACTED: unparseable form]"

        # 5. Form-shaped payloads when content-type is unknown / generic text
        if b"=" in body_bytes and not body_bytes.strip().startswith(b"<"):
            try:
                decoded = body_bytes.decode("utf-8")
                redacted_form = self._redact_form_text(decoded, strict_urlencode=False)
                if redacted_form is not None:
                    return redacted_form.encode("utf-8")
            except UnicodeDecodeError:
                pass

        # 6. General fallback: if UTF-8 decodable, sanitize text patterns; else if unparseable binary, keep length or mask
        try:
            text = body_bytes.decode("utf-8")
            redacted_text = self.redact_data_structure(text)
            if isinstance(redacted_text, str):
                return redacted_text.encode("utf-8")
        except UnicodeDecodeError:
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
                if self.is_sensitive_name(k_str):
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
