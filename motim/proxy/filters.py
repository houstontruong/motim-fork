"""Filter out noise from captured traffic."""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from motim.config import Config

# Default domains to ignore (analytics, tracking, etc.)
DEFAULT_IGNORE_DOMAINS = [
    r".*\.google-analytics\.com$",
    r".*\.googletagmanager\.com$",
    r".*\.doubleclick\.net$",
    r".*\.segment\.io$",
    r".*\.segment\.com$",
    r".*\.hotjar\.com$",
    r".*\.intercom\.io$",
    r".*\.mixpanel\.com$",
    r".*\.amplitude\.com$",
    r".*\.sentry\.io$",
    r".*\.launchdarkly\.com$",
    r".*\.datadoghq\.com$",
    r".*\.newrelic\.com$",
    r".*\.facebook\.com$",
    r".*\.twitter\.com$",
    r".*\.linkedin\.com$",
    r".*\.ads\..*$",
    r".*\.analytics\..*$",
]

# Paths to ignore (only truly static assets)
DEFAULT_IGNORE_PATHS = [
    r"^/favicon\.ico$",
    r"^/robots\.txt$",
    r".*\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm|mp3|wav)$",
]

# Compiled patterns (lazy)
_domain_patterns: list[re.Pattern] | None = None
_path_patterns: list[re.Pattern] | None = None


def _compile_patterns():
    """Compile regex patterns for filtering."""
    global _domain_patterns, _path_patterns
    _domain_patterns = [re.compile(p) for p in DEFAULT_IGNORE_DOMAINS]
    _path_patterns = [re.compile(p) for p in DEFAULT_IGNORE_PATHS]


def should_capture(host: str, path: str, content_type: str | None = None) -> bool:
    """Determine if this request/response should be captured.

    Args:
        host: Request hostname
        path: Request path (without query string)
        content_type: Response content type (optional, unused currently)

    Returns:
        True if the request should be captured
    """
    global _domain_patterns, _path_patterns

    if _domain_patterns is None:
        _compile_patterns()

    # Check domain
    for pattern in _domain_patterns:
        if pattern.match(host):
            return False

    # Check path
    for pattern in _path_patterns:
        if pattern.match(path):
            return False

    # Capture everything else! No content-type filtering.
    # APIs use all kinds of content types: json, xml, form-encoded,
    # text/plain, custom types, or even no content-type at all.
    return True


def should_capture_with_config(
    host: str,
    path: str,
    content_type: str | None = None,
    config: "Config" = None,
) -> bool:
    """Determine if request should be captured, using config for filtering.

    Args:
        host: Request hostname
        path: Request path
        content_type: Response content type
        config: MOTIM config with capture settings

    Returns:
        True if the request should be captured
    """
    if config is None:
        return should_capture(host, path, content_type)

    # Check against config's skip_domains
    for pattern in config.capture.skip_domains:
        # Convert glob to check
        if pattern.startswith("*."):
            # Subdomain wildcard
            suffix = pattern[1:]  # .example.com
            if host.endswith(suffix) or host == pattern[2:]:
                return False
        elif fnmatch.fnmatch(host, pattern):
            return False

    # Still apply path filtering
    global _path_patterns
    if _path_patterns is None:
        _compile_patterns()

    for pattern in _path_patterns:
        if pattern.match(path):
            return False

    return True
