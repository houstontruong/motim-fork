"""LinkFinder-style endpoint extraction for JS bundles.

This module embeds the upstream LinkFinder regex (MIT licensed) and exposes a small,
library-friendly API for extracting endpoint/URL strings from JavaScript content.

Upstream: https://github.com/GerbenJavado/LinkFinder (MIT)
"""

from __future__ import annotations

import re
from typing import Iterable

# Regex used by LinkFinder (MIT), kept as-is (whitespace preserved for re.VERBOSE).
_LINKFINDER_REGEX_STR = r"""

 (?:"|') # Start newline delimiter

 (
 ((?:[a-zA-Z]{1,10}://|//) # Match a scheme [a-Z]*1-10 or //
 [^"'/]{1,}\. # Match a domainname (any character + dot)
 [a-zA-Z]{2,}[^"']{0,}) # The domainextension and/or path

 |

 ((?:/|\.\./|\./) # Start with /,../,./
 [^"'><,;| *()(%%$^/\\\[\]] # Next character can't be...
 [^"'><,;|()]{1,}) # Rest of the characters can't be

 |

 ([a-zA-Z0-9_\-/]{1,}/ # Relative endpoint with /
 [a-zA-Z0-9_\-/.]{1,} # Resource name
 \.(?:[a-zA-Z]{1,4}|action) # Rest + extension (length 1-4 or action)
 (?:[\?|#][^"|']{0,}|)) # ? or # mark with parameters

 |

 ([a-zA-Z0-9_\-/]{1,}/ # REST API (no extension) with /
 [a-zA-Z0-9_\-/]{3,} # Proper REST endpoints usually have 3+ chars
 (?:[\?|#][^"|']{0,}|)) # ? or # mark with parameters

 |

 ([a-zA-Z0-9_\-]{1,} # filename
 \.(?:php|asp|aspx|jsp|json|
 action|html|js|txt|xml) # . + extension
 (?:[\?|#][^"|']{0,}|)) # ? or # mark with parameters

 )

 (?:"|') # End newline delimiter

"""

_LINKFINDER_RE = re.compile(_LINKFINDER_REGEX_STR, re.VERBOSE)


def _maybe_beautify_js(content: str) -> str:
    """Best-effort jsbeautifier call.

    LinkFinder beautifies when producing contexts; for plain extraction it isn't required,
    but we keep the option for consistency.
    """
    try:
        import jsbeautifier  # type: ignore[import-not-found]
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "jsbeautifier is required for --beautify. Install with: pip install 'motim[linkfinder]'"
        ) from e
    # LinkFinder skips beautify for huge files; mimic that behavior.
    if len(content) > 1_000_000:
        return content.replace(";", ";\r\n").replace(",", ",\r\n")
    return str(jsbeautifier.beautify(content))


def extract_links(
    content: str,
    *,
    filter_regex: str | None = None,
    beautify: bool = False,
    unique: bool = True,
) -> list[str]:
    """Extract URL/path strings from JS content using LinkFinder regex."""
    if beautify:
        content = _maybe_beautify_js(content)

    out: list[str] = []
    seen: set[str] = set()
    filt = re.compile(filter_regex) if filter_regex else None

    for m in _LINKFINDER_RE.finditer(content):
        link = m.group(1)
        if not link:
            continue
        if filt and not filt.search(link):
            continue
        if unique:
            if link in seen:
                continue
            seen.add(link)
        out.append(link)

    return out


def iter_links(
    content: str,
    *,
    filter_regex: str | None = None,
    beautify: bool = False,
) -> Iterable[str]:
    """Streaming variant of extract_links."""
    for link in extract_links(content, filter_regex=filter_regex, beautify=beautify, unique=False):
        yield link
