"""Generic deterministic format detectors: email, URL and IP address."""

from __future__ import annotations

import re

from .base import RegexDetector

# ASCII-only boundaries: \w is Unicode-aware in Python 3, so it would treat
# CJK characters as word characters and swallow emails adjacent to Chinese
# text ("邮箱zhang@example.com"). Anchor on ASCII word chars instead.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9._%+-])"
)


class EmailDetector(RegexDetector):
    """Detects email addresses in ASCII text."""

    name = "email"
    pattern = _EMAIL_RE
    fact_type = "EMAIL"
    confidence = 1.0


_URL_RE = re.compile(
    r"https?://[^\s<>'\"，。；;]+",
    re.IGNORECASE,
)


class UrlDetector(RegexDetector):
    """Detects absolute HTTP(S) URLs, which may carry identifiers in paths."""

    name = "url"
    pattern = _URL_RE
    fact_type = "URL"
    confidence = 1.0


_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)


class IpAddressDetector(RegexDetector):
    """Detects syntactically valid IPv4 addresses."""

    name = "ipv4"
    pattern = _IPV4_RE
    fact_type = "IP_ADDRESS"
    confidence = 1.0
