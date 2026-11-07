"""
security_validator.py
----------------------
Pre-download safety checks (threat-model T3 SSRF, T6 resource exhaustion).
Plain deterministic Python: the LLM never calls into this module.

What it gives the downloader (next step):

    validator = UrlValidator()
    target = validator.validate_url(url)                      # BEFORE every request
    nxt    = validator.validate_redirect(url, location, n)    # for EVERY redirect hop
    limit  = effective_max_bytes(requirement["max_size_mb"])
    check_declared_size(response.headers.get("content-length"), limit)
    counter = ByteCounter(limit); counter.add(len(chunk))     # while streaming

Rules (all fail CLOSED - when in doubt, block):
  * https only, port 443 only, no user:password@ in the URL
  * host must be on the provider allowlist (GitHub / Hugging Face by default)
  * every IP the host resolves to must be a public, globally routable address;
    if ANY resolved IP is private/loopback/link-local/metadata/etc. the host is blocked
  * redirects are never trusted: each hop is re-validated, max 5 hops
  * size is capped by min(user limit, hard cap) via Content-Length AND a streamed byte count,
    because Content-Length can be missing or lie

Known limit (stated honestly): we check the IPs a hostname resolves to, then the
downloader connects. A hostile DNS server could answer differently the second time
("DNS rebinding"). The host allowlist makes this impractical, since an attacker would
have to control github.com / huggingface.co DNS. Pinning the connection to the checked
IP is a Stage 3 hardening item if the allowlist is ever widened.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional
from urllib.parse import urljoin, urlsplit

MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
HARD_MAX_BYTES = 500 * 1024 * 1024          # 500 MB absolute server-side cap (T6)
ALLOWED_PORTS = (None, 443)

# Hosts the app is allowed to download from. Subdomains are allowed (codeload.github.com,
# objects.githubusercontent.com, cdn-lfs.huggingface.co, ...). To allow another source,
# add its domain here (or pass `allowed_host_suffixes=` to UrlValidator).
DEFAULT_ALLOWED_HOST_SUFFIXES = (
    "github.com",
    "githubusercontent.com",
    "huggingface.co",
    "hf.co",
)

# Ranges that Python's `is_global` may treat as public but that can smuggle in private
# IPv4 addresses (NAT64 / 6to4 / Teredo), so we block them outright.
_EXTRA_BLOCKED_V6 = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
))

_BAD_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")      # control chars, whitespace, backslash
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


class UnsafeURLError(Exception):
    """The URL (or a redirect target) failed a safety check. Message is user-safe."""


class SizeLimitError(Exception):
    """The download is (or became) larger than the allowed size."""


def default_resolver(host: str, port: int) -> list[str]:
    """Return every IP address the OS resolver gives for `host`."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0].split("%")[0] for info in infos})


def check_ip_is_public(ip_text: str) -> None:
    """Raise UnsafeURLError unless `ip_text` is a public, globally routable address."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        raise UnsafeURLError(f"'{ip_text}' is not a valid IP address")

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped                       # ::ffff:127.0.0.1 is really 127.0.0.1

    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _EXTRA_BLOCKED_V6):
        raise UnsafeURLError(f"Blocked address {ip}: IPv6 translation range")
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local \
            or ip.is_private or ip.is_reserved or not ip.is_global:
        raise UnsafeURLError(f"Blocked address {ip}: not a public internet address")


def _legacy_ipv4(host: str) -> Optional[str]:
    """
    Catch tricks like 2130706433, 0x7f000001, 127.1, 0177.0.0.1 which many network
    stacks treat as 127.0.0.1. Returns the dotted IPv4 string or None if not numeric.
    """
    if not re.fullmatch(r"[0-9a-fx.]+", host):
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


@dataclass
class ValidatedTarget:
    url: str
    host: str
    port: int
    ips: list = field(default_factory=list)

    def notes(self) -> dict:
        """Safe to store in downloads.validation_notes."""
        return {"url_checks": "passed", "host": self.host, "port": self.port,
                "resolved_ips": self.ips}


class UrlValidator:
    def __init__(self, allowed_host_suffixes: Optional[Iterable[str]] = DEFAULT_ALLOWED_HOST_SUFFIXES,
                 resolver: Callable[[str, int], list] = default_resolver,
                 max_redirects: int = MAX_REDIRECTS):
        # None disables the allowlist (the public-IP checks still apply).
        self.allowed = tuple(s.lower().lstrip(".") for s in allowed_host_suffixes) \
            if allowed_host_suffixes is not None else None
        self.resolver = resolver
        self.max_redirects = max_redirects

    # ----- main entry point -------------------------------------------------
    def validate_url(self, url: str) -> ValidatedTarget:
        if not isinstance(url, str) or not url:
            raise UnsafeURLError("Empty URL")
        if len(url) > MAX_URL_LENGTH:
            raise UnsafeURLError("URL is too long")
        if _BAD_URL_CHARS.search(url) or not url.isascii():
            raise UnsafeURLError("URL contains whitespace, control, backslash or non-ASCII characters")

        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise UnsafeURLError("URL could not be parsed")

        if parts.scheme.lower() != "https":
            raise UnsafeURLError("Only https:// URLs are allowed")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise UnsafeURLError("URLs containing credentials (user@host) are not allowed")
        if port not in ALLOWED_PORTS:
            raise UnsafeURLError(f"Port {port} is not allowed (only 443)")

        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise UnsafeURLError("URL has no host")

        ips = self._resolve_and_check(host, port or 443)
        return ValidatedTarget(url=url, host=host, port=port or 443, ips=ips)

    def validate_redirect(self, current_url: str, location: Optional[str],
                          redirects_followed: int) -> ValidatedTarget:
        """Validate a Location header. `redirects_followed` = hops already taken."""
        if redirects_followed >= self.max_redirects:
            raise UnsafeURLError(f"Too many redirects (limit {self.max_redirects})")
        if not location:
            raise UnsafeURLError("Redirect without a Location header")
        return self.validate_url(urljoin(current_url, location.strip()))

    # ----- internals --------------------------------------------------------
    def _host_allowed(self, host: str) -> bool:
        if self.allowed is None:
            return True
        return any(host == s or host.endswith("." + s) for s in self.allowed)

    def _resolve_and_check(self, host: str, port: int) -> list:
        # 1) IP literals / legacy numeric forms: check directly, never resolve.
        literal = None
        if ":" in host:                                   # IPv6 literal (brackets already stripped)
            literal = host
        else:
            literal = host if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) else _legacy_ipv4(host)
        if literal is not None:
            check_ip_is_public(literal)                   # blocks private/loopback/metadata
            if not self._host_allowed(host):
                raise UnsafeURLError("Downloads from raw IP addresses are not allowed")
            return [literal]

        # 2) Normal hostname: shape check -> allowlist -> DNS -> every IP must be public.
        if not _HOSTNAME.match(host):
            raise UnsafeURLError(f"Invalid host name '{host}'")
        if not self._host_allowed(host):
            raise UnsafeURLError(
                f"Host '{host}' is not on the download allowlist. If it is a legitimate "
                f"source or CDN, add its domain to DEFAULT_ALLOWED_HOST_SUFFIXES.")
        try:
            ips = list(self.resolver(host, port))
        except (OSError, UnicodeError):
            raise UnsafeURLError(f"Could not resolve host '{host}'")
        if not ips:
            raise UnsafeURLError(f"Host '{host}' resolved to no addresses")
        for ip in ips:                                    # ALL must be public, not just one
            check_ip_is_public(ip)
        return ips


# ---------------------------------------------------------------------------
# Size limits (T6)
# ---------------------------------------------------------------------------

def effective_max_bytes(max_size_mb: Optional[int], hard_cap: int = HARD_MAX_BYTES) -> int:
    """min(user's limit, server hard cap). No or non-positive user limit -> hard cap."""
    if not max_size_mb or max_size_mb <= 0:
        return hard_cap
    return min(int(max_size_mb) * 1024 * 1024, hard_cap)


def check_declared_size(content_length: Optional[str], max_bytes: int) -> Optional[int]:
    """
    Early reject using the Content-Length header. Returns the declared size, or None when
    the header is missing/invalid (that is fine ONLY because ByteCounter enforces the cap
    while streaming, so the header is never relied on).
    """
    if content_length is None:
        return None
    try:
        declared = int(str(content_length).strip())
    except ValueError:
        return None
    if declared < 0:
        return None
    if declared > max_bytes:
        raise SizeLimitError(
            f"Declared size {declared} bytes exceeds the limit of {max_bytes} bytes")
    return declared


class ByteCounter:
    """Call add(len(chunk)) for every streamed chunk; raises the moment the cap is crossed."""

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self.total = 0

    def add(self, n: int) -> int:
        self.total += n
        if self.total > self.max_bytes:
            raise SizeLimitError(
                f"Download exceeded the limit of {self.max_bytes} bytes (stopped at {self.total})")
        return self.total
