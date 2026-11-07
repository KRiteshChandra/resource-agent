"""
safe_downloader.py
-------------------
Turns an APPROVED candidate into files inside a quarantine folder, safely.
Plain deterministic Python: the LLM never calls into this module, and it never
touches the database (the download endpoint does that).

    downloader = SafeDownloader()
    result = downloader.download(candidate, approved_version, download_id, max_bytes)

What it does
  * Fetches by the EXACT approved commit id, never "main". Even if the source changes
    between the approval check and the download, we still get the approved content (T2).
  * GitHub: one zip of the repo at that commit (api.github.com -> codeload.github.com).
    Hugging Face: lists the dataset's files at that commit, then downloads up to MAX_FILES
    supported files (csv/tsv/json/jsonl/txt/md/pdf/png/jpg/parquet) that fit the size budget.
  * Every URL goes through UrlValidator BEFORE each request, and every redirect hop is
    re-validated (T3). Auth tokens are sent only on the first request to the provider's own
    API host, never forwarded to a redirect target such as a CDN.
  * Size is enforced while streaming on DECODED bytes, so a missing/lying Content-Length or a
    gzip bomb cannot get past it (T6). There is also a wall-clock limit (slow-loris).
  * Files are written as random names + a fixed safe extension (never the remote name),
    chmod 600, into quarantine/<download_id>/ (T4). Remote names are kept only as sanitized
    display text.
  * The file's real type is checked from its first bytes. Executables, HTML pages (e.g. a
    corporate proxy login page) and any file whose content does not match what we expected
    are rejected, and the WHOLE download fails closed with the partial files deleted.
  * Nothing is ever extracted or executed here. Zip safety (archive bombs, path traversal) is
    checked by the file inspector before anything is opened.

SHA-256: one file -> that file's hash. Several files -> "bundle hash" = sha256 of the lines
"<sha256> <size> <name>" sorted and joined with newlines.
"""

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote

import httpx

from app.services.security_validator import (
    HARD_MAX_BYTES, ByteCounter, SizeLimitError, UnsafeURLError, UrlValidator,
    check_declared_size,
)
from app.services.version_resolver import (
    is_pinned, parse_github_url, parse_huggingface_dataset_url,
)

DEFAULT_QUARANTINE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "quarantine"))

MAX_FILES = 10                        # Hugging Face: at most this many files per download
MAX_SECONDS = 300                     # wall-clock limit for the whole download
LISTING_MAX_BYTES = 5 * 1024 * 1024   # cap on the Hugging Face file-listing JSON
CHUNK_SIZE = 64 * 1024
HEAD_BYTES = 8192                     # first bytes kept for type detection
USER_AGENT = "ai-resource-agent/0.1"
REDIRECT_CODES = (301, 302, 303, 307, 308)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\\]")

# Hugging Face files we accept, by extension -> the content type we expect to see.
EXT_TO_TYPE = {
    ".csv": "text", ".tsv": "text", ".txt": "text", ".md": "text",
    ".json": "text", ".jsonl": "text",
    ".pdf": "pdf", ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".parquet": "parquet",
}
TEXT_EXTENSIONS = {e for e, t in EXT_TO_TYPE.items() if t == "text"}
TYPE_EXT = {"zip": ".zip", "pdf": ".pdf", "png": ".png", "jpeg": ".jpg", "parquet": ".parquet"}
_DATA_EXT = {".csv", ".tsv", ".json", ".jsonl", ".parquet"}

_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
          b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


class DownloadError(Exception):
    """The download was refused or failed. The message is safe to show the user."""

    def __init__(self, message: str, notes: Optional[dict] = None):
        super().__init__(message)
        self.notes = notes or {}


@dataclass
class StoredFile:
    path: str            # absolute path inside quarantine
    stored_name: str     # random name + safe extension
    original_name: str   # sanitized, display only
    size: int
    sha256: str
    detected_type: str   # text | zip | pdf | png | jpeg | parquet
    format: str          # csv | json | md | zip | pdf | ...


@dataclass
class DownloadResult:
    directory: str
    files: list
    total_bytes: int
    sha256: str
    detected_format: str
    notes: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Content-type detection from the first bytes (T4)
# ---------------------------------------------------------------------------

def _is_pe(head: bytes) -> bool:
    """Windows executable: 'MZ' AND a 'PE\\0\\0' header where the DOS header points to it."""
    if len(head) < 64:
        return False
    offset = int.from_bytes(head[0x3C:0x40], "little")
    return offset + 4 <= len(head) and head[offset:offset + 4] == b"PE\x00\x00"


def _looks_like_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    sample = head.rstrip(b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f")  # ignore a cut-off multibyte tail
    controls = sum(1 for b in sample if b < 9 or 13 < b < 32 or b == 127)
    return controls <= max(1, len(sample) // 100)


def detect_file_type(head: bytes) -> str:
    """
    Returns one of: empty, executable, zip, pdf, png, jpeg, gif, webp, parquet, gzip,
    archive, html, text, binary. Never trusts file extensions or Content-Type headers.
    """
    if not head:
        return "empty"
    if (head.startswith(b"MZ") and _is_pe(head)) or head.startswith(b"\x7fELF") \
            or head[:4] in _MACHO or head.startswith(b"#!"):
        return "executable"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"PAR1"):
        return "parquet"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\xfd7zXZ\x00")) \
            or (head.startswith(b"BZh") and head[4:10] == b"1AY&SY"):
        return "archive"
    if _looks_like_text(head):
        probe = head[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
        if probe.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
            return "html"
        return "text"
    return "binary"


def _display_name(text: str) -> str:
    return (re.sub(r"[^A-Za-z0-9._/-]", "_", text or "")[:150]) or "file"


def _safe_repo_path(path) -> bool:
    """A file path from a provider listing: relative, no traversal, no control chars."""
    if not isinstance(path, str) or not path or len(path) > 300 or _CONTROL.search(path):
        return False
    if path.startswith("/"):
        return False
    return all(seg not in ("", ".", "..") for seg in path.split("/"))


class SafeDownloader:
    def __init__(self, quarantine_dir: str = DEFAULT_QUARANTINE_DIR,
                 validator: Optional[UrlValidator] = None,
                 github_token: Optional[str] = None, hf_token: Optional[str] = None,
                 max_files: int = MAX_FILES, max_seconds: float = MAX_SECONDS,
                 timeout: float = 30.0,
                 transport: Optional[httpx.BaseTransport] = None,   # tests only
                 clock: Callable[[], float] = time.monotonic):      # tests only
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.validator = validator or UrlValidator()
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.hf_token = hf_token or os.getenv("HF_TOKEN")
        self.max_files = max_files
        self.max_seconds = max_seconds
        self.timeout = timeout
        self._transport = transport
        self._clock = clock

    # ------------------------------------------------------------------ public
    def download(self, candidate: dict, approved_version: str, download_id: str,
                 max_bytes: int = HARD_MAX_BYTES) -> DownloadResult:
        if not isinstance(download_id, str) or not _UUID.match(download_id):
            raise DownloadError("Invalid download id")
        if not is_pinned(approved_version):
            raise DownloadError("Refusing to download: the approved version is not an exact commit id")
        provider = candidate.get("provider")
        if provider not in ("github", "huggingface"):
            raise DownloadError(f"Downloading from provider '{provider}' is not supported")
        try:
            budget = min(int(max_bytes), HARD_MAX_BYTES)
        except (TypeError, ValueError):
            raise DownloadError("Invalid size limit")
        if budget <= 0:
            raise DownloadError("Invalid size limit")

        notes: dict = {"revision": approved_version, "provider": provider, "redirects": []}
        dest = os.path.join(self.quarantine_dir, download_id)
        try:
            os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
            os.makedirs(dest, mode=0o700, exist_ok=False)
        except FileExistsError:
            raise DownloadError("This download id already exists")
        except OSError:
            raise DownloadError("Could not create the quarantine folder")

        deadline = self._clock() + self.max_seconds
        try:
            with httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0),
                              follow_redirects=False, transport=self._transport) as client:
                if provider == "github":
                    files = self._github(client, candidate, approved_version, dest, budget, deadline, notes)
                else:
                    files = self._huggingface(client, candidate, approved_version, dest, budget, deadline, notes)
        except DownloadError as exc:
            shutil.rmtree(dest, ignore_errors=True)
            exc.notes = {**notes, **exc.notes}
            raise
        except UnsafeURLError as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise DownloadError(f"Blocked by security check: {exc}", notes)
        except SizeLimitError as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise DownloadError(f"Size limit: {exc}", notes)
        except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError):
            shutil.rmtree(dest, ignore_errors=True)
            raise DownloadError("Network error while downloading (provider unreachable or the "
                                "connection was interrupted)", notes)
        except OSError:
            shutil.rmtree(dest, ignore_errors=True)
            raise DownloadError("Could not write to the quarantine folder", notes)
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise

        total = sum(f.size for f in files)
        notes["signature_checks"] = "passed"
        notes["files_downloaded"] = len(files)
        return DownloadResult(
            directory=dest, files=files, total_bytes=total,
            sha256=self._bundle_hash(files),
            detected_format=",".join(sorted({f.format for f in files})),
            notes=notes,
        )

    # --------------------------------------------------------------- providers
    def _github(self, client, candidate, sha, dest, budget, deadline, notes) -> list:
        parsed = parse_github_url(candidate.get("source_url") or "")
        if not parsed:
            raise DownloadError("Unsupported or malformed GitHub URL on this resource")
        owner, repo = parsed
        url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{sha}"
        stored = self._download_one(client, url, dest, f"{repo}-{sha[:7]}.zip", "zip",
                                    budget, deadline, notes, self.github_token, "api.github.com")
        return [stored]

    def _huggingface(self, client, candidate, sha, dest, budget, deadline, notes) -> list:
        dataset_id = parse_huggingface_dataset_url(candidate.get("source_url") or "")
        if not dataset_id:
            raise DownloadError("Unsupported or malformed Hugging Face URL on this resource")

        # 1) list the files at the approved commit
        listing_url = f"https://huggingface.co/api/datasets/{dataset_id}/tree/{sha}?recursive=true"
        buf = bytearray()
        _, headers = self._fetch(client, listing_url, LISTING_MAX_BYTES, buf.extend, deadline,
                                 notes, self.hf_token, "huggingface.co")
        try:
            items = json.loads(bytes(buf))
        except ValueError:
            raise DownloadError("Hugging Face returned an unreadable file listing")
        if not isinstance(items, list):
            raise DownloadError("Hugging Face returned an unexpected file listing")
        notes["listing_truncated"] = 'rel="next"' in (headers.get("link") or "")

        # 2) choose files: supported type, safe path, fits the budget, at most max_files
        skipped: list = []
        candidates = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "file":
                continue
            path = item.get("path")
            if not _safe_repo_path(path):
                skipped.append({"path": _display_name(str(path)), "reason": "unsafe path"})
                continue
            ext = os.path.splitext(path)[1].lower()
            if ext not in EXT_TO_TYPE:
                skipped.append({"path": _display_name(path), "reason": "unsupported file type"})
                continue
            size = (item.get("lfs") or {}).get("size", item.get("size"))
            size = size if isinstance(size, int) and size >= 0 else None
            priority = 0 if path == "README.md" else (1 if ext in _DATA_EXT else 2)
            candidates.append((priority, path, ext, size))
        candidates.sort(key=lambda c: (c[0], c[1]))

        chosen, planned = [], 0
        for priority, path, ext, size in candidates:
            if len(chosen) >= self.max_files:
                skipped.append({"path": _display_name(path), "reason": f"over the {self.max_files}-file limit"})
            elif size is not None and planned + size > budget:
                skipped.append({"path": _display_name(path), "reason": "does not fit the size limit"})
            else:
                chosen.append((path, ext))
                planned += size or 0
        notes["skipped_files"] = skipped[:50]
        if not chosen:
            raise DownloadError("No supported files within the size limit were found in this dataset", notes)

        # 3) download each chosen file at the pinned commit
        stored, used = [], 0
        for path, ext in chosen:
            url = f"https://huggingface.co/datasets/{dataset_id}/resolve/{sha}/{quote(path, safe='/')}"
            one = self._download_one(client, url, dest, path, EXT_TO_TYPE[ext], budget - used,
                                     deadline, notes, self.hf_token, "huggingface.co")
            used += one.size
            stored.append(one)
        return stored

    # ----------------------------------------------------------------- network
    def _fetch(self, client, url, budget, on_chunk, deadline, notes, token, token_host):
        """GET `url` (validating every hop), streaming decoded chunks to on_chunk."""
        target = self.validator.validate_url(url)
        hops = 0
        while True:
            headers = {"User-Agent": USER_AGENT}
            if token and hops == 0 and target.host == token_host:
                headers["Authorization"] = f"Bearer {token}"      # first hop only, never forwarded
            with client.stream("GET", target.url, headers=headers) as resp:
                if resp.status_code in REDIRECT_CODES:
                    target = self.validator.validate_redirect(
                        target.url, resp.headers.get("location"), hops)
                    hops += 1
                    notes["redirects"].append(target.host)
                    continue
                if resp.status_code != 200:
                    raise DownloadError(f"Provider returned HTTP {resp.status_code}")
                check_declared_size(resp.headers.get("content-length"), budget)
                counter = ByteCounter(budget)
                for chunk in resp.iter_bytes(CHUNK_SIZE):
                    counter.add(len(chunk))
                    if self._clock() > deadline:
                        raise DownloadError("Download took too long and was stopped")
                    on_chunk(chunk)
                return counter.total, resp.headers

    def _download_one(self, client, url, dest, original_name, expected_type, budget,
                      deadline, notes, token, token_host) -> StoredFile:
        tmp = os.path.join(dest, uuid.uuid4().hex + ".part")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        digest, head = hashlib.sha256(), bytearray()
        with os.fdopen(os.open(tmp, flags, 0o600), "wb") as fh:
            def on_chunk(chunk: bytes):
                if len(head) < HEAD_BYTES:
                    head.extend(chunk[:HEAD_BYTES - len(head)])
                digest.update(chunk)
                fh.write(chunk)
            size, _ = self._fetch(client, url, budget, on_chunk, deadline, notes, token, token_host)

        shown = _display_name(original_name)
        if size == 0:
            raise DownloadError(f"'{shown}' is empty")
        detected = detect_file_type(bytes(head))
        if detected in ("executable", "html"):
            raise DownloadError(f"'{shown}' was rejected: it looks like "
                                f"{'an executable program' if detected == 'executable' else 'an HTML web page, not data'}")
        if detected != expected_type:
            raise DownloadError(f"'{shown}' was rejected: expected {expected_type} content "
                                f"but the file's contents look like {detected}")

        if detected == "text":
            ext = os.path.splitext(original_name)[1].lower()
            ext = ext if ext in TEXT_EXTENSIONS else ".txt"
            fmt = ext.lstrip(".")
        else:
            ext = TYPE_EXT[detected]
            fmt = detected
        stored_name = uuid.uuid4().hex + ext
        final = os.path.join(dest, stored_name)
        os.replace(tmp, final)
        try:
            os.chmod(final, 0o600)
        except OSError:
            pass
        return StoredFile(path=final, stored_name=stored_name, original_name=shown, size=size,
                          sha256=digest.hexdigest(), detected_type=detected, format=fmt)

    @staticmethod
    def _bundle_hash(files: list) -> str:
        if len(files) == 1:
            return files[0].sha256
        lines = sorted(f"{f.sha256} {f.size} {f.original_name}" for f in files)
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
