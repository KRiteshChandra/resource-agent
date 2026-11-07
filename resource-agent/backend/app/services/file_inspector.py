"""
file_inspector.py
------------------
Looks inside the files the safe downloader put in quarantine and produces the inspection
report (architecture.md 2.8). It is also the place where zip archives are checked for
archive bombs and path traversal BEFORE anyone unpacks them (threat T4, T5).

Contract with routers/downloads.py (already written; this file is picked up automatically):

    inspect_download(files: list[StoredFile]) -> {
        "format":         "csv,md"            # same style as detected_format
        "schema_preview": {"files": [...], "total_warnings": n}
        "record_count":   int | None
        "encoding":       "utf-8" | "ascii" | "mixed" | ... | None
    }
    Raises InspectionError when a file is unsafe or cannot be processed. The download endpoint
    then sets the status to "quarantined": files are kept but NOT usable.

What is rejected (raise) vs reported (warning)
    Rejected:  anything unsafe or structurally broken in BINARY formats: zip path traversal /
               absolute paths / backslashes / ':' in names / special files / unsafe symlinks /
               duplicate names / encrypted entries / overlapping entries / bomb-like sizes or
               ratios / corrupt or lying archive data; PNG/JPEG that are truncated, corrupt, or
               declare more than 100 million pixels; Parquet without a valid footer; a file that
               changed after download.
    Warned:    things worth knowing but not proof of danger: malformed CSV/JSON/JSONL (a data
               quality problem, not a security one), executables/scripts or nested archives inside
               a zip (never run by this app), PDF active-content markers, EXIF metadata, data
               appended after an image, scans cut short by the size/time limits.

Safety rules of this module
  * Nothing is ever extracted, executed or evaluated. Zips are read through Python's zipfile
    streaming API only (never extractall), and only to verify sizes/CRCs and read tiny previews.
  * No third-party parsers (no pandas / pyarrow / Pillow / PDF libraries) are run on untrusted
    files: formats are parsed by small, bounded, standard-library code. Consequence: Parquet
    schema/row count are NOT read, and PDF page counts are estimates (see each report's notes).
  * Every scan has a size cap and a shared time budget. Text counting stops early (reported as
    scan_complete=false, record_count=null); binary verification that runs out of time rejects.
  * Text taken from inside the files (column names, file names, README preview) is untrusted: it
    is stripped of control and bidirectional-override characters and truncated. The frontend must
    still display it as plain text (React does this by default; never use innerHTML).

Limits are constants at the top of this file; raise them deliberately if you need to.
"""

import codecs
import csv
import io
import json
import os
import posixpath
import re
import stat
import struct
import time
import zipfile
import zlib
from collections import Counter, defaultdict
from typing import Callable, Optional

from app.services.safe_downloader import HEAD_BYTES as DETECT_BYTES
from app.services.safe_downloader import detect_file_type

# ----------------------------------------------------------------------------- limits
MAX_INSPECT_SECONDS = 120               # shared by all files of one download
CHUNK = 64 * 1024
TEXT_HEAD_BYTES = 64 * 1024             # sample used to detect encoding / delimiter
SAMPLE_ROWS = 1000                      # rows/items sampled for types and fields
MAX_SCAN_BYTES = 100 * 1024 * 1024      # text counting stops after this many bytes
MAX_JSON_PARSE_BYTES = 20 * 1024 * 1024  # bigger .json files are not parsed (memory)
MAX_LINE_BYTES = 4 * 1024 * 1024        # longer JSONL/text lines are counted, not parsed
MAX_COLUMNS_SHOWN = 100
MAX_FIELDS_SHOWN = 50
MAX_PIXELS = 100_000_000                # image "decompression bomb" guard
MAX_PNG_CHUNKS = 100_000
MAX_PDF_SCAN = 50 * 1024 * 1024         # bigger PDFs: only first/last 1 MiB are scanned

# zip
MAX_ENTRIES = 20_000
MAX_UNCOMPRESSED_TOTAL = 1024 * 1024 * 1024   # 1 GiB when unpacked
RATIO_MIN_ENTRY = 1024 * 1024                  # per-entry ratio check applies above 1 MiB ...
MAX_ENTRY_RATIO = 200                          # ... to entries compressing better than 200:1
RATIO_MIN_TOTAL = 100 * 1024 * 1024            # whole-archive ratio check applies above 100 MiB
MAX_TOTAL_RATIO = 100
MAX_PATH_LEN = 1024
MAX_SYMLINK_TARGET = 1024

DATA_FORMATS = {"csv", "tsv", "json", "jsonl", "zip"}   # these feed the top-level record_count


class InspectionError(Exception):
    """The file is unsafe or cannot be processed. The message is safe to show to the user."""


# ----------------------------------------------------------------------------- helpers
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_BIDI = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value, limit: int = 100) -> str:
    """Make untrusted text safe to display: no control / bidi-override characters, truncated."""
    return _UNSAFE_TEXT.sub("?", str(value))[:limit]


class _Budget:
    """Shared wall-clock budget. `clock` is injectable for tests."""

    def __init__(self, seconds: float, clock: Callable[[], float]):
        self._clock = clock
        self._deadline = clock() + seconds

    def expired(self) -> bool:
        return self._clock() > self._deadline


def _open_nofollow(path: str):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags), "rb")


def _result(record_count, record_unit, encoding, details, warnings) -> dict:
    return {"record_count": record_count, "record_unit": record_unit, "encoding": encoding,
            "details": details, "warnings": warnings}


# ----------------------------------------------------------------------------- text helpers
def _detect_encoding(head: bytes) -> str:
    """Detected from the first 64 KB only."""
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.isascii():
        return "ascii"
    try:
        codecs.getincrementaldecoder("utf-8")().decode(head, final=False)
        return "utf-8"
    except UnicodeDecodeError:
        return "latin-1 (assumed)"


def _codec(encoding: str) -> str:
    return {"utf-8-sig": "utf-8-sig", "ascii": "utf-8", "utf-8": "utf-8"}.get(encoding, "latin-1")


def _iter_lines(fh, max_line: int):
    """
    Yields each line as bytes, or None for a line longer than max_line (the rest of that line
    is skipped without being kept in memory).
    """
    while True:
        line = fh.readline(max_line)
        if not line:
            return
        if len(line) == max_line and not line.endswith(b"\n"):
            while True:
                rest = fh.readline(max_line)
                if not rest or rest.endswith(b"\n"):
                    break
            yield None
        else:
            yield line


_INT = re.compile(r"^[+-]?\d+$")
_FLOAT = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")


def _kind(value: str) -> str:
    v = value.strip()
    if v == "":
        return "empty"
    if _INT.match(v):
        return "int"
    if _FLOAT.match(v):
        return "float"
    if v.lower() in ("true", "false"):
        return "bool"
    return "text"


def _column_type(kinds: set) -> str:
    kinds = kinds - {"empty"}
    if not kinds:
        return "empty"
    if len(kinds) == 1:
        return next(iter(kinds))
    if kinds == {"int", "float"}:
        return "float"
    return "text"


def _looks_like_header(row: list) -> bool:
    """Heuristic: every field non-empty, all distinct, none numeric."""
    vals = [v.strip() for v in row]
    return all(vals) and len(set(vals)) == len(vals) and not any(_kind(v) in ("int", "float") for v in vals)


_DELIMITERS = {",": "comma", "\t": "tab", ";": "semicolon", "|": "pipe"}


def _sniff_delimiter(sample_text: str, force_tab: bool) -> str:
    if force_tab:
        return "\t"
    sample = sample_text[: sample_text.rfind("\n") + 1] or sample_text
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _jtype(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


class _FieldStats:
    """Collects which keys appear in sampled JSON objects, and with what value types."""

    def __init__(self):
        self.counts = Counter()
        self.types = defaultdict(set)
        self.item_types = Counter()

    def add(self, item) -> None:
        self.item_types[_jtype(item)] += 1
        if isinstance(item, dict):
            for key, value in item.items():
                self.counts[key] += 1
                self.types[key].add(_jtype(value))

    def summary(self) -> dict:
        fields = sorted(self.counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[:MAX_FIELDS_SHOWN]
        return {
            "item_types": dict(self.item_types),
            "fields": [{"name": _clean(k, 80), "types": sorted(self.types[k]), "present_in": c}
                       for k, c in fields],
            "field_count": len(self.counts),
        }


# ----------------------------------------------------------------------------- CSV / TSV
def _inspect_csv(fh, f, budget, force_tab: bool) -> dict:
    head = fh.read(TEXT_HEAD_BYTES)
    fh.seek(0)
    encoding = _detect_encoding(head)
    codec = _codec(encoding)
    delimiter = _sniff_delimiter(head.decode(codec, errors="replace"), force_tab)

    text = io.TextIOWrapper(fh, encoding=codec, errors="replace", newline="")
    reader = csv.reader(text, delimiter=delimiter)
    warnings: list = []
    rows = ragged = 0
    first = None
    header = False
    kinds: list = []
    scan_complete = True
    try:
        for i, row in enumerate(reader):
            if not row:
                continue
            if first is None:
                first = row
                header = _looks_like_header(row)
                kinds = [set() for _ in row]
                if header:
                    continue
            rows += 1
            if len(row) != len(first):
                ragged += 1
            if rows <= SAMPLE_ROWS:
                for j, value in enumerate(row[:len(kinds)]):
                    kinds[j].add(_kind(value))
            if i % 1000 == 0 and (fh.tell() > MAX_SCAN_BYTES or budget.expired()):
                scan_complete = False
                break
    except csv.Error as exc:
        scan_complete = False
        warnings.append(f"CSV parsing stopped early: {_clean(exc, 80)}")
    finally:
        text.detach()

    if first is None:
        warnings.append("The file contains no rows.")
        columns, column_count = [], 0
    else:
        column_count = len(first)
        names = [_clean(v, 80) for v in first] if header else [f"col_{j + 1}" for j in range(column_count)]
        columns = [{"name": names[j], "type": _column_type(kinds[j])}
                   for j in range(min(column_count, MAX_COLUMNS_SHOWN))]
    if ragged:
        warnings.append(f"{ragged} row(s) have a different number of fields than the first row.")
    if not scan_complete:
        warnings.append("Row counting stopped early (size or time limit); the record count is unknown.")

    details = {"delimiter": _DELIMITERS.get(delimiter, delimiter), "header_detected": header,
               "header_note": "heuristic: all first-row fields non-empty, distinct and non-numeric",
               "column_count": column_count, "columns": columns, "ragged_rows": ragged,
               "scan_complete": scan_complete, "rows_counted": rows,
               "types_sampled_from_rows": min(rows, SAMPLE_ROWS)}
    return _result(rows if scan_complete else None, "rows", encoding, details, warnings)


# ----------------------------------------------------------------------------- JSON
def _inspect_json(fh, f, budget) -> dict:
    head = fh.read(TEXT_HEAD_BYTES)
    fh.seek(0)
    encoding = _detect_encoding(head)
    warnings: list = []
    first_char = head.lstrip(b"\xef\xbb\xbf \t\r\n")[:1]
    guess = {b"[": "array", b"{": "object"}.get(first_char, "other")

    if f.size > MAX_JSON_PARSE_BYTES:
        warnings.append(f"File is larger than {MAX_JSON_PARSE_BYTES // (1024 * 1024)} MB, so it was not parsed.")
        return _result(None, "items", encoding,
                       {"parsed": False, "valid_json": None, "top_level_type_guess": guess}, warnings)

    try:
        data = json.loads(fh.read().decode(_codec(encoding), errors="replace"))
    except (ValueError, RecursionError) as exc:
        reason = "nested too deeply" if isinstance(exc, RecursionError) else _clean(exc, 100)
        warnings.append(f"Not valid JSON: {reason}")
        return _result(None, "items", encoding, {"parsed": False, "valid_json": False}, warnings)

    details = {"parsed": True, "valid_json": True, "top_level_type": _jtype(data)}
    count = None
    if isinstance(data, list):
        count = len(data)
        stats = _FieldStats()
        for item in data[:SAMPLE_ROWS]:
            stats.add(item)
        details["items_sampled"] = min(count, SAMPLE_ROWS)
        details.update(stats.summary())
    elif isinstance(data, dict):
        details["key_count"] = len(data)
        details["keys"] = [_clean(k, 80) for k in list(data)[:MAX_FIELDS_SHOWN]]
    return _result(count, "items", encoding, details, warnings)


# ----------------------------------------------------------------------------- JSONL
def _inspect_jsonl(fh, f, budget) -> dict:
    head = fh.read(TEXT_HEAD_BYTES)
    fh.seek(0)
    encoding = _detect_encoding(head)
    codec = _codec(encoding)
    lines = non_empty = parsed = invalid = overlong = 0
    stats = _FieldStats()
    scan_complete = True
    for line in _iter_lines(fh, MAX_LINE_BYTES):
        lines += 1
        if line is None:
            overlong += 1
            non_empty += 1
            continue
        stripped = line.strip()
        if stripped:
            non_empty += 1
            if parsed + invalid < SAMPLE_ROWS:
                try:
                    obj = json.loads(stripped.decode(codec, errors="replace"))
                except (ValueError, RecursionError):
                    invalid += 1
                else:
                    parsed += 1
                    stats.add(obj)
        if lines % 1000 == 0 and (fh.tell() > MAX_SCAN_BYTES or budget.expired()):
            scan_complete = False
            break

    warnings: list = []
    if invalid:
        warnings.append(f"{invalid} of the first {parsed + invalid} lines are not valid JSON.")
    if overlong:
        warnings.append(f"{overlong} line(s) longer than {MAX_LINE_BYTES // (1024 * 1024)} MB were counted but not parsed.")
    if not scan_complete:
        warnings.append("Counting stopped early (size or time limit); the record count is unknown.")
    if non_empty == 0:
        warnings.append("The file contains no records.")
    details = {"lines_sampled": parsed + invalid, "invalid_lines_in_sample": invalid,
               "overlong_lines": overlong, "scan_complete": scan_complete, **stats.summary()}
    return _result(non_empty if scan_complete else None, "lines", encoding, details, warnings)


# ----------------------------------------------------------------------------- TXT / MD
def _inspect_plain(fh, f, budget, is_markdown: bool) -> dict:
    head = fh.read(TEXT_HEAD_BYTES)
    fh.seek(0)
    encoding = _detect_encoding(head)
    codec = _codec(encoding)
    lines = non_empty = longest = 0
    title = None
    scan_complete = True
    for line in _iter_lines(fh, MAX_LINE_BYTES):
        lines += 1
        if line is None:
            non_empty += 1
            longest = max(longest, MAX_LINE_BYTES)
            continue
        longest = max(longest, len(line.rstrip(b"\r\n")))
        if line.strip():
            non_empty += 1
        if is_markdown and title is None and line.startswith(b"# "):
            title = _clean(line[2:].decode(codec, errors="replace").strip(), 120)
        if lines % 1000 == 0 and (fh.tell() > MAX_SCAN_BYTES or budget.expired()):
            scan_complete = False
            break
    warnings = [] if scan_complete else ["Counting stopped early (size or time limit); the line count is unknown."]
    details = {"lines": lines, "non_empty_lines": non_empty, "longest_line_bytes": longest,
               "scan_complete": scan_complete}
    if is_markdown:
        details["title"] = title
    return _result(lines if scan_complete else None, "lines", encoding, details, warnings)


# ----------------------------------------------------------------------------- ZIP
_SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
_PROGRAM_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".com", ".jar",
                ".sh", ".so", ".dylib", ".apk"}
_ARCHIVE_EXT = {".zip", ".jar", ".war", ".whl", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst"}
_README_RE = re.compile(r"^readme(\.(md|markdown|txt|rst))?$")
_LICENSE_RE = re.compile(r"^(licen[sc]e|copying|unlicense)([._-].*)?$")
_RESERVED_RE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$")


def _check_entry_name(name: str) -> None:
    shown = _clean(name, 80)
    if not name.strip("/"):
        raise InspectionError("the archive has an entry with an empty name")
    if len(name) > MAX_PATH_LEN:
        raise InspectionError(f"an entry name is longer than {MAX_PATH_LEN} characters")
    if _CONTROL_CHARS.search(name):
        raise InspectionError(f"entry '{shown}' has control characters in its name")
    if "\\" in name:
        raise InspectionError(f"entry '{shown}' contains a backslash (not safe to unpack on Windows)")
    if name.startswith("/"):
        raise InspectionError(f"entry '{shown}' has an absolute path")
    for part in name.split("/"):
        if part == "..":
            raise InspectionError(f"entry '{shown}' tries to escape the extraction folder (path traversal)")
        if ":" in part:
            raise InspectionError(f"entry '{shown}' contains ':' (drive letter / alternate data stream risk on Windows)")


def _check_symlink(zf, info) -> None:
    shown = _clean(info.filename, 80)
    if not 0 < info.file_size <= MAX_SYMLINK_TARGET:
        raise InspectionError(f"symbolic link '{shown}' has an invalid size")
    target = zf.read(info).decode("utf-8", errors="replace")
    if not target or "\x00" in target or "\\" in target or ":" in target or target.startswith("/"):
        raise InspectionError(f"symbolic link '{shown}' points to an unsafe target")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(info.filename), target))
    if resolved == ".." or resolved.startswith("../"):
        raise InspectionError(f"symbolic link '{shown}' points outside the archive")


def _verify_entry(zf, info, budget) -> bytes:
    """Stream the entry through zipfile (checks CRC and size). Returns its first 1024 bytes."""
    count = 0
    first = b""
    try:
        with zf.open(info) as src:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                if len(first) < 1024:
                    first = (first + chunk)[:1024]
                count += len(chunk)
                if budget.expired():
                    raise InspectionError("verifying the archive took too long")
    except InspectionError:
        raise
    except Exception:
        raise InspectionError(f"entry '{_clean(info.filename, 80)}' contains corrupt or unreadable data") from None
    if count != info.file_size:
        raise InspectionError(f"entry '{_clean(info.filename, 80)}' does not match its declared size")
    return first


def _inspect_zip(fh, f, budget) -> dict:
    try:
        zf = zipfile.ZipFile(fh)
    except zipfile.BadZipFile:
        raise InspectionError("not a valid zip archive") from None

    with zf:
        infos = zf.infolist()
        if not infos:
            raise InspectionError("the archive is empty")
        if len(infos) > MAX_ENTRIES:
            raise InspectionError(f"the archive has {len(infos)} entries (limit {MAX_ENTRIES})")

        # ---- pass 1: structure only (no decompression, except tiny symlink targets) -------------
        names, lowered = set(), set()
        case_clashes = bidi_names = reserved_names = symlinks = files = dirs = total = 0
        extensions: Counter = Counter()
        file_infos = []
        for info in infos:
            name = info.filename
            _check_entry_name(name)
            if name in names:
                raise InspectionError(f"duplicate entry name '{_clean(name, 80)}'")
            names.add(name)
            if name.lower() in lowered:
                case_clashes += 1
            lowered.add(name.lower())
            if _BIDI.search(name):
                bidi_names += 1
            if any(_RESERVED_RE.match(p.lower()) or p.endswith((".", " ")) for p in name.rstrip("/").split("/")):
                reserved_names += 1
            if info.flag_bits & 0x1:
                raise InspectionError("the archive contains encrypted entries that cannot be inspected")
            if info.compress_type not in _SUPPORTED_COMPRESSION:
                raise InspectionError(f"entry '{_clean(name, 80)}' uses an unsupported compression method")

            mode = (info.external_attr >> 16) & 0xFFFF if info.create_system == 3 else 0
            kind = stat.S_IFMT(mode)
            if kind in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
                raise InspectionError(f"entry '{_clean(name, 80)}' is a special file (device, pipe or socket)")
            if kind == stat.S_IFLNK:
                symlinks += 1
                _check_symlink(zf, info)

            if info.is_dir():
                dirs += 1
                continue
            files += 1
            file_infos.append(info)
            extensions[posixpath.splitext(name)[1].lower() or "(none)"] += 1
            total += info.file_size
            if total > MAX_UNCOMPRESSED_TOTAL:
                raise InspectionError(
                    f"unpacked size would exceed {MAX_UNCOMPRESSED_TOTAL // (1024 * 1024)} MB (possible zip bomb)")
            if info.file_size > RATIO_MIN_ENTRY and (
                    info.compress_size <= 0 or info.file_size / info.compress_size > MAX_ENTRY_RATIO):
                raise InspectionError(
                    f"entry '{_clean(name, 80)}' has a suspicious compression ratio (possible zip bomb)")

        if total > RATIO_MIN_TOTAL and total / max(f.size, 1) > MAX_TOTAL_RATIO:
            raise InspectionError("the archive expands far more than normal (possible zip bomb)")

        # Overlapping entries (several entries sharing the same compressed bytes) are the classic
        # way to beat per-entry ratio checks. A local record is at least 30 + name + data bytes.
        ordered = sorted(infos, key=lambda i: i.header_offset)
        for current, nxt in zip(ordered, ordered[1:]):
            if current.header_offset + 30 + len(current.orig_filename) + current.compress_size > nxt.header_offset:
                raise InspectionError("the archive has overlapping entries (zip bomb technique)")

        # ---- pass 2: verify every entry's data (CRC + exact size) and sniff its content ----------
        program_names, nested_names = [], []
        for info in file_infos:
            first = _verify_entry(zf, info, budget)
            content = detect_file_type(first) if first else "empty"
            ext = posixpath.splitext(info.filename)[1].lower()
            if content == "executable" or ext in _PROGRAM_EXT:
                program_names.append(info.filename)
            if content in ("zip", "gzip", "archive") or ext in _ARCHIVE_EXT:
                nested_names.append(info.filename)

        # ---- summary ------------------------------------------------------------------------------
        readme = None
        license_files = []
        for info in file_infos:
            depth = len(info.filename.split("/"))
            base = posixpath.basename(info.filename).lower()
            if depth <= 2 and _README_RE.match(base) and (readme is None or depth < len(readme.filename.split("/"))):
                readme = info
            if depth <= 2 and _LICENSE_RE.match(base):
                license_files.append(_clean(info.filename, 120))

        readme_preview = None
        if readme is not None:
            with zf.open(readme) as src:
                readme_preview = _clean(" ".join(src.read(4096).decode("utf-8", errors="replace").split()), 300)

        top_level = sorted({i.filename.split("/")[0] for i in infos if "/" in i.filename.rstrip("/")})
        largest = sorted(file_infos, key=lambda i: -i.file_size)[:10]

        warnings: list = []
        if program_names:
            warnings.append(f"{len(program_names)} file(s) look like programs or scripts. This app never runs "
                            f"them; do not run them unless you trust the source.")
        if nested_names:
            warnings.append(f"{len(nested_names)} nested archive(s) inside the zip were not opened.")
        if symlinks:
            warnings.append(f"{symlinks} symbolic link(s) (targets stay inside the archive).")
        if reserved_names:
            warnings.append(f"{reserved_names} entry name(s) are reserved or invalid on Windows.")
        if bidi_names:
            warnings.append(f"{bidi_names} entry name(s) contain text-direction override characters "
                            f"(can disguise file names).")
        if case_clashes:
            warnings.append(f"{case_clashes} entry name(s) differ only by letter case (collide on Windows/macOS).")

        details = {
            "entries": len(infos), "files": files, "directories": dirs,
            "uncompressed_bytes": total,
            "compression_ratio": round(total / f.size, 1) if f.size else None,
            "top_level_folders": [_clean(n, 80) for n in top_level[:10]],
            "extensions": dict(extensions.most_common(10)),
            "largest_files": [{"name": _clean(i.filename, 200), "size_bytes": i.file_size} for i in largest],
            "license_files": license_files[:5],
            "readme_preview": readme_preview,
            "readme_note": "text from inside the archive; untrusted",
            "symlinks": symlinks, "nested_archives": len(nested_names),
            "programs_or_scripts": len(program_names),
            "program_examples": [_clean(n, 120) for n in program_names[:10]],
            "verified": "every entry's data was read once to check its CRC and declared size; nothing was unpacked",
        }
    return _result(files, "files", None, details, warnings)


# ----------------------------------------------------------------------------- PDF
_PDF_ACTIVE = {name: re.compile(rb"/" + name.encode() + rb"(?![A-Za-z])")
               for name in ("JavaScript", "JS", "Launch", "OpenAction", "AA", "EmbeddedFile", "RichMedia")}
_PDF_PAGE = re.compile(rb"/Type\s*/Page(?![A-Za-z])")
_PDF_ENCRYPT = re.compile(rb"/Encrypt(?![A-Za-z])")


def _inspect_pdf(fh, f, budget) -> dict:
    warnings: list = []
    one_mib = 1024 * 1024
    scan_complete = f.size <= MAX_PDF_SCAN
    if scan_complete:
        data = fh.read()
    else:
        data = fh.read(one_mib)
        fh.seek(f.size - one_mib)
        data += fh.read()
        warnings.append("Large PDF: only the first and last 1 MiB were scanned; the page count is unknown.")

    version = re.match(rb"%PDF-(\d\.\d)", data)
    if b"%%EOF" not in data[-1024:]:
        warnings.append("No %%EOF marker near the end of the file (it may be truncated).")

    pages = len(_PDF_PAGE.findall(data)) if scan_complete else 0
    if scan_complete and pages == 0:
        warnings.append("Page count unavailable (pages may be stored inside compressed streams).")

    markers = [name for name, rx in _PDF_ACTIVE.items() if rx.search(data)]
    if markers:
        warnings.append("Contains markers for active or embedded content (" + ", ".join(markers) +
                        "). This app never opens it; do not open it in a viewer you do not trust.")
    encrypted = bool(_PDF_ENCRYPT.search(data))
    if encrypted:
        warnings.append("The PDF is encrypted, so its contents cannot be inspected.")

    details = {"pdf_version": version.group(1).decode() if version else None,
               "pages_estimated": pages or None, "risk_markers": markers, "encrypted": encrypted,
               "scan_complete": scan_complete,
               "note": "heuristic keyword scan; it can miss content hidden in compressed streams"}
    return _result(pages or None, "pages", None, details, warnings)


# ----------------------------------------------------------------------------- PNG
_PNG_COLOR = {0: "grayscale", 2: "rgb", 3: "palette", 4: "grayscale+alpha", 6: "rgba"}


def _inspect_png(fh, f, budget) -> dict:
    size = f.size
    fh.seek(8)
    pos, chunks = 8, 0
    width = height = bit_depth = color_type = interlace = None
    has_exif = saw_iend = False
    while pos < size:
        if budget.expired():
            raise InspectionError("verifying the image took too long")
        header = fh.read(8)
        if len(header) < 8:
            raise InspectionError("the PNG is truncated")
        length, ctype = struct.unpack(">I4s", header)
        if not re.fullmatch(rb"[A-Za-z]{4}", ctype):
            raise InspectionError("the PNG has an invalid chunk type")
        if pos + 12 + length > size:
            raise InspectionError("the PNG is truncated or has an invalid chunk length")
        chunks += 1
        if chunks > MAX_PNG_CHUNKS:
            raise InspectionError("the PNG has too many chunks")
        if chunks == 1 and (ctype != b"IHDR" or length != 13):
            raise InspectionError("the PNG does not start with a valid IHDR chunk")
        crc = zlib.crc32(ctype)
        remaining = length
        captured = b""
        while remaining:
            data = fh.read(min(CHUNK, remaining))
            if not data:
                raise InspectionError("the PNG is truncated")
            if chunks == 1:
                captured += data
            crc = zlib.crc32(data, crc)
            remaining -= len(data)
        stored = fh.read(4)
        if len(stored) < 4 or struct.unpack(">I", stored)[0] != (crc & 0xFFFFFFFF):
            raise InspectionError("the PNG is corrupt (chunk checksum mismatch)")
        if chunks == 1:
            width, height, bit_depth, color_type, _comp, _filt, interlace = struct.unpack(">IIBBBBB", captured)
            if width == 0 or height == 0 or width > 0x7FFFFFFF or height > 0x7FFFFFFF:
                raise InspectionError("the PNG has invalid dimensions")
            if width * height > MAX_PIXELS:
                raise InspectionError(
                    f"the PNG declares {width}x{height} pixels (over {MAX_PIXELS:,}); possible decompression bomb")
        if ctype == b"eXIf":
            has_exif = True
        pos += 12 + length
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        raise InspectionError("the PNG has no IEND chunk (truncated)")

    warnings: list = []
    trailing = size - pos
    if trailing:
        warnings.append(f"{trailing} byte(s) follow the end of the image (could be hidden or appended data).")
    if has_exif:
        warnings.append("Contains EXIF metadata (may include location, device or personal information).")
    details = {"width": width, "height": height, "bit_depth": bit_depth,
               "color_type": _PNG_COLOR.get(color_type, "unknown"), "interlaced": bool(interlace),
               "chunks": chunks, "has_exif": has_exif, "trailing_bytes": trailing}
    return _result(None, None, None, details, warnings)


# ----------------------------------------------------------------------------- JPEG
_JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def _inspect_jpeg(fh, f, budget) -> dict:
    fh.seek(2)
    width = height = precision = None
    progressive = has_exif = False
    fill = segments = 0
    while True:
        b = fh.read(1)
        if not b:
            raise InspectionError("the JPEG ends before its image data (truncated)")
        if b != b"\xff":
            raise InspectionError("the JPEG has an invalid structure")
        m = fh.read(1)
        while m == b"\xff":
            fill += 1
            if fill > 1000:
                raise InspectionError("the JPEG has an invalid structure (too much padding)")
            m = fh.read(1)
        if not m or m == b"\x00":
            raise InspectionError("the JPEG has an invalid structure")
        marker = m[0]
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            continue
        if marker == 0xD9:
            raise InspectionError("the JPEG ends before any image data")
        segments += 1
        if segments > 10_000:
            raise InspectionError("the JPEG has too many header segments")
        length_bytes = fh.read(2)
        if len(length_bytes) < 2:
            raise InspectionError("the JPEG is truncated")
        length = int.from_bytes(length_bytes, "big")
        if length < 2:
            raise InspectionError("the JPEG has an invalid segment length")
        seg = fh.read(length - 2)
        if len(seg) < length - 2:
            raise InspectionError("the JPEG is truncated")
        if marker == 0xE1 and seg.startswith(b"Exif\x00\x00"):
            has_exif = True
        if marker in _JPEG_SOF:
            if len(seg) < 6:
                raise InspectionError("the JPEG has an invalid frame header")
            precision = seg[0]
            height = int.from_bytes(seg[1:3], "big")
            width = int.from_bytes(seg[3:5], "big")
            progressive = marker in (0xC2, 0xC6, 0xCA, 0xCE)
        if marker == 0xDA:
            break
    if width is None:
        raise InspectionError("the JPEG has no frame header")
    if not width or not height:
        raise InspectionError("the JPEG has invalid dimensions")
    if width * height > MAX_PIXELS:
        raise InspectionError(
            f"the JPEG declares {width}x{height} pixels (over {MAX_PIXELS:,}); possible decompression bomb")

    warnings: list = []
    fh.seek(max(0, f.size - 64))
    if not fh.read(64).rstrip(b"\x00").endswith(b"\xff\xd9"):
        warnings.append("No end-of-image marker at the end of the file (truncated, or has trailing data).")
    if has_exif:
        warnings.append("Contains EXIF metadata (may include location, device or personal information).")
    details = {"width": width, "height": height, "precision_bits": precision,
               "progressive": progressive, "has_exif": has_exif}
    return _result(None, None, None, details, warnings)


# ----------------------------------------------------------------------------- Parquet
def _inspect_parquet(fh, f, budget) -> dict:
    if f.size < 12:
        raise InspectionError("the Parquet file is too small to be valid")
    fh.seek(f.size - 8)
    tail = fh.read(8)
    footer_len = int.from_bytes(tail[:4], "little")
    if tail[4:] != b"PAR1":
        raise InspectionError("the Parquet file has no closing PAR1 marker (truncated, corrupt or encrypted)")
    if footer_len == 0 or footer_len > f.size - 12:
        raise InspectionError("the Parquet file has an invalid footer length")
    details = {"footer_bytes": footer_len,
               "note": "Schema and row count were NOT read: this app does not run a Parquet parser "
                       "on untrusted files. Only the file structure was checked."}
    return _result(None, None, None, details, [])


# ----------------------------------------------------------------------------- dispatcher
def _inspect_file(f, budget: _Budget) -> dict:
    name = _clean(f.original_name, 150)
    try:
        fh = _open_nofollow(f.path)
    except OSError:
        raise InspectionError(f"'{name}' is missing from quarantine or is not a regular file") from None
    with fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise InspectionError(f"'{name}' is not a regular file")
        if st.st_size != f.size:
            raise InspectionError(f"'{name}' changed after it was downloaded")
        if detect_file_type(fh.read(DETECT_BYTES)) != f.detected_type:
            raise InspectionError(f"'{name}' no longer matches the file type verified at download")
        fh.seek(0)

        handlers = {
            "csv": lambda: _inspect_csv(fh, f, budget, False),
            "tsv": lambda: _inspect_csv(fh, f, budget, True),
            "json": lambda: _inspect_json(fh, f, budget),
            "jsonl": lambda: _inspect_jsonl(fh, f, budget),
            "txt": lambda: _inspect_plain(fh, f, budget, False),
            "md": lambda: _inspect_plain(fh, f, budget, True),
            "zip": lambda: _inspect_zip(fh, f, budget),
            "pdf": lambda: _inspect_pdf(fh, f, budget),
            "png": lambda: _inspect_png(fh, f, budget),
            "jpeg": lambda: _inspect_jpeg(fh, f, budget),
            "parquet": lambda: _inspect_parquet(fh, f, budget),
        }
        handler = handlers.get(f.format)
        if handler is None:
            raise InspectionError(f"'{name}': unsupported format '{_clean(f.format, 20)}'")
        try:
            result = handler()
        except InspectionError as exc:
            raise InspectionError(f"'{name}': {exc}") from None
        except Exception as exc:  # never leak internals; the endpoint stores this message
            raise InspectionError(f"'{name}' could not be processed ({type(exc).__name__})") from None

    return {"name": name, "format": f.format, "size_bytes": f.size,
            "record_count": result["record_count"], "record_unit": result["record_unit"],
            "encoding": result["encoding"], "details": result["details"], "warnings": result["warnings"]}


def inspect_download(files: list, *, max_seconds: float = MAX_INSPECT_SECONDS,
                     clock: Callable[[], float] = time.monotonic) -> dict:
    """
    `files` are the StoredFile objects from SafeDownloader. See the module docstring for the
    return shape and for what is rejected (raises InspectionError) versus reported as a warning.

    Top-level record_count: the sum over data files (csv / tsv / json / jsonl rows or items;
    for a zip, the number of files inside it). If there are no data files and exactly one file,
    that file's own count (text lines or PDF pages). Otherwise None.
    """
    if not files:
        raise InspectionError("there are no files to inspect")
    budget = _Budget(max_seconds, clock)
    reports = [_inspect_file(f, budget) for f in files]

    data_counts = [r["record_count"] for r in reports if r["format"] in DATA_FORMATS and r["record_count"] is not None]
    if data_counts:
        record_count: Optional[int] = sum(data_counts)
    elif len(reports) == 1:
        record_count = reports[0]["record_count"]
    else:
        record_count = None

    encodings = {r["encoding"] for r in reports if r["encoding"]}
    encoding = None if not encodings else (next(iter(encodings)) if len(encodings) == 1 else "mixed")

    return {
        "format": ",".join(sorted({r["format"] for r in reports})),
        "schema_preview": {"files": reports, "total_warnings": sum(len(r["warnings"]) for r in reports)},
        "record_count": record_count,
        "encoding": encoding,
    }
