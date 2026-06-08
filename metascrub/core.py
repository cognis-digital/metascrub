"""METASCRUB engine.

Real, dependency-free metadata scanning and stripping for the formats most
likely to leak author/device/location info before a public release:

  * PNG  - ancillary text/time/EXIF chunks (tEXt, zTXt, iTXt, tIME, eXIf)
  * JPEG - EXIF (APP1/Exif), XMP (APP1/xmlns), Photoshop IRB (APP13),
           Adobe (APP14), and COM comment segments
  * PDF  - /Info document-information dictionary keys + XMP metadata stream

The strategy is conservative: we parse the container structure and *drop*
ancillary metadata segments/chunks while preserving the actual image/document
payload. We never invent attack capability -- this only sanitizes files the
operator already controls.
"""

from __future__ import annotations

import os
import re
import struct
import zlib
from dataclasses import dataclass, field, asdict
from typing import Callable

SUPPORTED_FORMATS = ("png", "jpeg", "pdf")

# PNG ancillary chunks that carry human/device metadata. Critical chunks
# (IHDR/PLTE/IDAT/IEND) are always preserved.
_PNG_META_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"tIME", b"eXIf"}
_PNG_SIG = b"\x89PNG\r\n\x1a\n"

# PDF /Info keys that commonly identify author/tooling.
_PDF_INFO_KEYS = (
    "Author", "Creator", "Producer", "Title", "Subject",
    "Keywords", "CreationDate", "ModDate", "Company", "Manager",
)


@dataclass
class Finding:
    """One piece of identifying metadata detected in a file."""

    kind: str          # e.g. "png:tEXt", "jpeg:exif", "pdf:info"
    key: str           # human-readable label (chunk name / tag / dict key)
    detail: str = ""   # short preview of the value (truncated)
    bytes_removed: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScrubResult:
    path: str
    fmt: str
    findings: list[Finding] = field(default_factory=list)
    cleaned: bool = False
    output_path: str | None = None
    error: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.fmt,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "cleaned": self.cleaned,
            "output_path": self.output_path,
            "error": self.error,
        }


def _preview(value: bytes | str, limit: int = 80) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:
            value = repr(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit] + ("..." if len(value) > limit else "")


def detect_format(path: str) -> str | None:
    """Sniff the container by magic bytes (extension is not trusted)."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head.startswith(_PNG_SIG):
        return "png"
    if head[:2] == b"\xff\xd8":
        return "jpeg"
    if head[:5] == b"%PDF-":
        return "pdf"
    return None


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #
def _png_iter_chunks(data: bytes):
    pos = len(_PNG_SIG)
    n = len(data)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        start = pos + 8
        end = start + length
        if end + 4 > n:
            break
        body = data[start:end]
        crc = data[end:end + 4]
        yield ctype, body, crc
        pos = end + 4


def _png_text_label(ctype: bytes, body: bytes) -> str:
    """Best-effort keyword extraction for a preview."""
    try:
        if ctype == b"tEXt":
            kw, _, val = body.partition(b"\x00")
            return f"{kw.decode('latin-1', 'replace')}={_preview(val)}"
        if ctype == b"zTXt":
            kw, _, rest = body.partition(b"\x00")
            comp = rest[1:] if rest else b""
            try:
                val = zlib.decompress(comp)
            except Exception:
                val = b""
            return f"{kw.decode('latin-1', 'replace')}={_preview(val)}"
        if ctype == b"iTXt":
            kw, _, _ = body.partition(b"\x00")
            return kw.decode("utf-8", "replace")
    except Exception:
        pass
    return _preview(body)


def _scan_png(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for ctype, body, _crc in _png_iter_chunks(data):
        if ctype in _PNG_META_CHUNKS:
            label = ctype.decode("ascii", "replace")
            detail = _png_text_label(ctype, body) if ctype != b"tIME" else "timestamp"
            if ctype == b"eXIf":
                detail = "embedded EXIF block"
            findings.append(
                Finding(
                    kind=f"png:{label}",
                    key=label,
                    detail=detail,
                    bytes_removed=len(body) + 12,  # length+type+crc framing
                )
            )
    return findings


def _clean_png(data: bytes) -> bytes:
    out = bytearray(_PNG_SIG)
    for ctype, body, _crc in _png_iter_chunks(data):
        if ctype in _PNG_META_CHUNKS:
            continue
        out += struct.pack(">I", len(body))
        out += ctype
        out += body
        out += struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)
    return bytes(out)


# --------------------------------------------------------------------------- #
# JPEG
# --------------------------------------------------------------------------- #
# Marker -> human label for metadata-bearing segments we strip.
_JPEG_STRIP_MARKERS = {
    0xE1: "APP1 (EXIF/XMP)",
    0xED: "APP13 (Photoshop IRB)",
    0xEE: "APP14 (Adobe)",
    0xFE: "COM (comment)",
}


def _jpeg_segments(data: bytes):
    """Yield (marker_byte, full_segment_bytes_including_marker)."""
    pos = 2  # skip SOI
    n = len(data)
    while pos + 1 < n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            yield marker, data[pos:]
            return
        if marker == 0xDA:  # SOS -> entropy data to end
            yield marker, data[pos:]
            return
        if 0xD0 <= marker <= 0xD7 or marker in (0x01, 0xFF):
            pos += 2
            continue
        if pos + 4 > n:
            return
        (seglen,) = struct.unpack(">H", data[pos + 2:pos + 4])
        end = pos + 2 + seglen
        if end > n:
            end = n
        yield marker, data[pos:end]
        pos = end


def _scan_jpeg(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for marker, seg in _jpeg_segments(data):
        if marker in _JPEG_STRIP_MARKERS:
            label = _JPEG_STRIP_MARKERS[marker]
            payload = seg[4:]
            detail = label
            if marker == 0xE1:
                if payload[:6] == b"Exif\x00\x00":
                    detail = "EXIF (camera/GPS/timestamp)"
                elif payload[:4] == b"http" or b"xmlns" in payload[:200]:
                    detail = "XMP (" + _preview(payload[:120]) + ")"
            elif marker == 0xFE:
                detail = "comment: " + _preview(payload)
            findings.append(
                Finding(
                    kind=f"jpeg:app{marker - 0xE0:x}" if 0xE0 <= marker <= 0xEF else "jpeg:com",
                    key=label,
                    detail=detail,
                    bytes_removed=len(seg),
                )
            )
    return findings


def _clean_jpeg(data: bytes) -> bytes:
    out = bytearray(data[:2])  # SOI
    for marker, seg in _jpeg_segments(data):
        if marker in _JPEG_STRIP_MARKERS:
            continue
        out += seg
    return bytes(out)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def _scan_pdf(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    text = data.decode("latin-1", "replace")

    # /Info dictionary keys (e.g. /Author (Jane Doe))
    for key in _PDF_INFO_KEYS:
        for m in re.finditer(
            r"/%s\s*\((?P<v>(?:\\.|[^)\\])*)\)" % key, text
        ):
            val = m.group("v")
            findings.append(
                Finding(
                    kind="pdf:info",
                    key=key,
                    detail=_preview(val),
                    bytes_removed=len(m.group(0)),
                )
            )
        # hex-string form: /Author <...>
        for m in re.finditer(r"/%s\s*<(?P<v>[0-9A-Fa-f\s]*)>" % key, text):
            findings.append(
                Finding(
                    kind="pdf:info",
                    key=key,
                    detail="<hex string>",
                    bytes_removed=len(m.group(0)),
                )
            )

    # XMP metadata streams.
    for m in re.finditer(r"<\?xpacket begin.*?<\?xpacket end[^>]*\?>", text, re.S):
        findings.append(
            Finding(
                kind="pdf:xmp",
                key="XMP packet",
                detail=_preview(m.group(0), 100),
                bytes_removed=len(m.group(0)),
            )
        )
    return findings


def _clean_pdf(data: bytes) -> bytes:
    text = data.decode("latin-1", "replace")

    for key in _PDF_INFO_KEYS:
        # Blank the value but keep a syntactically valid empty literal/hex.
        text = re.sub(
            r"/%s\s*\((?:\\.|[^)\\])*\)" % key,
            "/%s ()" % key,
            text,
        )
        text = re.sub(
            r"/%s\s*<[0-9A-Fa-f\s]*>" % key,
            "/%s ()" % key,
            text,
        )

    # Replace XMP packet contents with an empty packet, padded to original
    # length so byte offsets in simple linear PDFs stay sane.
    def _blank_xmp(m: "re.Match") -> str:
        original = m.group(0)
        empty = (
            '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            '<?xpacket end="w"?>'
        )
        if len(empty) < len(original):
            empty = empty + " " * (len(original) - len(empty))
        return empty[: len(original)]

    text = re.sub(
        r"<\?xpacket begin.*?<\?xpacket end[^>]*\?>", _blank_xmp, text, flags=re.S
    )
    return text.encode("latin-1", "replace")


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
_SCANNERS: dict[str, Callable[[bytes], list[Finding]]] = {
    "png": _scan_png,
    "jpeg": _scan_jpeg,
    "pdf": _scan_pdf,
}
_CLEANERS: dict[str, Callable[[bytes], bytes]] = {
    "png": _clean_png,
    "jpeg": _clean_jpeg,
    "pdf": _clean_pdf,
}


def scan_file(path: str) -> ScrubResult:
    """Detect metadata without modifying the file."""
    if not os.path.isfile(path):
        return ScrubResult(path=path, fmt="?", error="not a file")
    fmt = detect_format(path)
    if fmt not in _SCANNERS:
        return ScrubResult(path=path, fmt=fmt or "unknown",
                           error="unsupported format")
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        findings = _SCANNERS[fmt](data)
    except Exception as exc:  # defensive: never crash on malformed input
        return ScrubResult(path=path, fmt=fmt, error=f"parse error: {exc}")
    return ScrubResult(path=path, fmt=fmt, findings=findings)


def clean_file(path: str, output_path: str | None = None,
               in_place: bool = False) -> ScrubResult:
    """Strip metadata, writing a sanitized copy (or in place)."""
    result = scan_file(path)
    if result.error:
        return result
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        cleaned = _CLEANERS[result.fmt](data)
    except Exception as exc:
        result.error = f"clean error: {exc}"
        return result

    if in_place:
        out = path
    elif output_path:
        out = output_path
    else:
        root, ext = os.path.splitext(path)
        out = f"{root}.scrubbed{ext}"

    with open(out, "wb") as fh:
        fh.write(cleaned)
    result.cleaned = True
    result.output_path = out
    return result
