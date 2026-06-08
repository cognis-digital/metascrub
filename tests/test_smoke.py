"""Smoke tests for METASCRUB. No network. Builds fixtures in-memory."""

import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metascrub import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, scan_file, clean_file, detect_format,
)
from metascrub import cli  # noqa: E402


# --------------------------------------------------------------------------- #
# fixture builders
# --------------------------------------------------------------------------- #
def _png_chunk(t: bytes, b: bytes) -> bytes:
    return (struct.pack(">I", len(b)) + t + b
            + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF))


def make_png(with_meta: bool = True) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00\xff")
    out = sig + _png_chunk(b"IHDR", ihdr)
    if with_meta:
        out += _png_chunk(b"tEXt", b"Author\x00Jane Doe")
        out += _png_chunk(b"tIME", struct.pack(">HBBBBB", 2026, 6, 8, 1, 2, 3))
    out += _png_chunk(b"IDAT", idat)
    out += _png_chunk(b"IEND", b"")
    return out


def make_jpeg() -> bytes:
    soi = b"\xff\xd8"
    exif_payload = b"Exif\x00\x00" + b"II*\x00" + b"\x00" * 16
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
    com = b"\xff\xfe" + struct.pack(">H", 2 + 11) + b"created by X"
    sos = b"\xff\xda" + struct.pack(">H", 3) + b"\x00" + b"\x12\x34"
    eoi = b"\xff\xd9"
    return soi + app1 + com + sos + eoi


def make_pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Author (Jane Doe) /Creator (Acme Editor) "
        b"/Producer (libfoo 2.1) /CreationDate (D:20260608120000Z) >>\nendobj\n"
        b"xref\n%%EOF\n"
    )


def _tmp(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #
class TestMeta(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "metascrub")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")

    def test_detect_format(self):
        self.assertEqual(detect_format(_tmp(make_png(), ".png")), "png")
        self.assertEqual(detect_format(_tmp(make_jpeg(), ".jpg")), "jpeg")
        self.assertEqual(detect_format(_tmp(make_pdf(), ".pdf")), "pdf")
        self.assertIsNone(detect_format(_tmp(b"hello world", ".txt")))


class TestPng(unittest.TestCase):
    def test_scan_finds_meta(self):
        r = scan_file(_tmp(make_png(), ".png"))
        kinds = {f.kind for f in r.findings}
        self.assertIn("png:tEXt", kinds)
        self.assertIn("png:tIME", kinds)
        self.assertTrue(r.has_findings)

    def test_clean_removes_meta_keeps_image(self):
        path = _tmp(make_png(), ".png")
        r = clean_file(path)
        self.assertTrue(r.cleaned)
        again = scan_file(r.output_path)
        self.assertFalse(again.has_findings)
        with open(r.output_path, "rb") as fh:
            self.assertIn(b"IDAT", fh.read())

    def test_clean_no_meta_png_is_noop(self):
        r = scan_file(_tmp(make_png(with_meta=False), ".png"))
        self.assertFalse(r.has_findings)


class TestJpeg(unittest.TestCase):
    def test_scan_and_clean(self):
        path = _tmp(make_jpeg(), ".jpg")
        r = scan_file(path)
        self.assertTrue(any("exif" in f.detail.lower() for f in r.findings))
        cleaned = clean_file(path)
        again = scan_file(cleaned.output_path)
        self.assertFalse(again.has_findings)
        with open(cleaned.output_path, "rb") as fh:
            self.assertIn(b"\xff\xda", fh.read())


class TestPdf(unittest.TestCase):
    def test_scan_and_clean(self):
        path = _tmp(make_pdf(), ".pdf")
        r = scan_file(path)
        keys = {f.key for f in r.findings}
        self.assertTrue({"Author", "Creator", "Producer"} <= keys)
        cleaned = clean_file(path)
        with open(cleaned.output_path, "rb") as fh:
            body = fh.read()
        self.assertNotIn(b"Jane Doe", body)
        self.assertNotIn(b"Acme Editor", body)


class TestCli(unittest.TestCase):
    def test_scan_exit_code_nonzero_on_findings(self):
        path = _tmp(make_png(), ".png")
        self.assertEqual(cli.main(["scan", path]), 1)

    def test_scan_clean_file_exit_zero(self):
        path = _tmp(make_png(with_meta=False), ".png")
        self.assertEqual(cli.main(["scan", path]), 0)

    def test_clean_exit_zero(self):
        path = _tmp(make_png(), ".png")
        out = path + ".out.png"
        self.assertEqual(cli.main(["clean", path, "-o", out]), 0)
        self.assertTrue(os.path.exists(out))

    def test_unsupported_format_errors(self):
        path = _tmp(b"not an image", ".txt")
        self.assertEqual(cli.main(["scan", path]), 1)

    def test_json_output_parses(self):
        path = _tmp(make_png(), ".png")
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            cli.main(["--format", "json", "scan", path])
        finally:
            sys.stdout = old
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], "metascrub")
        self.assertGreater(payload["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
