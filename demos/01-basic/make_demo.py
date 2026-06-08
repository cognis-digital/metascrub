"""Generate the demo PNG (release_banner.png) with realistic leaky metadata.

Standard library only. A real binary PNG can't be checked in as text, so this
script reproducibly builds it next to itself.
"""

import os
import struct
import zlib


def _chunk(ctype: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + ctype + body
            + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF))


def build_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0)  # 2x2 RGBA
    raw = b"".join(b"\x00" + b"\xff\x00\x00\xff\x00\xff\x00\xff"
                    for _ in range(2))
    idat = zlib.compress(raw)
    out = sig
    out += _chunk(b"IHDR", ihdr)
    out += _chunk(b"tEXt", b"Author\x00Jane Doe <jane@acme.example>")
    out += _chunk(b"tEXt", b"Software\x00Adobe Photoshop 25.0 (Macintosh)")
    out += _chunk(b"tIME", struct.pack(">HBBBBB", 2026, 6, 8, 14, 3, 9))
    out += _chunk(b"IDAT", idat)
    out += _chunk(b"IEND", b"")
    return out


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    dest = os.path.join(here, "release_banner.png")
    with open(dest, "wb") as fh:
        fh.write(build_png())
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()
