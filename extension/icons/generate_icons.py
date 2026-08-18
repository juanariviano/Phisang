#!/usr/bin/env python3
"""Generate simple shield PNG icons without third-party image libraries."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent


def chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_png(path: Path, width: int, height: int, pixels: list[tuple[int, int, int, int]]) -> None:
    raw = b""
    for y in range(height):
        raw += b"\x00"
        for x in range(width):
            raw += bytes(pixels[y * width + x])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    path.write_bytes(png)


def draw_icon(size: int) -> list[tuple[int, int, int, int]]:
    pixels: list[tuple[int, int, int, int]] = []
    for y in range(size):
        for x in range(size):
            nx = (x + 0.5) / size
            ny = (y + 0.5) / size
            in_shield = (
                nx > 0.18
                and nx < 0.82
                and ny > 0.14
                and ny < 0.86
                and (ny < 0.62 or abs(nx - 0.5) < (0.86 - ny) * 1.15)
            )
            if in_shield:
                pixels.append((228, 192, 122, 255))
            else:
                pixels.append((11, 16, 32, 255))
    return pixels


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 48, 128):
        write_png(OUT / f"icon{size}.png", size, size, draw_icon(size))


if __name__ == "__main__":
    main()
