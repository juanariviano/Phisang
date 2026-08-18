#!/usr/bin/env python3
"""Generate the Phisang banana icons without third-party image libraries.

The mark is a fat stroked arc with a green stem: a filled banana silhouette
turns to mush at 16px, a thick arc survives it. Geometry is defined in the same
32-unit space as the SVG in web/src/components/Logo.jsx so the two stay in step.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent

GROUND = (255, 191, 0)
FRUIT = (22, 33, 15)
LEAF = (70, 114, 53)

# Arc: centre (9, 24), radius 17, stroke 6.5, swept from -90 deg to 0 deg.
ARC_CX, ARC_CY, ARC_R, ARC_HALF = 9.0, 24.0, 17.0, 3.25
ARC_START, ARC_END = (9.0, 7.0), (26.0, 24.0)

# Stem: (9, 7) -> (7.4, 3.6), stroke 3.2.
STEM_A, STEM_B, STEM_HALF = (9.0, 7.0), (7.4, 3.6), 1.6

CORNER = 7.0  # rounded-rect radius in 32-unit space
SS = 3  # supersampling factor per axis


def chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def write_png(path: Path, size: int, pixels: list[tuple[int, int, int, int]]) -> None:
    raw = b""
    for y in range(size):
        raw += b"\x00"
        for x in range(size):
            raw += bytes(pixels[y * size + x])
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def dist(ax: float, ay: float, bx: float, by: float) -> float:
    return math.hypot(ax - bx, ay - by)


def dist_to_segment(px: float, py: float, a: tuple[float, float], b: tuple[float, float]) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    span = dx * dx + dy * dy
    t = 0.0 if span == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / span))
    return dist(px, py, ax + t * dx, ay + t * dy)


def in_rounded_rect(u: float, v: float) -> bool:
    cx = min(max(u, CORNER), 32.0 - CORNER)
    cy = min(max(v, CORNER), 32.0 - CORNER)
    return dist(u, v, cx, cy) <= CORNER


def sample(u: float, v: float) -> tuple[int, int, int, int] | None:
    """Colour at a point in 32-unit space, or None for transparent."""
    if not in_rounded_rect(u, v):
        return None

    if dist_to_segment(u, v, STEM_A, STEM_B) <= STEM_HALF:
        return LEAF + (255,)

    radial = abs(dist(u, v, ARC_CX, ARC_CY) - ARC_R)
    angle = math.degrees(math.atan2(v - ARC_CY, u - ARC_CX))
    on_arc = radial <= ARC_HALF and -90.0 <= angle <= 0.0
    capped = (
        dist(u, v, *ARC_START) <= ARC_HALF or dist(u, v, *ARC_END) <= ARC_HALF
    )
    if on_arc or capped:
        return FRUIT + (255,)

    return GROUND + (255,)


def draw_icon(size: int) -> list[tuple[int, int, int, int]]:
    """Supersampled so the arc and the rounded corners do not read as stairs."""
    scale = 32.0 / size
    step = scale / SS
    pixels: list[tuple[int, int, int, int]] = []
    for y in range(size):
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(SS):
                for sx in range(SS):
                    u = (x * scale) + (sx + 0.5) * step
                    v = (y * scale) + (sy + 0.5) * step
                    hit = sample(u, v)
                    if hit is None:
                        continue
                    acc[0] += hit[0]
                    acc[1] += hit[1]
                    acc[2] += hit[2]
                    acc[3] += 255.0
            n = SS * SS
            alpha = acc[3] / n
            if alpha < 1:
                pixels.append((0, 0, 0, 0))
                continue
            # Premultiplied average, then un-premultiply against coverage.
            covered = acc[3] / 255.0
            pixels.append(
                (
                    round(acc[0] / covered),
                    round(acc[1] / covered),
                    round(acc[2] / covered),
                    round(alpha),
                )
            )
    return pixels


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 48, 128):
        write_png(OUT / f"icon{size}.png", size, draw_icon(size))
        print(f"wrote icon{size}.png")


if __name__ == "__main__":
    main()
