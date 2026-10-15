"""Pure-Python RIPEMD-160 (Dobbertin, Bosselaers, Preneel, 1996).

Only used when hashlib cannot provide it (OpenSSL 3 moved RIPEMD-160 into the
legacy provider, which many builds leave disabled). Not constant-time; fine for
displaying addresses, not for anything secret.
"""

from __future__ import annotations

import struct

_M32 = 0xFFFFFFFF

# Message-word order for each of the 80 steps, left and right lines.
_WORD_L = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)  # fmt: skip
_WORD_R = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)  # fmt: skip

# Left-rotation amounts for each step.
_ROT_L = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)  # fmt: skip
_ROT_R = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)  # fmt: skip

# Round constants, one per group of 16 steps.
_K_L = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_K_R = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def _boolean(group: int, x: int, y: int, z: int) -> int:
    """The five nonlinear functions f1..f5."""
    if group == 0:
        return x ^ y ^ z
    if group == 1:
        return (x & y) | (~x & z)
    if group == 2:
        return (x | ~y) ^ z
    if group == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _block(state: tuple[int, ...], chunk: bytes) -> tuple[int, ...]:
    words = struct.unpack("<16I", chunk)
    a1, b1, c1, d1, e1 = state
    a2, b2, c2, d2, e2 = state

    for step in range(80):
        g = step // 16
        # Left line uses f1..f5 in order, right line uses them in reverse.
        t = _rotl(
            (a1 + (_boolean(g, b1, c1, d1) & _M32) + words[_WORD_L[step]] + _K_L[g]) & _M32,
            _ROT_L[step],
        )
        a1, b1, c1, d1, e1 = e1, (t + e1) & _M32, b1, _rotl(c1, 10), d1

        t = _rotl(
            (a2 + (_boolean(4 - g, b2, c2, d2) & _M32) + words[_WORD_R[step]] + _K_R[g]) & _M32,
            _ROT_R[step],
        )
        a2, b2, c2, d2, e2 = e2, (t + e2) & _M32, b2, _rotl(c2, 10), d2

    h0, h1, h2, h3, h4 = state
    return (
        (h1 + c1 + d2) & _M32,
        (h2 + d1 + e2) & _M32,
        (h3 + e1 + a2) & _M32,
        (h4 + a1 + b2) & _M32,
        (h0 + b1 + c2) & _M32,
    )


def ripemd160(message: bytes) -> bytes:
    """Return the 20-byte RIPEMD-160 digest of ``message``."""
    state: tuple[int, ...] = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

    # MD4-style padding: 0x80, zeros to 56 mod 64, then the bit length as a
    # little-endian 64-bit integer.
    padded = message + b"\x80" + b"\x00" * ((55 - len(message)) % 64)
    padded += struct.pack("<Q", (8 * len(message)) & 0xFFFFFFFFFFFFFFFF)

    for i in range(0, len(padded), 64):
        state = _block(state, padded[i : i + 64])

    return struct.pack("<5I", *state)
