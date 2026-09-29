"""Pure-Python Keccak-256 (the pre-standard variant Ethereum uses).

Ethereum function selectors are the first 4 bytes of keccak256(signature).
`hashlib.sha3_256` is *not* Keccak-256 (NIST changed the padding), so we
implement it here. It is dependency-free and doubles as a learning artifact.

Verified against known vectors in tests/test_keccak.py.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# Rotation offsets indexed [x][y].
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_RATE = 136  # 1088-bit rate for Keccak-256


def _rotl(x: int, n: int) -> int:
    n %= 64
    if n == 0:
        return x & _MASK
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    padlen = _RATE - (len(data) % _RATE)
    if padlen == 1:
        padded = data + b"\x81"
    else:
        padded = data + b"\x01" + b"\x00" * (padlen - 2) + b"\x80"

    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), _RATE):
        block = padded[off : off + _RATE]
        for i in range(_RATE // 8):
            lane = int.from_bytes(block[i * 8 : i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)

    out = bytearray()
    for i in range(4):  # 4 lanes -> 32 bytes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def selector(signature: str) -> str:
    """Return the 4-byte function selector for an ABI signature, e.g. '0x095ea7b3'."""
    return "0x" + keccak256(signature.encode("ascii"))[:4].hex()
