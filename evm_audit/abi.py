"""Very small ABI argument decoder.

Handles the head-only encoding for static types plus `bytes`/`string`
tails (which, in the functions we care about, are always the last arg).
This is intentionally not a full ABI codec -- it is enough to read
approvals and permits in plain language.
"""

from __future__ import annotations

MAX_UINT256 = (1 << 256) - 1
MAX_UINT160 = (1 << 160) - 1


def is_static(type_name: str) -> bool:
    if type_name in ("bytes", "string"):
        return False
    return not type_name.endswith("]")


def decode_word(type_name: str, word: bytes):
    if type_name == "address":
        return "0x" + word[-20:].hex()
    if type_name == "bool":
        return bool(int.from_bytes(word, "big"))
    if type_name == "bytes32":
        return "0x" + word.hex()
    if type_name.startswith(("uint", "int")):
        return int.from_bytes(word, "big", signed=type_name.startswith("int"))
    if type_name.startswith("bytes") and type_name[5:].isdigit():
        n = int(type_name[5:])
        return "0x" + word[:n].hex()
    return "0x" + word.hex()


def decode_args(types: list[str], data: bytes) -> list:
    values = []
    for i, type_name in enumerate(types):
        word = data[i * 32 : (i + 1) * 32]
        if len(word) < 32:
            values.append(None)
            continue
        if is_static(type_name):
            values.append(decode_word(type_name, word))
            continue
        # dynamic tail: 32-byte offset, then 32-byte length, then payload
        off = int.from_bytes(word, "big")
        if off + 32 > len(data):
            values.append(None)
            continue
        length = int.from_bytes(data[off : off + 32], "big")
        raw = data[off + 32 : off + 32 + length]
        if type_name == "bytes":
            values.append("0x" + raw.hex())
        else:
            values.append(raw.decode("utf-8", "replace"))
    return values
