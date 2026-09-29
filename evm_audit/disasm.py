"""Minimal, dependency-free EVM bytecode disassembler.

The interesting part for a learner: opcodes are single bytes, except
PUSH1..PUSH32 which carry immediate data. You cannot walk the code
one byte at a time -- you must skip the immediate bytes, or you will
"discover" fake opcodes inside push data. That single rule is why
disassembly must be sequential and why jump destinations can only be
trusted when they are not inside push data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .opcodes import OPCODES


def parse_hex(text: str) -> bytes:
    """Parse '0x...' or bare hex, tolerating whitespace and underscores."""
    s = re.sub(r"[\s_]", "", text or "")
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    if s and not re.fullmatch(r"[0-9a-fA-F]+", s):
        raise ValueError("input is not valid hex")
    return bytes.fromhex(s)


@dataclass
class Instruction:
    pc: int
    opcode: int
    mnemonic: str
    operand: bytes | None = None
    size: int = 1
    target: int | None = None

    @property
    def operand_hex(self) -> str | None:
        return "0x" + self.operand.hex() if self.operand is not None else None

    @property
    def operand_int(self) -> int | None:
        return int.from_bytes(self.operand, "big") if self.operand else None

    def render(self) -> str:
        out = f"{self.pc:>6}  {self.mnemonic:<12}"
        if self.operand is not None:
            out += self.operand_hex or ""
        if self.target is not None:
            out += f"  -> {self.target}"
        return out.rstrip()


@dataclass
class Disassembly:
    code: bytes          # code with metadata stripped
    instructions: list[Instruction]
    jumpdests: set[int]
    metadata: dict | None = None
    raw_size: int = 0    # original bytecode length, metadata included


def strip_metadata(code: bytes) -> tuple[bytes, dict | None]:
    """Remove the trailing Solidity CBOR metadata blob, if present.

    Layout: <runtime code> <cbor blob> <uint16 big-endian cbor length>.
    The final two bytes say how many bytes precede them; the first byte
    of the blob is a CBOR map header (0xa0..0xa5).
    """
    if len(code) < 4:
        return code, None
    length = int.from_bytes(code[-2:], "big")
    if length == 0 or length > len(code) - 2:
        return code, None
    start = len(code) - 2 - length
    if code[start] not in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5):
        return code, None
    meta = code[start:-2]
    info: dict = {"bytes": meta.hex()}
    # ipfs value is CBOR bytes(34): 0x58 0x22 then the 0x1220 multihash.
    i = meta.find(b"ipfs")
    if i != -1 and len(meta) >= i + 6 + 34:
        info["ipfs"] = "0x" + meta[i + 6 : i + 6 + 34].hex()
    # solc version is a CBOR byte string: 0x43 (bytes, len 3) then major/minor/patch.
    i = meta.find(b"solc")
    if i != -1 and len(meta) >= i + 8:
        info["solc"] = f"{meta[i + 5]}.{meta[i + 6]}.{meta[i + 7]}"
    if b"bzzr" in meta:
        info["bzzr"] = True
    return code[:start], info


def _attach_jump_targets(instrs: list[Instruction]) -> None:
    """Annotate JUMP/JUMPI with the destination pushed immediately before it.

    This is a simple, deterministic heuristic: in compiled code the
    destination almost always comes from the preceding PUSH.
    """
    for i, ins in enumerate(instrs):
        if ins.mnemonic not in ("JUMP", "JUMPI"):
            continue
        j = i - 1
        if j >= 0 and instrs[j].mnemonic.startswith("PUSH") and instrs[j].operand:
            ins.target = instrs[j].operand_int


def disassemble(code: bytes, *, strip_meta: bool = True) -> Disassembly:
    raw_size = len(code)
    metadata = None
    if strip_meta:
        code, metadata = strip_metadata(code)

    instrs: list[Instruction] = []
    jumpdests: set[int] = set()
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32 carries immediate data
            size = op - 0x5F
            operand = code[pc + 1 : pc + 1 + size]
            instrs.append(Instruction(pc, op, f"PUSH{size}", operand, 1 + size))
            pc += 1 + size
            continue
        name = OPCODES.get(op)
        if name is None:
            instrs.append(Instruction(pc, op, f"INVALID_0x{op:02x}", None, 1))
            pc += 1
            continue
        if op == 0x5B:
            jumpdests.add(pc)
        instrs.append(Instruction(pc, op, name, None, 1))
        pc += 1

    _attach_jump_targets(instrs)
    return Disassembly(code, instrs, jumpdests, metadata, raw_size)
