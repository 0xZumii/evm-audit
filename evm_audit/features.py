"""Turn a disassembly into a feature vector plus plain-language signals.

The goal is deliberately NOT "phishing / not phishing". It is:
what does this code structurally do, and what should a human look at?
That framing keeps you honest and is also the part current tools skip.
"""

from __future__ import annotations

import math
from collections import Counter

from .disasm import Disassembly
from .keccak import keccak256
from .opcodes import (
    CREATE_OPS,
    EXTERNAL_CALL_OPS,
    LOG_OPS,
    OPCODE_NOTES,
    STORAGE_READ_OPS,
    STORAGE_WRITE_OPS,
)

# EIP-1167 minimal proxy: 10-byte prefix + 20-byte address + 15-byte suffix.
EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")

# Known proxy storage slots. The EIP-1967 slots are keccak-derived constants;
# the ZeppelinOS and EIP-1822 ("PROXIABLE") slots are legacy schemes still
# used in the wild (USDC's proxy, for instance, uses the ZeppelinOS slot).
PROXY_SLOTS = {
    "eip1967.implementation": bytes.fromhex(
        "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    ),
    "eip1967.admin": bytes.fromhex(
        "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    ),
    "eip1967.beacon": bytes.fromhex(
        "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
    ),
    "zeppelinos.implementation": keccak256(b"org.zeppelinos.proxy.implementation"),
    "zeppelinos.admin": keccak256(b"org.zeppelinos.proxy.admin"),
    "eip1822.proxiable": keccak256(b"PROXIABLE"),
}

# Focused alias for the standard scheme.
EIP1967_SLOTS = {
    "implementation": PROXY_SLOTS["eip1967.implementation"],
    "admin": PROXY_SLOTS["eip1967.admin"],
    "beacon": PROXY_SLOTS["eip1967.beacon"],
}


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_minimal_proxy(code: bytes) -> bool:
    return (
        len(code) == 45
        and code[:10] == EIP1167_PREFIX
        and code[-15:] == EIP1167_SUFFIX
    )


def minimal_proxy_target(code: bytes) -> str | None:
    if is_minimal_proxy(code):
        return "0x" + code[10:30].hex()
    return None


def eip1967_slots_present(code: bytes) -> list[str]:
    return [name for name, slot in PROXY_SLOTS.items() if slot in code]


# 0xffffffff / 0x00000000 show up next to SHR/AND as dispatch masks, not selectors.
_SELECTOR_MASKS = (b"\xff\xff\xff\xff", b"\x00\x00\x00\x00")


def extract_selectors(instrs) -> list[str]:
    """Recover 4-byte function selectors from the dispatch pattern.

    Old solc:  PUSH4 <selector>; EQ; PUSH2 <dest>; JUMPI
    New solc:  PUSH4 <selector>; PUSH1 0xe0; SHL; ...; EQ
    """
    found: list[str] = []
    for i, ins in enumerate(instrs):
        if ins.opcode != 0x63 or not ins.operand or len(ins.operand) != 4:
            continue
        if ins.operand in _SELECTOR_MASKS:
            continue
        window = instrs[i + 1 : i + 5]
        if any(w.mnemonic in ("EQ", "SHL", "SHR", "SAR") for w in window):
            sel = "0x" + ins.operand.hex()
            if sel not in found:
                found.append(sel)
    return found


def _build_signals(dis: Disassembly, counts: Counter) -> list[dict]:
    signals: list[dict] = []
    code = dis.code

    def add(level: str, message: str) -> None:
        signals.append({"level": level, "message": message})

    delegatecall = counts.get("DELEGATECALL", 0)
    callcode = counts.get("CALLCODE", 0)
    storage_writes = sum(counts.get(m, 0) for m in STORAGE_WRITE_OPS)
    unknown = sum(1 for i in dis.instructions if i.mnemonic.startswith("INVALID_0x"))
    slots = eip1967_slots_present(code)

    target = minimal_proxy_target(code)
    if target:
        add(
            "high",
            f"EIP-1167 minimal proxy: the real logic lives in another contract at {target}.",
        )
    if slots:
        add("notable", f"EIP-1967 upgradeable proxy slots referenced: {', '.join(slots)}.")
    if callcode:
        add("high", "CALLCODE present (deprecated delegate-execution opcode).")
    if delegatecall and storage_writes:
        add(
            "high",
            "DELEGATECALL combined with SSTORE: external code can mutate this "
            "contract's storage. Verify the delegate target is trusted and immutable.",
        )
    elif delegatecall and not storage_writes:
        add(
            "notable",
            "DELEGATECALL with no persistent storage writes: typical proxy/forwarder shape.",
        )
    if counts.get("SELFDESTRUCT", 0):
        add("notable", "SELFDESTRUCT present.")
    if counts.get("CREATE2", 0):
        add("info", "CREATE2 present: deploys at a deterministic address.")
    if unknown:
        add(
            "notable",
            f"{unknown} undefined opcode byte(s). Linear disassembly cannot tell data from "
            "code, so this is often embedded data (e.g. revert strings) -- but a high count "
            "can also indicate obfuscation. Verify before trusting it as a signal.",
        )
    if not extract_selectors(dis.instructions) and not target and len(dis.instructions) > 20:
        add("info", "No standard 4-byte dispatch detected; call surface is unusual.")
    return signals


def extract_features(dis: Disassembly) -> dict:
    instrs = dis.instructions
    counts: Counter = Counter(i.mnemonic for i in instrs)
    opcode_hist = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    external = {m: counts.get(m, 0) for m in EXTERNAL_CALL_OPS}
    storage_writes = sum(counts.get(m, 0) for m in STORAGE_WRITE_OPS)
    storage_reads = sum(counts.get(m, 0) for m in STORAGE_READ_OPS)
    create_ops = sum(counts.get(m, 0) for m in CREATE_OPS)
    log_count = sum(counts.get(m, 0) for m in LOG_OPS)
    unknown = sum(1 for i in instrs if i.mnemonic.startswith("INVALID_0x"))
    selectors = extract_selectors(instrs)
    slots = eip1967_slots_present(dis.code)
    minimal = is_minimal_proxy(dis.code)

    audit_notes = [
        {"opcode": m, "count": counts[m], "note": OPCODE_NOTES[m]}
        for m in OPCODE_NOTES
        if counts.get(m)
    ]
    audit_notes.sort(key=lambda d: d["count"], reverse=True)

    valid_jumps = sum(
        1
        for i in instrs
        if i.mnemonic in ("JUMP", "JUMPI") and i.target in dis.jumpdests
    )
    all_jumps = sum(1 for i in instrs if i.mnemonic in ("JUMP", "JUMPI"))

    return {
        "code_size": dis.raw_size,
        "stripped_size": len(dis.code),
        "instruction_count": len(instrs),
        "jumpdest_count": len(dis.jumpdests),
        "push_count": sum(1 for i in instrs if i.mnemonic.startswith("PUSH")),
        "unknown_opcode_count": unknown,
        "bytecode_entropy": round(byte_entropy(dis.code), 4),
        "opcode_counts": opcode_hist,
        "external_calls": external,
        "delegatecall_count": counts.get("DELEGATECALL", 0),
        "storage_writes": storage_writes,
        "storage_reads": storage_reads,
        "create_ops": create_ops,
        "log_count": log_count,
        "function_selectors": selectors,
        "is_minimal_proxy": minimal,
        "minimal_proxy_target": minimal_proxy_target(dis.code),
        "eip1967_slots": slots,
        "proxy_like": bool(
            minimal
            or slots
            or (counts.get("DELEGATECALL", 0) and storage_writes == 0)
        ),
        "jump_targets": {
            "total": all_jumps,
            "resolved_to_valid_jumpdest": valid_jumps,
        },
        "metadata": dis.metadata,
        "risk_signals": _build_signals(dis, counts),
        "audit_notes": audit_notes,
    }
