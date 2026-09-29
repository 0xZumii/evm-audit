"""EVM opcode reference table.

Plain data on purpose: read it while you learn. Coverage reflects
Shanghai (PUSH0), Cancun (TLOAD/TSTORE/MCOPY/BLOBHASH/BLOBBASEFEE)
and the invalid/EOF-reserved ranges.
"""

from __future__ import annotations

OPCODES: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

for _i in range(1, 33):  # PUSH1..PUSH32 = 0x60..0x7f
    OPCODES[0x5F + _i] = f"PUSH{_i}"
for _i in range(1, 17):  # DUP1..DUP16 = 0x80..0x8f
    OPCODES[0x7F + _i] = f"DUP{_i}"
for _i in range(1, 17):  # SWAP1..SWAP16 = 0x90..0x9f
    OPCODES[0x8F + _i] = f"SWAP{_i}"
for _i in range(0, 5):   # LOG0..LOG4 = 0xa0..0xa4
    OPCODES[0xA0 + _i] = f"LOG{_i}"

PUSH_OPS = frozenset(range(0x60, 0x80))
DUP_OPS = frozenset(range(0x80, 0x90))
SWAP_OPS = frozenset(range(0x90, 0xA0))
LOG_OPS = frozenset(range(0xA0, 0xA5))

EXTERNAL_CALL_OPS = ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL")
CREATE_OPS = ("CREATE", "CREATE2")
STORAGE_WRITE_OPS = ("SSTORE", "TSTORE")
STORAGE_READ_OPS = ("SLOAD", "TLOAD")

# Short notes used to explain findings in plain language.
OPCODE_NOTES: dict[str, str] = {
    "DELEGATECALL": (
        "Runs another contract's code inside THIS contract's storage and balance. "
        "Whoever controls the delegate target controls this contract."
    ),
    "CALLCODE": "Legacy, deprecated; delegates execution like DELEGATECALL. Treat as high risk.",
    "CALL": "Sends a message (and optionally value) to another address.",
    "STATICCALL": "External call that cannot modify state.",
    "SELFDESTRUCT": (
        "Destroys the contract and sends its balance to a target "
        "(only still effective for contracts created before Cancun)."
    ),
    "CREATE2": "Deploys at a deterministic address; used by factories and, sometimes, by drainers.",
    "SSTORE": "Writes persistent storage. This is how approvals, owners and balances get altered.",
    "TSTORE": "Writes transient storage (discarded at end of transaction).",
    "JUMPI": "Conditional jump: control-flow decisions live here.",
    "KECCAK256": "Hashes memory/calldata, usually for storage-slot derivation or signatures.",
    "CALLDATALOAD": "Reads a 32-byte word from caller-supplied calldata. Attackers control this input.",
    "SLOAD": "Reads persistent storage.",
}
