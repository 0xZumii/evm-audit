"""Resolve a proxy's implementation target on-chain.

Auditing a proxy means auditing *two* things: the entry contract (which
holds storage and permissions) and the implementation it delegates to.
This reads known proxy storage slots via eth_getStorageAt and handles
EIP-1167 minimal proxies from bytecode.

Supported slot schemes: EIP-1967, ZeppelinOS (used by USDC's proxy),
EIP-1967 beacon, and EIP-1822 in bytecode detection.
"""

from __future__ import annotations

from . import rpc
from .disasm import parse_hex
from .features import PROXY_SLOTS, is_minimal_proxy, minimal_proxy_target

_IMPLEMENTATION_SLOTS = ("eip1967.implementation", "zeppelinos.implementation")
_ADMIN_SLOTS = ("eip1967.admin", "zeppelinos.admin")
_BEACON_SLOTS = ("eip1967.beacon",)


def _word_to_address(word_hex: str | None) -> str | None:
    if not word_hex:
        return None
    raw = word_hex[2:] if word_hex.startswith("0x") else word_hex
    raw = raw.rjust(64, "0")
    addr = raw[-40:]
    return None if int(addr, 16) == 0 else "0x" + addr


def _read_first(address: str, slot_names, rpc_url: str | None) -> tuple[str | None, str | None]:
    """Return (address, slot_name) for the first non-empty known slot."""
    for name in slot_names:
        word = rpc.get_storage_at(address, "0x" + PROXY_SLOTS[name].hex(), rpc_url)
        addr = _word_to_address(word)
        if addr:
            return addr, name
    return None, None


def resolve_implementation(address: str, rpc_url: str | None = None) -> dict:
    code_hex = rpc.get_code(address, rpc_url)
    info = {
        "address": address,
        "kind": "regular contract",
        "implementation": None,
        "implementation_slot": None,
        "admin": None,
        "beacon": None,
    }
    if code_hex in ("0x", "0x0"):
        info["kind"] = "not a contract (EOA or wrong chain)"
        return info

    if is_minimal_proxy(parse_hex(code_hex)):
        info["kind"] = "EIP-1167 minimal proxy"
        info["implementation"] = minimal_proxy_target(parse_hex(code_hex))
        return info

    info["implementation"], info["implementation_slot"] = _read_first(
        address, _IMPLEMENTATION_SLOTS, rpc_url
    )
    info["admin"], _ = _read_first(address, _ADMIN_SLOTS, rpc_url)
    info["beacon"], _ = _read_first(address, _BEACON_SLOTS, rpc_url)
    if info["implementation"] or info["beacon"]:
        scheme = (info["implementation_slot"] or "eip1967.beacon").split(".")[0]
        info["kind"] = f"{scheme} upgradeable proxy"
    return info
