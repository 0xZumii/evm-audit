"""Signature- and calldata-level analysis: the surface bytecode cannot see.

Most current wallet drains do not come from a malicious *contract*. They
come from a malicious *message*: an approval, an operator grant, or an
EIP-712 permit. The contract is often legitimate; the payload is the attack.
This module decodes those payloads and says what you are actually authorizing.
"""

from __future__ import annotations

from .abi import MAX_UINT160, MAX_UINT256, decode_args
from .disasm import parse_hex
from .keccak import selector as selector_of

# ---------------------------------------------------------------------------
# Known function signatures. Selectors are derived, not hardcoded, so the
# table doubles as documentation of how selectors work.
# kind: approval | operator | transfer | permit | permit2-approval | permit2-permit
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, dict] = {
    "approve(address,uint256)": {
        "label": "ERC-20 approve", "risk": "high", "kind": "approval",
        "params": ["address", "uint256"], "names": ["spender", "amount"],
    },
    "increaseAllowance(address,uint256)": {
        "label": "ERC-20 increaseAllowance", "risk": "high", "kind": "approval",
        "params": ["address", "uint256"], "names": ["spender", "amount"],
    },
    "setApprovalForAll(address,bool)": {
        "label": "ERC-721/1155 setApprovalForAll", "risk": "high", "kind": "operator",
        "params": ["address", "bool"], "names": ["operator", "approved"],
    },
    "transferFrom(address,address,uint256)": {
        "label": "ERC-20/721 transferFrom", "risk": "notable", "kind": "transfer",
        "params": ["address", "address", "uint256"], "names": ["from", "to", "amount"],
    },
    "safeTransferFrom(address,address,uint256)": {
        "label": "ERC-721 safeTransferFrom", "risk": "notable", "kind": "transfer",
        "params": ["address", "address", "uint256"], "names": ["from", "to", "tokenId"],
    },
    "safeTransferFrom(address,address,uint256,bytes)": {
        "label": "ERC-721 safeTransferFrom (with data)", "risk": "notable", "kind": "transfer",
        "params": ["address", "address", "uint256", "bytes"], "names": ["from", "to", "tokenId", "data"],
    },
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": {
        "label": "EIP-2612 permit (gasless approval)", "risk": "high", "kind": "permit",
        "params": ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
        "names": ["owner", "spender", "value", "deadline", "v", "r", "s"],
    },
    "approve(address,address,uint160,uint48)": {
        "label": "Permit2 approve (token, spender, amount, expiration)",
        "risk": "high", "kind": "permit2-approval",
        "params": ["address", "address", "uint160", "uint48"],
        "names": ["token", "spender", "amount", "expiration"],
    },
    # PermitSingle is a fully-static tuple, so it flattens into head words.
    "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)": {
        "label": "Permit2 permit (signature-based)", "risk": "high", "kind": "permit2-permit",
        "params": ["address", "address", "uint160", "uint48", "uint48", "address", "uint256", "bytes"],
        "names": ["owner", "token", "amount", "expiration", "nonce", "spender", "sigDeadline", "signature"],
    },
    "permitBatch(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)": {
        "label": "Permit2 permitBatch (multiple tokens, one signature)",
        "risk": "high", "kind": "permit2-batch", "params": None, "names": None,
    },
}

BY_SELECTOR: dict[str, dict] = {
    selector_of(sig): {"sig": sig, **meta} for sig, meta in SIGNATURES.items()
}


def _finding(level: str, message: str) -> dict:
    return {"level": level, "message": message}


def _analyze_known(entry: dict, args: dict, result: dict) -> None:
    kind = entry["kind"]
    if kind == "approval":
        amount = args.get("amount")
        if amount == MAX_UINT256:
            result["findings"].append(_finding(
                "high",
                f"UNLIMITED approval: spender {args.get('spender')} can move ALL of that token.",
            ))
        else:
            result["findings"].append(_finding(
                "notable",
                f"Grants spender {args.get('spender')} an allowance of {amount}.",
            ))
    elif kind == "operator":
        if args.get("approved"):
            result["findings"].append(_finding(
                "high",
                f"Grants operator {args.get('operator')} control over ALL of your tokens in this collection.",
            ))
        else:
            result["findings"].append(_finding("info", "Revokes an operator approval."))
    elif kind == "permit":
        if args.get("value") == MAX_UINT256:
            result["findings"].append(_finding(
                "high",
                f"UNLIMITED permit: spender {args.get('spender')} can move ALL of that token via signature.",
            ))
        else:
            result["findings"].append(_finding(
                "notable",
                f"Signature authorizes spender {args.get('spender')} for {args.get('value')}.",
            ))
    elif kind == "permit2-approval":
        amount = args.get("amount")
        if amount in (MAX_UINT160, MAX_UINT256):
            result["findings"].append(_finding(
                "high",
                f"UNLIMITED Permit2 approval: spender {args.get('spender')} can move ALL of {args.get('token')}.",
            ))
        else:
            result["findings"].append(_finding(
                "notable", f"Permit2 approval of {amount} for spender {args.get('spender')}."
            ))
    elif kind == "permit2-permit":
        amount = args.get("amount")
        if amount in (MAX_UINT160, MAX_UINT256):
            result["findings"].append(_finding(
                "high",
                f"UNLIMITED Permit2 permit: spender {args.get('spender')} can move ALL of {args.get('token')}.",
            ))
        else:
            result["findings"].append(_finding(
                "notable", f"Permit2 permit of {amount} for spender {args.get('spender')}."
            ))
    elif kind == "transfer":
        result["findings"].append(_finding(
            "notable",
            f"Moves assets from {args.get('from')} to {args.get('to')}. "
            "If 'from' is you and you did not initiate this, it is a drain.",
        ))


def analyze_calldata(data_hex: str) -> dict:
    data = parse_hex(data_hex)
    if len(data) < 4:
        return {"error": "calldata is shorter than a 4-byte selector"}
    sel = "0x" + data[:4].hex()
    entry = BY_SELECTOR.get(sel)
    result: dict = {
        "selector": sel, "known": bool(entry), "signature": None,
        "label": None, "risk": None, "args": [], "findings": [],
    }
    if not entry:
        result["findings"].append(_finding(
            "info",
            "Unknown selector; not in the local table. Look it up on a 4byte database, "
            "and treat unknown approvals/permits as suspicious.",
        ))
        return result
    result["signature"] = entry["sig"]
    result["label"] = entry["label"]
    result["risk"] = entry["risk"]
    if entry.get("params"):
        values = decode_args(entry["params"], data[4:])
        names = entry["names"] or entry["params"]
        for name, type_name, value in zip(names, entry["params"], values):
            result["args"].append({"name": name, "type": type_name, "value": value})
        _analyze_known(entry, {a["name"]: a["value"] for a in result["args"]}, result)
    else:
        result["findings"].append(_finding(
            "notable", "Recognized, but this decoder does not expand its arguments.",
        ))
    return result


# ---------------------------------------------------------------------------
# EIP-712 typed data (eth_signTypedData_v4 payloads)
# ---------------------------------------------------------------------------
RISKY_PRIMARY_TYPES = {
    "Permit", "PermitSingle", "PermitBatch",
    "PermitTransferFrom", "PermitBatchTransferFrom", "PermitTransferFromWithPermit",
}

_UNLIMITED_MARKERS = {MAX_UINT256, MAX_UINT160}


def _flatten(prefix: str, value, out: list[tuple[str, object]]) -> None:
    if isinstance(value, dict):
        for key, sub in value.items():
            _flatten(f"{prefix}{key}.", sub, out)
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            _flatten(f"{prefix}[{i}].", sub, out)
    else:
        out.append((prefix.rstrip("."), value))


def analyze_typed_data(payload: dict) -> dict:
    domain = payload.get("domain", {}) or {}
    primary = payload.get("primaryType") or payload.get("primary_type")
    message = payload.get("message", {}) or {}

    fields: list[tuple[str, object]] = []
    _flatten("", message, fields)

    findings: list[dict] = []
    if primary in RISKY_PRIMARY_TYPES:
        findings.append(_finding(
            "high",
            f"'{primary}' is a signing authorization, not a transaction. "
            "Approving it can move or unlock assets without a further confirmation.",
        ))
    for path, value in fields:
        if isinstance(value, int) and value in _UNLIMITED_MARKERS:
            findings.append(_finding(
                "high", f"Unlimited value at '{path}': {value} (max for its type)."
            ))
    for path, value in fields:
        if isinstance(path, str) and path.split(".")[-1].lower() in (
            "spender", "operator", "to", "recipient",
        ) and isinstance(value, str) and value.startswith("0x"):
            findings.append(_finding(
                "notable", f"Counterparty '{path}' = {value}. Verify this address is trusted."
            ))
    vc = domain.get("verifyingContract")
    if vc:
        findings.append(_finding(
            "info", f"Signed against contract {vc}. Confirm it is the token/protocol you expect."
        ))
    if not any(f["level"] == "high" for f in findings):
        findings.append(_finding("info", "No high-risk typed-data patterns detected."))

    return {
        "primaryType": primary,
        "domain": {
            "name": domain.get("name"),
            "version": domain.get("version"),
            "chainId": domain.get("chainId"),
            "verifyingContract": vc,
        },
        "fields": [{"path": p, "value": v} for p, v in fields],
        "findings": findings,
    }
