"""EIP-712 hashing, signature recovery, and on-chain domain verification.

Why this exists
---------------
An EIP-712 type string is opaque data to the compiler. `keccak256("Permit(...)")`
with a typo in a field name -- `adress` for `address` -- compiles, deploys, and
silently breaks every signature: the wallet hashes what the spec says, the
contract hashes what the typo says, and the digest never matches. The failure
is invisible because nothing reverts; the signature is simply invalid forever.

You cannot reliably find these by scraping deployed bytecode: solc constant-folds
`keccak256("...")` into a `PUSH32` of the resulting hash, so the offending string
is often not in the runtime code at all. So this module verifies at a level that
cannot lie:

1. Recompute the EIP-712 hashes from the declared structures (the same pure
   functions a wallet uses). Verified against the EIP-712 spec's own vectors.
2. Compare the recomputed domain separator against the contract's on-chain
   `DOMAIN_SEPARATOR()` and its ERC-5267 `eip712Domain()` declaration.
3. Optionally recover a real signature's signer -- the end-to-end proof that a
   given implementation accepts the signatures it is supposed to.

Everything in the "encoding" and "secp256k1" sections is pure and offline. Only
`verify_domain` / `verify_typed_data` touch the network.
"""

from __future__ import annotations

import sys

from .keccak import keccak256, selector
from .rpc import chain_id, eth_call
from .disasm import parse_hex

# ERC-5267 eip712Domain() and EIP-2612 DOMAIN_SEPARATOR(). Derived, not hardcoded,
# so the tests double as proof the selectors are what we think they are.
EIP712_DOMAIN_SELECTOR = selector("eip712Domain()")
DOMAIN_SEPARATOR_SELECTOR = selector("DOMAIN_SEPARATOR()")

# EIP-712 domain fields, in the order the spec fixes them. Anything absent is
# dropped from the type, and future fields must come after these.
CANONICAL_DOMAIN_FIELDS = (
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
)

_UINT256 = 1 << 256


def _finding(level: str, message: str) -> dict:
    return {"level": level, "message": message}


# ---------------------------------------------------------------------------
# Tiny ABI decode: only what eip712Domain()'s fixed return shape needs.
# ---------------------------------------------------------------------------
def _word(data: bytes, index: int) -> bytes:
    return data[index * 32 : (index + 1) * 32]


def _read_bytes(data: bytes, offset: int) -> bytes:
    if offset + 32 > len(data):
        raise ValueError("dynamic offset past end of return data")
    length = int.from_bytes(_word(data, offset // 32), "big")
    start = offset + 32
    if start + length > len(data):
        raise ValueError("dynamic payload past end of return data")
    return data[start : start + length]


def _read_string(data: bytes, offset: int) -> str:
    return _read_bytes(data, offset).decode("utf-8", "replace")


def _read_address(word: bytes) -> str:
    return "0x" + word[-20:].hex()


def decode_eip712_domain(return_hex: str) -> dict:
    """Decode the ERC-5267 `eip712Domain()` return value.

    Signature (ERC-5267):
        bytes1 fields, string name, string version, uint256 chainId,
        address verifyingContract, bytes32 salt, uint256[] extensions

    `fields` is a *bitmask* over CANONICAL_DOMAIN_FIELDS (bit i => field i
    present), not an array. Values for absent fields are unspecified and are
    deliberately not read.
    """
    data = parse_hex(return_hex)
    if len(data) < 7 * 32:
        raise ValueError("eip712Domain() return data is too short")
    fields = data[0]
    name = _read_string(data, int.from_bytes(_word(data, 1), "big"))
    version = _read_string(data, int.from_bytes(_word(data, 2), "big"))
    chain_id = int.from_bytes(_word(data, 3), "big")
    verifying = _read_address(_word(data, 4))
    salt = _word(data, 5)
    ext_off = int.from_bytes(_word(data, 6), "big")
    extensions: list[int] = []
    if ext_off:
        count = int.from_bytes(_word(data, ext_off // 32), "big")
        for i in range(count):
            extensions.append(int.from_bytes(_word(data, ext_off // 32 + 1 + i), "big"))

    values = {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": verifying,
        "salt": "0x" + salt.hex(),
    }
    present = [
        key for i, (key, _t) in enumerate(CANONICAL_DOMAIN_FIELDS) if fields & (1 << i)
    ]
    return {
        "fields_byte": fields,
        "present": present,
        "domain": {key: values[key] for key in present},
        "extensions": extensions,
    }


# ---------------------------------------------------------------------------
# EIP-712 encoding. Pure; verified against the spec's Mail example in tests.
# ---------------------------------------------------------------------------
def _fields(types: dict, name: str) -> list[tuple[str, str]]:
    """Normalize a JSON-schema types entry to an ordered list of (type, name)."""
    raw = types.get(name)
    if raw is None:
        raise ValueError(f"type '{name}' is not defined")
    return [(f["type"], f["name"]) for f in raw]


def _base_type(type_name: str) -> str:
    import re

    return re.sub(r"\[[0-9]*\]", "", type_name)


def _dependencies(name: str, types: dict, seen: set[str]) -> None:
    for type_name, _field_name in _fields(types, name):
        base = _base_type(type_name)
        if base != name and base in types and base not in seen:
            seen.add(base)
            _dependencies(base, types, seen)


def _one_type(name: str, types: dict) -> str:
    members = ",".join(f"{t} {n}" for t, n in _fields(types, name))
    return f"{name}({members})"


def encode_type(primary: str, types: dict) -> str:
    """EIP-712 `encodeType`: primary type, then referenced structs sorted by name."""
    deps: set[str] = set()
    _dependencies(primary, types, deps)
    parts = [_one_type(primary, types)]
    parts.extend(_one_type(name, types) for name in sorted(deps))
    return "".join(parts)


def type_hash(primary: str, types: dict) -> bytes:
    return keccak256(encode_type(primary, types).encode("ascii"))


def _as_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return parse_hex(value)
    raise ValueError(f"cannot read bytes from {value!r}")


def _encode_value(type_name: str, value, types: dict) -> bytes:
    if type_name == "string":
        return keccak256(str(value).encode("utf-8"))
    if type_name == "bytes":
        return keccak256(_as_bytes(value))
    if type_name == "bool":
        return (1 if value else 0).to_bytes(32, "big")
    if type_name == "address":
        n = int(value, 16) if isinstance(value, str) else int(value)
        return (n & ((1 << 160) - 1)).to_bytes(32, "big")
    if type_name.startswith("uint") or type_name.startswith("int"):
        return (int(value) % _UINT256).to_bytes(32, "big")
    if type_name.startswith("bytes") and type_name[5:].isdigit():
        n = int(type_name[5:])
        raw = _as_bytes(value)[:n]
        return raw + b"\x00" * (32 - len(raw))
    if type_name.endswith("]"):
        inner = type_name[: type_name.rindex("[")]
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"array type {type_name} needs a list value")
        return keccak256(b"".join(_encode_value(inner, v, types) for v in value))
    if type_name in types:
        return hash_struct(type_name, types, value)
    raise ValueError(f"unsupported EIP-712 type '{type_name}'")


def hash_struct(primary: str, types: dict, data: dict) -> bytes:
    encoded = bytearray()
    for type_name, field_name in _fields(types, primary):
        if field_name not in data:
            raise ValueError(
                f"value for '{primary}.{field_name}' is missing; "
                "the declared type does not match the data"
            )
        encoded += _encode_value(type_name, data[field_name], types)
    return keccak256(type_hash(primary, types) + bytes(encoded))


def _canonical_domain_types(domain: dict) -> list[dict]:
    return [
        {"name": name, "type": type_name}
        for name, type_name in CANONICAL_DOMAIN_FIELDS
        if name in domain
    ]


def domain_separator(domain: dict, types: dict | None = None, order: list[str] | None = None) -> bytes:
    """Compute the EIP-712 domain separator.

    `types` may carry an explicit EIP712Domain definition (a signed payload
    does). Otherwise fields are taken in the canonical order, skipping absent
    ones. `order` pins the field order explicitly (e.g. from a bitmask).
    """
    if types and types.get("EIP712Domain"):
        return hash_struct("EIP712Domain", types, domain)
    if order is not None:
        declared = [{"name": k, "type": dict(CANONICAL_DOMAIN_FIELDS)[k]} for k in order]
    else:
        declared = _canonical_domain_types(domain)
    return hash_struct("EIP712Domain", {"EIP712Domain": declared}, domain)


def hash_typed_data(domain: dict, types: dict, primary_type: str, message: dict) -> bytes:
    """The 32-byte digest an EIP-712 signer signs: keccak256(0x1901 || dom || msg)."""
    dom = domain_separator(domain, types)
    msg = hash_struct(primary_type, types, message)
    return keccak256(b"\x19\x01" + dom + msg)


# ---------------------------------------------------------------------------
# secp256k1 public-key recovery (pure Python -- no coincurve, no ecdsa).
# ---------------------------------------------------------------------------
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    y = (lam * (p[0] - x) - p[1]) % _P
    return (x, y)


def _mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def recover_public_key(digest: bytes, v: int, r: int, s: int):
    """Recover the secp256k1 public key that signed `digest`. Returns (x, y)."""
    if v >= 35:  # EIP-155: v = chainId * 2 + 35/36
        recid = (v - 35) % 2
    elif v in (27, 28):
        recid = v - 27
    elif v in (0, 1):
        recid = v
    else:
        raise ValueError(f"unrecognised recovery id / v value: {v}")
    if not (1 <= r < _N and 1 <= s < _N):
        raise ValueError("r or s is out of range for secp256k1")

    x = r + (recid // 2) * _N
    if x >= _P:
        raise ValueError("recovered x is not on the curve")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if y * y % _P != y_sq:
        raise ValueError("point is not on secp256k1")
    if (y & 1) != (recid & 1):
        y = _P - y
    point_r = (x, y)

    z = int.from_bytes(digest, "big") % _N
    neg_z_g = _mul(z, _G)
    neg_z_g = (neg_z_g[0], (-neg_z_g[1]) % _P) if neg_z_g else None
    numerator = _add(_mul(s, point_r), neg_z_g)
    return _mul(pow(r, -1, _N), numerator)


def to_checksum_address(address: str) -> str:
    """EIP-55 mixed-case checksum, so a human can eyeball a signer address."""
    addr = address[2:].lower() if address.startswith("0x") else address.lower()
    digest = keccak256(addr.encode("ascii")).hex()
    body = "".join(
        char.upper() if int(digest[i], 16) >= 8 else char for i, char in enumerate(addr)
    )
    return "0x" + body


def public_key_to_address(point) -> str:
    if point is None:
        raise ValueError("cannot derive an address from an invalid public key")
    raw = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return to_checksum_address("0x" + keccak256(raw)[12:].hex())


def recover_address(digest: bytes, signature: str | bytes) -> str:
    """Recover the signer address from a 65-byte r||s||v signature."""
    sig = _as_bytes(signature) if isinstance(signature, str) else bytes(signature)
    if len(sig) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(sig)}")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    return public_key_to_address(recover_public_key(digest, v, r, s))


# ---------------------------------------------------------------------------
# Verification: pure comparison, then the networked wrapper.
# ---------------------------------------------------------------------------
def _norm32(value: str) -> str:
    raw = value[2:] if value.startswith("0x") else value
    return "0x" + raw.rjust(64, "0").lower()


def check_domain(
    declared: dict,
    onchain_separator: str | None,
    node_chain_id: int | None = None,
    address: str | None = None,
) -> dict:
    """Pure comparison of a declared domain against on-chain facts."""
    findings: list[dict] = []
    recomputed = "0x" + domain_separator(declared).hex()
    match: bool | None = None

    if onchain_separator:
        onchain = _norm32(onchain_separator)
        match = recomputed == onchain
        if match:
            findings.append(_finding(
                "info",
                "The declared EIP-712 domain hashes to the contract's on-chain "
                "DOMAIN_SEPARATOR(). Wallets that sign this domain will be verified.",
            ))
        else:
            findings.append(_finding(
                "high",
                "The declared EIP-712 domain does NOT hash to the contract's "
                "DOMAIN_SEPARATOR(). Signatures a wallet produces from this domain "
                "will be rejected on-chain. This is the silent EIP-712 failure.",
            ))
    else:
        findings.append(_finding(
            "notable",
            "The contract declares an EIP-712 domain but exposes no "
            "DOMAIN_SEPARATOR() to check it against, so it cannot be verified here.",
        ))

    if node_chain_id is not None and "chainId" in declared:
        if int(declared["chainId"]) != node_chain_id:
            findings.append(_finding(
                "high",
                f"Declared chainId {declared['chainId']} does not match this chain "
                f"({node_chain_id}). Signatures are bound to the wrong chain, or the "
                "domain was copied from another deployment.",
            ))
    if address and "verifyingContract" in declared:
        if str(declared["verifyingContract"]).lower() != address.lower():
            findings.append(_finding(
                "notable",
                f"Declared verifyingContract {declared['verifyingContract']} is not the "
                f"queried address {address}. Confirm that is intended.",
            ))

    return {
        "recomputed_separator": recomputed,
        "onchain_separator": _norm32(onchain_separator) if onchain_separator else None,
        "match": match,
        "findings": findings,
    }


def verify_domain(address: str, rpc_url: str | None = None, expected: dict | None = None) -> dict:
    """Verify a contract's EIP-712 domain against its on-chain facts.

    `expected` (e.g. {"name": "USD Coin", "version": "2"}) lets you verify
    pre-ERC-5267 contracts that only expose DOMAIN_SEPARATOR().
    """
    result: dict = {
        "address": address,
        "node_chain_id": None,
        "declared_domain": None,
        "declaration_source": None,
        "has_domain_separator": False,
        "onchain_separator": None,
        "findings": [],
    }

    try:
        result["node_chain_id"] = chain_id(rpc_url)
    except Exception:
        pass

    for step in ("separator", "declaration"):
        try:
            if step == "separator":
                separator = eth_call(address, DOMAIN_SEPARATOR_SELECTOR, rpc_url)
                if separator and separator not in ("0x", "0x0"):
                    result["onchain_separator"] = _norm32(separator)
                    result["has_domain_separator"] = True
            else:
                raw = eth_call(address, EIP712_DOMAIN_SELECTOR, rpc_url)
                if raw and raw != "0x":
                    decoded = decode_eip712_domain(raw)
                    result["declared_domain"] = decoded["domain"]
                    result["declaration_source"] = "ERC-5267 eip712Domain()"
                    result["extensions"] = decoded["extensions"]
        except Exception:
            # A reverting call just means "not implemented". Keep going: the
            # other probe may still succeed, and a partial verdict beats none.
            pass

    declared = result["declared_domain"]
    if declared is None and expected:
        declared = dict(expected)
        declared.setdefault("verifyingContract", address)
        if result["node_chain_id"] is not None:
            declared.setdefault("chainId", result["node_chain_id"])
        result["declaration_source"] = "supplied expectation (no ERC-5267)"
    result["declared_domain"] = declared

    if declared is None:
        if result["has_domain_separator"]:
            result["findings"].append(_finding(
                "notable",
                "Contract exposes DOMAIN_SEPARATOR() but has no ERC-5267 "
                "eip712Domain(). Re-run with --name/--version to verify it.",
            ))
        else:
            result["findings"].append(_finding(
                "info",
                "No EIP-712 domain found on this contract. It may not use typed-data "
                "signatures at all.",
            ))
        return result

    result.update(check_domain(
        declared, result["onchain_separator"], result["node_chain_id"], address
    ))
    return result


def verify_typed_data(payload: dict, rpc_url: str | None = None, expected_signer: str | None = None,
                      signature: str | None = None, check_domain: bool = False) -> dict:
    """Verify a signed (or to-be-signed) EIP-712 payload.

    Computes the digest, and if the payload names a verifyingContract that is
    reachable, checks that the payload's domain separator matches the contract's
    on-chain DOMAIN_SEPARATOR(). With `signature`, recovers the actual signer.
    """
    domain = payload.get("domain", {}) or {}
    types = payload.get("types", {}) or {}
    primary = payload.get("primaryType") or payload.get("primary_type")
    message = payload.get("message", {}) or {}

    result: dict = {
        "primaryType": primary,
        "domain": domain,
        "digest": None,
        "signer": None,
        "findings": [],
    }
    if not primary:
        result["findings"].append(_finding("info", "Payload has no primaryType; nothing to hash."))
        return result

    try:
        digest = hash_typed_data(domain, types, primary, message)
    except (ValueError, KeyError) as exc:
        result["findings"].append(_finding(
            "notable", f"Could not compute the EIP-712 digest: {exc}"
        ))
        return result
    result["digest"] = "0x" + digest.hex()

    if signature:
        try:
            signer = recover_address(digest, signature)
            result["signer"] = signer
            result["findings"].append(_finding("info", f"Signature recovers to {signer}."))
            if expected_signer and signer.lower() != expected_signer.lower():
                result["findings"].append(_finding(
                    "high",
                    f"Recovered signer {signer} is NOT the expected {expected_signer}.",
                ))
        except ValueError as exc:
            result["findings"].append(_finding("high", f"Signature could not be recovered: {exc}"))

    verifying = domain.get("verifyingContract")
    if check_domain and verifying:
        try:
            separator = eth_call(verifying, DOMAIN_SEPARATOR_SELECTOR, rpc_url)
            if separator and separator not in ("0x", "0x0"):
                onchain = _norm32(separator)
                local = "0x" + domain_separator(domain, types).hex()
                if local != onchain:
                    result["findings"].append(_finding(
                        "high",
                        "This payload's domain does not match the verifying contract's "
                        f"DOMAIN_SEPARATOR(). Local {local}, on-chain {onchain}. A wallet "
                        "signing it will produce a signature the contract rejects.",
                    ))
                else:
                    result["findings"].append(_finding(
                        "info", "Payload domain matches the verifying contract's on-chain separator.",
                    ))
        except Exception:
            pass

    if not any(f["level"] == "high" for f in result["findings"]):
        result["findings"].append(_finding("info", "No EIP-712 mismatches detected."))
    return result


# ---------------------------------------------------------------------------
# Batch mode: the measurement, not the claim.
#
# The "silent EIP-712 failure" is usually described with a number nobody can
# trace. This runs the domain check over a corpus of contracts and reports what
# was actually observed, so the prevalence is a fact rather than a talking point.
# ---------------------------------------------------------------------------
def classify(result: dict) -> str:
    """Reduce a verify_domain result to one auditable outcome.

    The vocabulary matters: `unverified` (no separator exposed) is deliberately
    NOT folded into `ok`, so a corpus full of contracts that cannot be checked
    never looks like a clean bill of health.
    """
    if result.get("has_domain_separator") is not True:
        # Nothing to compare against. `no_domain` means the contract does not use
        # EIP-712 at all; `unverified` means it does but exposes no separator.
        return "no_domain" if result.get("declared_domain") is None else "unverified"

    match = result.get("match")
    if match is True:
        return "mismatch" if _has_high(result) else "ok"
    if match is False:
        return "mismatch"
    # Separator exists but no domain was declared or supplied for it.
    return "no_domain" if result.get("declared_domain") is None else "uncompared"


def _has_high(result: dict) -> bool:
    return any(f["level"] == "high" for f in result.get("findings", []))


def batch_verify(entries: list[dict], rpc_url: str | None = None, quiet: bool = False) -> dict:
    """Run verify_domain over parsed corpus entries and tally the outcomes.

    `entries` come from `read_corpus`: {"address", "name", "version", "chainId"}.
    A per-entry name/version is passed through as `expected`, which is what lets
    pre-ERC-5267 tokens (USDC, DAI) be checked instead of skipped.
    """
    rows: list[dict] = []
    counts: dict[str, int] = {}
    total = len(entries)

    for index, entry in enumerate(entries, start=1):
        address = entry["address"]
        expected = {
            key: entry[key]
            for key in ("name", "version", "chainId")
            if entry.get(key) is not None
        }
        if not quiet:
            print(f"[{index:>3}/{total}] {address}", file=sys.stderr, flush=True)
        try:
            info = verify_domain(address, rpc_url, expected or None)
            status = classify(info)
            highs = [f["message"] for f in info["findings"] if f["level"] == "high"]
        except Exception as exc:  # transport failure is not a contract verdict
            status = "error"
            info = {"address": address}
            highs = [str(exc)]
        counts[status] = counts.get(status, 0) + 1
        rows.append({
            "address": address,
            "status": status,
            "declared_by": info.get("declaration_source"),
            "separator": info.get("onchain_separator"),
            "recomputed": info.get("recomputed_separator"),
            "findings": highs,
        })

    checked = counts.get("ok", 0) + counts.get("mismatch", 0)
    mismatches = counts.get("mismatch", 0)
    return {
        "total": total,
        "counts": counts,
        "checked": checked,
        "mismatch_rate": (mismatches / checked) if checked else None,
        "rows": rows,
    }


def read_corpus(text: str) -> list[dict]:
    """Parse a corpus file: one entry per line, `#` starts a comment.

    Accepted forms (the name may contain spaces, so quote it):

        <address>
        <address>  "Name"
        <address>  "Name"  <version>
        <address>  "Name"  <version>  <chainId>

    An entry with no name can only be checked if the contract implements
    ERC-5267; otherwise it will report `unverified`, not a guess.
    """
    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_quoted(line)
        if not parts:
            continue
        entry = {"address": parts[0], "name": None, "version": None, "chainId": None}
        if len(parts) > 1:
            entry["name"] = parts[1]
        if len(parts) > 2:
            entry["version"] = parts[2]
        if len(parts) > 3:
            try:
                entry["chainId"] = int(parts[3])
            except ValueError:
                pass
        entries.append(entry)
    return entries


def _split_quoted(line: str) -> list[str]:
    """Split on whitespace, keeping "quoted strings" (and simple escapes) whole."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    escaped = False
    for char in line:
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = None
            else:
                buf.append(char)
        elif char in ("'", '"'):
            quote = char
        elif char.isspace():
            if buf:
                parts.append("".join(buf))
                buf = []
        else:
            buf.append(char)
    if buf:
        parts.append("".join(buf))
    return parts
