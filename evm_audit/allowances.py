"""Approval exposure: what can be taken from an address, without another signature.

The problem this exists for
---------------------------
Every other command here reads a payload: "what does this calldata / typed data
do?" This one asks the opposite question -- *forget payloads. What can be done
to this address without any further signature?*

An approval is a standing instruction. It outlives the transaction that created
it, survives the dapp that requested it, and is exercisable by whoever controls
the spender at any future moment. A wallet shows you the request in front of
you, and an approval's whole nature is that it is no longer in front of you.

How the set is assembled -- and where it is incomplete
------------------------------------------------------
There is no on-chain enumerator for allowances. `allowance(owner, spender)`
needs the spender; nothing returns a list of spenders. The only discovery
surface is the log:

    Approval(owner, spender, value)           ERC-20. ERC-721's per-tokenId
                                              approval uses the SAME topic.
    ApprovalForAll(owner, operator, bool)     ERC-721/1155 operator grants.
    Permit2 Approval/Permit(owner, token,     Permit2 allowances. Emitted by the
        spender, amount, expiration)          Permit2 contract, not the token.

Logs are the crude sieve; the state read is the truth. A log says an approval
went in at some block. Only `allowance()`, `isApprovedForAll()` and Permit2's
`allowance()` say whether it is still there *now*. Every candidate is therefore
re-read from current state before it is reported, and a candidate whose state
cannot be read is `unreadable` -- never `revoked`.

The incompleteness is real and printed, not hidden: log discovery sees only
approvals granted inside the scanned block range, and only on the token
contracts supplied. An approval granted in 2021 on a token that is not in the
list is invisible here. "No active approvals found" means "none found in what
was scanned" -- it is never "safe".
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone

from .abi import MAX_UINT160
from .disasm import parse_hex
from .eip712 import read_corpus, to_checksum_address
from .keccak import keccak256, selector as selector_of
from .rpc import chain_id, eth_call, get_block_number, get_code, get_logs

# ---------------------------------------------------------------------------
# Signatures, topics and selectors, derived with keccak rather than typed in.
# A mistyped topic would silently filter every log away and the report would
# look like a clean address, so tests assert the derivations against published
# values (0x8c5be1e5... for Approval, 0xdd62ed3e for allowance(), ...) and the
# Permit2 topics are checked against real logs on-chain.
# ---------------------------------------------------------------------------


def _topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()


APPROVAL_TOPIC = _topic("Approval(address,address,uint256)")
APPROVAL_FOR_ALL_TOPIC = _topic("ApprovalForAll(address,address,bool)")
PERMIT2_APPROVAL_TOPIC = _topic("Approval(address,address,address,uint160,uint48)")
PERMIT2_PERMIT_TOPIC = _topic("Permit(address,address,address,uint160,uint48)")

ALLOWANCE_SELECTOR = selector_of("allowance(address,address)")
IS_APPROVED_FOR_ALL_SELECTOR = selector_of("isApprovedForAll(address,address)")
PERMIT2_ALLOWANCE_SELECTOR = selector_of("allowance(address,address,address)")
BALANCE_OF_SELECTOR = selector_of("balanceOf(address)")
SYMBOL_SELECTOR = selector_of("symbol()")
DECIMALS_SELECTOR = selector_of("decimals()")

PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
ZERO_ADDRESS = "0x" + "00" * 20
MAX_UINT48 = (1 << 48) - 1

# An allowance that is not exactly uint256-max is still "infinite" in practice:
# protocols commonly approve max minus a small reserve, and no real balance can
# approach 2**255. Without reading total supply there is no honest way to call a
# smaller number unlimited, so this is the line. Permit2's amount is uint160.
UNLIMITED_ERC20 = 1 << 255
UNLIMITED_PERMIT2 = 1 << 159

# All four events put the owner at topic 1, which is what lets the whole
# surface be discovered in a single `eth_getLogs` filter instead of one query
# per event kind.
APPROVAL_TOPICS = [
    APPROVAL_TOPIC,
    APPROVAL_FOR_ALL_TOPIC,
    PERMIT2_APPROVAL_TOPIC,
    PERMIT2_PERMIT_TOPIC,
]

# Initial number of token addresses per `eth_getLogs` filter. Public nodes cap
# this (PublicNode refuses more than nine addresses in one filter) and the cap
# is undocumented and provider-specific, so a rejected filter is split
# automatically -- see _LogFetcher. Eight stays under the observed cap; a
# stricter provider still works, just with smaller filters.
ADDRESS_CHUNK = 8

# A non-exhaustive seed of deep-liquidity mainnet tokens, used when --tokens is
# omitted. Ten addresses cannot be "all tokens" and the report says so out
# loud. Supply a real list -- any token list JSON's `address` fields -- for a
# scan that means something.
DEFAULT_TOKENS = (
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
    "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",  # WBTC
    "0x514910771AF9Ca656af840dff83E8264EcF986CA",  # LINK
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",  # UNI
    "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",  # AAVE
    "0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e",  # YFI
    "0xE41d2489571d322189246DaFA5ebDe1F4699F498",  # ZRX
)

# Status vocabulary. The distinction is the whole point:
#   unlimited / operator  -- active, and unbounded by amount
#   active                -- active, finite
#   expired               -- Permit2 only: no longer exercisable
#   revoked               -- read OK, and currently zero/false
#   self                  -- the spender is the owner; grants nothing new
#   unreadable            -- state could not be read. NOT a revocation.
ACTIVE_STATUSES = ("unlimited", "operator", "active")
VISIBLE_STATUSES = ("unlimited", "operator", "active", "unreadable")
STATUS_RANK = {"unlimited": 0, "operator": 0, "active": 1, "unreadable": 2,
               "expired": 3, "self": 3, "revoked": 4}
LEVELS = {
    "unlimited": "high",
    "operator": "high",
    "active": "notable",
    "expired": "info",
    "self": "info",
    "revoked": "info",
    "unreadable": "info",
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _is_address(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def _norm(address: str) -> str:
    return address.lower()


def _dedupe(addresses) -> list[str]:
    seen: list[str] = []
    for address in addresses:
        lowered = _norm(address)
        if lowered not in seen:
            seen.append(lowered)
    return seen


def _addr_word(address: str) -> str:
    return address[2:].lower().rjust(64, "0")


def _addr_topic(address: str) -> str:
    return "0x" + _addr_word(address)


def _topic_to_address(topic: str) -> str | None:
    if not isinstance(topic, str) or len(topic) < 40:
        return None
    return "0x" + topic[-40:].lower()


def _first_word(data: bytes) -> bytes | None:
    return data[:32] if len(data) >= 32 else None


def _to_int(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (ValueError, TypeError):
        return None


def _safe_text(value: str, limit: int = 32) -> str | None:
    """Strip control characters before a token-controlled string is printed.

    A symbol is attacker-controlled data. Printing it raw would let a token
    emit terminal escape sequences into the report, so it is flattened first.
    """
    if not value:
        return None
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "\u2026"
    return cleaned or None


def _reason(exc: Exception) -> str:
    return _safe_text(str(exc), 120) or exc.__class__.__name__


def _raise_if_code_defect(exc: Exception) -> None:
    """A bug in this tool must not be laundered into a per-item status.

    Same rule as `discovery.verify_corpus`: transport/decode failures are a
    statement about the chain, but a NameError/TypeError is a statement about
    us, and reporting it as "unreadable" would hide it.
    """
    if isinstance(exc, (NameError, TypeError, AttributeError, KeyError, IndexError)):
        raise exc


def _safe_chain(rpc_url: str | None) -> int | None:
    try:
        return chain_id(rpc_url)
    except Exception:
        return None


def format_units(value: int | None, decimals: int | None) -> str:
    """Human amount, when decimals are known; the raw integer otherwise."""
    if value is None:
        return "?"
    if decimals is None or decimals > 36:
        return str(value)
    scale = 10 ** decimals
    whole, frac = divmod(int(value), scale)
    if not frac:
        return str(whole)
    return f"{whole}.{str(frac).rjust(decimals, '0').rstrip('0')}"


def format_expiry(expiration: int | None, now: int) -> str:
    if expiration is None:
        return "?"
    if expiration == MAX_UINT48:
        return "never"
    stamp = datetime.fromtimestamp(expiration, tz=timezone.utc).strftime("%Y-%m-%d")
    return stamp if expiration > now else f"{stamp} (past)"


def _units(value: int | None, decimals: int | None) -> float:
    """Decimal-adjusted size, used only to order rows -- never as a valuation."""
    if value is None or decimals is None or decimals > 36:
        return 0.0
    try:
        return float(value) / (10 ** decimals)
    except OverflowError:
        return float("inf")


# ---------------------------------------------------------------------------
# token metadata (all of it optional, none of it trusted)
# ---------------------------------------------------------------------------

def decode_symbol(data: bytes) -> str | None:
    """Decode `symbol()` tolerantly: ABI string, bytes32, or bare bytes."""
    if not data:
        return None
    # ABI-encoded string: word 0 is the offset (0x20), word 1 the length.
    if len(data) >= 64:
        offset = int.from_bytes(data[:32], "big")
        if offset == 32:
            length = int.from_bytes(data[32:64], "big")
            if 0 < length <= len(data) - 64:
                return _safe_text(data[64 : 64 + length].decode("utf-8", "replace"))
    chunk = data[:32]
    text = chunk.split(b"\x00")[0]
    if text and all(0x20 <= byte < 0x7F for byte in text):
        return _safe_text(text.decode("ascii"))
    # Some very old tokens return neither padding nor a length prefix.
    if len(data) < 32 and all(0x20 <= byte < 0x7F for byte in data):
        return _safe_text(data.decode("ascii"))
    return None


def token_meta(token: str, rpc_url: str | None = None) -> dict:
    """Best-effort symbol()/decimals(). Missing metadata is normal and not an error."""
    meta: dict = {"symbol": None, "decimals": None}
    try:
        meta["symbol"] = decode_symbol(parse_hex(eth_call(token, SYMBOL_SELECTOR, rpc_url)))
    except Exception as exc:
        _raise_if_code_defect(exc)
    try:
        word = _first_word(parse_hex(eth_call(token, DECIMALS_SELECTOR, rpc_url)))
        if word is not None:
            meta["decimals"] = int.from_bytes(word, "big")
    except Exception as exc:
        _raise_if_code_defect(exc)
    return meta


# ---------------------------------------------------------------------------
# current-state reads. Each returns {"status": "ok"|"unreadable", ...}, never
# a bare None that a caller could mistake for "no approval".
# ---------------------------------------------------------------------------

def read_allowance(token: str, owner: str, spender: str, rpc_url: str | None = None) -> dict:
    data = ALLOWANCE_SELECTOR + _addr_word(owner) + _addr_word(spender)
    try:
        word = _first_word(parse_hex(eth_call(token, data, rpc_url)))
    except Exception as exc:
        _raise_if_code_defect(exc)
        return {"status": "unreadable", "value": None, "reason": _reason(exc)}
    if word is None:
        return {"status": "unreadable", "value": None,
                "reason": "return data is shorter than one 32-byte word"}
    return {"status": "ok", "value": int.from_bytes(word, "big")}


def read_is_approved_for_all(token: str, owner: str, operator: str,
                             rpc_url: str | None = None) -> dict:
    data = IS_APPROVED_FOR_ALL_SELECTOR + _addr_word(owner) + _addr_word(operator)
    try:
        word = _first_word(parse_hex(eth_call(token, data, rpc_url)))
    except Exception as exc:
        _raise_if_code_defect(exc)
        return {"status": "unreadable", "value": None, "reason": _reason(exc)}
    if word is None:
        return {"status": "unreadable", "value": None,
                "reason": "return data is shorter than one 32-byte word"}
    return {"status": "ok", "value": bool(int.from_bytes(word, "big"))}


def read_permit2_allowance(permit2: str, owner: str, token: str, spender: str,
                           rpc_url: str | None = None) -> dict:
    """Permit2 packs (uint160 amount, uint48 expiration, uint48 nonce) into one word."""
    data = (PERMIT2_ALLOWANCE_SELECTOR + _addr_word(owner) + _addr_word(token)
            + _addr_word(spender))
    try:
        word = _first_word(parse_hex(eth_call(permit2, data, rpc_url)))
    except Exception as exc:
        _raise_if_code_defect(exc)
        return {"status": "unreadable", "amount": None, "expiration": None,
                "nonce": None, "reason": _reason(exc)}
    if word is None:
        return {"status": "unreadable", "amount": None, "expiration": None,
                "nonce": None, "reason": "return data is shorter than one 32-byte word"}
    packed = int.from_bytes(word, "big")
    return {"status": "ok", "amount": packed & MAX_UINT160,
            "expiration": (packed >> 160) & MAX_UINT48,
            "nonce": (packed >> 208) & MAX_UINT48}


def read_balance(token: str, owner: str, rpc_url: str | None = None) -> int | None:
    data = BALANCE_OF_SELECTOR + _addr_word(owner)
    try:
        word = _first_word(parse_hex(eth_call(token, data, rpc_url)))
    except Exception as exc:
        _raise_if_code_defect(exc)
        return None
    return int.from_bytes(word, "big") if word is not None else None


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _decode_event(log: dict, owner: str) -> dict | None:
    topics = log.get("topics") or []
    if len(topics) < 3:
        return None
    t0 = str(topics[0]).lower()
    # A node is trusted for filtering, but a hostile or buggy endpoint can
    # return anything, so the owner is re-checked rather than assumed.
    if _topic_to_address(topics[1]) != _norm(owner):
        return None

    contract = _norm(log.get("address") or "")
    block = _to_int(log.get("blockNumber"))
    tx = log.get("transactionHash")

    if t0 == APPROVAL_TOPIC:
        spender = _topic_to_address(topics[2])
        if spender is None:
            return None
        return {"kind": "erc20", "token": contract, "spender": spender,
                "block": block, "tx": tx}
    if t0 == APPROVAL_FOR_ALL_TOPIC:
        spender = _topic_to_address(topics[2])
        if spender is None:
            return None
        return {"kind": "operator", "token": contract, "spender": spender,
                "block": block, "tx": tx}
    if t0 in (PERMIT2_APPROVAL_TOPIC, PERMIT2_PERMIT_TOPIC):
        if len(topics) < 4:
            return None
        token = _topic_to_address(topics[2])
        spender = _topic_to_address(topics[3])
        if token is None or spender is None:
            return None
        # The log lives on Permit2; the allowance is over `token`.
        return {"kind": "permit2", "permit2": contract, "token": token,
                "spender": spender, "block": block, "tx": tx}
    return None


def discover_events(
    owner: str,
    addresses: list[str],
    from_block: int,
    to_block: int,
    rpc_url: str | None = None,
    page: int = 2000,
    chunk: int = ADDRESS_CHUNK,
    max_calls: int = 8000,
    quiet: bool = False,
) -> dict:
    """Collect approval events for `owner` on `addresses`, paged by block range.

    Returns one deduplicated candidate per (kind, token, spender) with the
    blocks and count that put it there. Candidates are not verdicts: the
    caller re-reads current state for every one of them.
    """
    owner = _norm(owner)
    addresses = _dedupe(addresses)
    found: dict[tuple, dict] = {}
    fetcher = _LogFetcher(_addr_topic(owner), rpc_url, max_calls=max_calls)

    groups = [addresses[i : i + chunk] for i in range(0, len(addresses), chunk)]
    for group in groups:
        block = from_block
        while block <= to_block and not fetcher.dead:
            end = min(block + page - 1, to_block)
            if not quiet:
                print(f"  logs {block}..{end} ({len(group)} address(es))",
                      file=sys.stderr, flush=True)
            logs = fetcher.fetch(group, block, end)
            for log in logs:
                event = _decode_event(log, owner)
                if event is None:
                    continue
                key = (event["kind"], event["token"], event["spender"])
                row = found.get(key)
                if row is None:
                    found[key] = {**event, "first_block": event["block"],
                                  "last_block": event["block"], "count": 1}
                else:
                    row["last_block"] = event["block"]
                    row["count"] += 1
            block = end + 1

    return {
        "owner": owner,
        "blocks": [from_block, to_block],
        "calls": fetcher.calls,
        "errors": fetcher.errors,
        "events": list(found.values()),
        "addresses": addresses,
    }


class _LogFetcher:
    """Fetch logs, splitting a filter the provider rejects.

    Public nodes cap `eth_getLogs` filters -- PublicNode refuses more than nine
    addresses in one filter, and the cap is undocumented and differs by
    provider. So rather than guess a safe size, a rejected filter is split:
    addresses first, then the block range (which is also how a too-wide range
    or a result-count cap shows up).

    Splitting blindly would be dangerous on an outage, where every call fails
    and the recursion would fan out into thousands of doomed requests. So
    before splitting a range, a one-block query is used to confirm the endpoint
    is usable at all; if it is not, the scan stops and says so.
    """

    def __init__(self, owner_topic: str, rpc_url: str | None, max_calls: int = 8000):
        self.owner_topic = owner_topic
        self.rpc_url = rpc_url
        self.calls = 0
        self.errors: list[str] = []
        self.max_calls = max_calls
        self.dead = False

    def _query(self, addresses: list[str], lo: int, hi: int) -> list[dict]:
        self.calls += 1
        return get_logs(lo, hi, address=addresses,
                        topics=[APPROVAL_TOPICS, self.owner_topic], url=self.rpc_url)

    def fetch(self, addresses: list[str], lo: int, hi: int) -> list[dict]:
        if self.dead or self.calls >= self.max_calls:
            if not self.dead and self.calls >= self.max_calls:
                self.errors.append(
                    f"stopped after {self.calls} requests; the provider kept rejecting filters")
                self.dead = True
            return []
        try:
            return self._query(addresses, lo, hi)
        except Exception as exc:
            _raise_if_code_defect(exc)
            if len(addresses) > 1:
                mid = len(addresses) // 2
                return (self.fetch(addresses[:mid], lo, hi)
                        + self.fetch(addresses[mid:], lo, hi))
            if hi > lo:
                if not self._usable(addresses, lo):
                    self.dead = True
                    return []
                mid = (lo + hi) // 2
                return (self.fetch(addresses, lo, mid)
                        + self.fetch(addresses, mid + 1, hi))
            self.errors.append(f"{lo}..{hi} {addresses[0]}: {_reason(exc)}")
            return []

    def _usable(self, addresses: list[str], block: int) -> bool:
        try:
            self._query(addresses, block, block)
            return True
        except Exception as exc:
            _raise_if_code_defect(exc)
            self.errors.append(
                f"endpoint could not answer a minimal query ({_reason(exc)}); "
                "stopping rather than fan out into thousands of failing requests")
            return False


# ---------------------------------------------------------------------------
# classification and plain-language description
# ---------------------------------------------------------------------------

def _classify(kind: str, state: dict, now: int) -> str:
    if state.get("status") != "ok":
        return "unreadable"
    if kind == "erc20":
        value = state["value"]
        if value == 0:
            return "revoked"
        return "unlimited" if value >= UNLIMITED_ERC20 else "active"
    if kind == "operator":
        return "operator" if state["value"] else "revoked"
    # permit2: amount 0 is revoked; otherwise expiration decides.
    amount = state["amount"]
    if amount == 0:
        return "revoked"
    if state["expiration"] < now:
        return "expired"
    return "unlimited" if amount >= UNLIMITED_PERMIT2 else "active"


def classify_spender(code_hex: str | None) -> dict:
    """Tell an EOA from a contract from an EIP-7702-delegated account."""
    if code_hex is None:
        return {"kind": "unknown", "code_size": None, "delegate": None}
    code = parse_hex(code_hex)
    if not code:
        return {"kind": "eoa", "code_size": 0, "delegate": None}
    if code[:3] == b"\xef\x01\x00" and len(code) >= 23:
        return {"kind": "delegated", "code_size": len(code),
                "delegate": "0x" + code[3:23].hex()}
    return {"kind": "contract", "code_size": len(code), "delegate": None}


def describe_row(row: dict, now: int) -> str:
    """One sentence a person can act on. Never a verdict, never 'safe'."""
    symbol = row.get("symbol")
    token = row["token"]
    label = f"{symbol} ({to_checksum_address(token)})" if symbol else to_checksum_address(token)
    spender = to_checksum_address(row["spender"])
    status = row["status"]
    kind = row["kind"]

    if status == "unreadable":
        message = (f"{label}: could not read current state for spender {spender} "
                   f"({row.get('reason') or 'unknown error'}). This is NOT a revocation; "
                   f"it is unknown.")
        if kind == "erc20":
            message += (" ERC-721 per-tokenId approvals share the ERC-20 Approval topic, "
                        "so this may be an NFT approval the command cannot quantify.")
        return message
    if status == "self":
        return (f"{label}: the spender is the owner address (self-approval). It grants "
                f"nothing beyond what you already control, so it is not counted as exposure.")
    if status == "revoked":
        return f"{label}: spender {spender} -- current on-chain value is zero (revoked)."
    if status == "expired":
        return (f"{label}: Permit2 allowance to {spender} expired "
                f"{format_expiry(row['expiration'], now)}; it can no longer be exercised.")

    suffix = ""
    if row.get("spender_kind") == "eoa":
        suffix = f" Spender {spender} is an EOA (no code): whoever holds its key can take."
    elif row.get("spender_kind") == "delegated":
        suffix = (f" Spender {spender} is an EIP-7702-delegated account; its behaviour "
                  f"lives at {to_checksum_address(row['delegate'])}.")
    elif row.get("spender_kind") == "unknown":
        suffix = f" The spender's code could not be read, so it is unclassified."

    if kind == "operator":
        return (f"OPERATOR: {spender} can move every {label} you own, without another "
                f"signature.{suffix}")

    if kind == "permit2":
        if status == "unlimited":
            head = f"UNLIMITED Permit2 allowance: {spender} can move all of your {label}"
        else:
            amount = format_units(row["amount"], row.get("decimals"))
            head = f"{label}: Permit2 allowance of {amount} to {spender}"
        expiry = format_expiry(row["expiration"], now)
        tail = "that does not expire" if expiry == "never" else f"expiring {expiry}"
        return f"{head}, {tail}.{suffix}"

    # ERC-20
    if status == "unlimited":
        head = (f"UNLIMITED allowance: {spender} can move every {label} you hold, "
                f"now or later.")
    else:
        amount = format_units(row["allowance"], row.get("decimals"))
        head = f"{label}: allowance of {amount} to {spender}."
    if row.get("balance") is None:
        head += " Your balance could not be read, so current exposure is not bounded."
    else:
        balance = format_units(row["balance"], row.get("decimals"))
        if status == "unlimited" or (row.get("allowance") or 0) > row["balance"]:
            head += f" Your balance is {balance}, which bounds what can be taken today."
    return head + suffix


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def scan(
    owner: str,
    tokens: list[str] | None = None,
    *,
    from_block: int | None = None,
    to_block: int | None = None,
    lookback_blocks: int = 20000,
    page: int = 2000,
    chunk: int = ADDRESS_CHUNK,
    max_calls: int = 8000,
    rpc_url: str | None = None,
    permit2: str = PERMIT2_ADDRESS,
    include_permit2: bool = True,
    now: int | None = None,
    quiet: bool = False,
) -> dict:
    """Answer: what can be taken from `owner` without another signature?

    The answer is bounded by the block range and the token list, and the report
    carries both bounds plus everything that could not be read.
    """
    if not _is_address(owner):
        raise ValueError(f"owner must be a 0x address, got {owner!r}")
    if now is None:
        now = int(time.time())
    if to_block is None:
        to_block = get_block_number(rpc_url)
    if from_block is None:
        from_block = max(0, to_block - max(1, lookback_blocks) + 1)

    supplied = bool(tokens)
    token_list = _dedupe(tokens or list(DEFAULT_TOKENS))
    for token in token_list:
        if not _is_address(token):
            raise ValueError(f"not an address: {token!r}")

    scan_addresses = list(token_list)
    permit2_info: dict = {"address": _norm(permit2), "status": "disabled", "code_size": None}
    if include_permit2:
        if not _is_address(permit2):
            raise ValueError(f"permit2 must be a 0x address, got {permit2!r}")
        try:
            code = get_code(_norm(permit2), rpc_url)
        except Exception as exc:
            _raise_if_code_defect(exc)
            permit2_info["status"] = "unverified"
        else:
            permitted = classify_spender(code)
            permit2_info["code_size"] = permitted["code_size"]
            if permitted["kind"] == "eoa":
                permit2_info["status"] = "absent"  # no code: nothing deployed
            else:
                # A delegated account here would still be Permit2-shaped code
                # in practice; either way the state read is what matters.
                permit2_info["status"] = "verified"
                if permit2_info["address"] not in scan_addresses:
                    scan_addresses.append(permit2_info["address"])

    discovery = discover_events(owner, scan_addresses, from_block, to_block,
                                rpc_url, page=page, chunk=chunk,
                                max_calls=max_calls, quiet=quiet)

    meta_cache: dict[str, dict] = {}
    balance_cache: dict[str, int | None] = {}
    code_cache: dict[str, dict] = {}
    owner_lower = _norm(owner)
    rows: list[dict] = []

    for event in discovery["events"]:
        kind = event["kind"]
        state = {"status": "unreadable", "reason": "not read"}
        if kind == "erc20":
            state = read_allowance(event["token"], owner_lower, event["spender"], rpc_url)
        elif kind == "operator":
            state = read_is_approved_for_all(event["token"], owner_lower,
                                             event["spender"], rpc_url)
        else:
            state = read_permit2_allowance(event["permit2"], owner_lower,
                                           event["token"], event["spender"], rpc_url)

        status = _classify(kind, state, now)
        # An approval to yourself is not exposure: you can already move your own
        # tokens, so counting it as "active" would be a false positive.
        if status in ACTIVE_STATUSES and event["spender"] == owner_lower:
            status = "self"

        if event["token"] not in meta_cache:
            meta_cache[event["token"]] = token_meta(event["token"], rpc_url)
        meta = meta_cache[event["token"]]

        balance = None
        if kind != "operator":
            if event["token"] not in balance_cache:
                balance_cache[event["token"]] = read_balance(event["token"], owner_lower, rpc_url)
            balance = balance_cache[event["token"]]

        spender_kind = None
        delegate = None
        if status in ACTIVE_STATUSES and event["spender"] != ZERO_ADDRESS:
            if event["spender"] not in code_cache:
                try:
                    code_cache[event["spender"]] = classify_spender(
                        get_code(event["spender"], rpc_url))
                except Exception as exc:
                    _raise_if_code_defect(exc)
                    code_cache[event["spender"]] = {"kind": "unknown",
                                                    "code_size": None, "delegate": None}
            spender_kind = code_cache[event["spender"]]["kind"]
            delegate = code_cache[event["spender"]]["delegate"]

        # Exposure is what can be taken today: min(allowance, balance) where the
        # balance is readable. It is deliberately not converted to any currency
        # -- this tool has no price feed and will not invent one.
        allowance = state.get("value") if kind == "erc20" else None
        amount = state.get("amount") if kind == "permit2" else None
        exposure = None
        if status in ACTIVE_STATUSES:
            if kind == "operator":
                exposure = None
            elif balance is None:
                exposure = allowance if kind == "erc20" else amount
            else:
                exposure = min(allowance if kind == "erc20" else amount, balance)

        row = {
            "status": status,
            "level": LEVELS[status],
            "kind": kind,
            "token": event["token"],
            "symbol": meta.get("symbol"),
            "decimals": meta.get("decimals"),
            "spender": event["spender"],
            "spender_kind": spender_kind,
            "delegate": delegate,
            "allowance": allowance,
            "amount": amount,
            "balance": balance,
            "exposure": exposure,
            "expiration": state.get("expiration"),
            "nonce": state.get("nonce"),
            "reason": state.get("reason"),
            "first_block": event["first_block"],
            "last_block": event["last_block"],
            "count": event["count"],
            "tx": event.get("tx"),
        }
        row["message"] = describe_row(row, now)
        rows.append(row)

    rows.sort(key=lambda r: (STATUS_RANK.get(r["status"], 9),
                             -_units(r.get("exposure"), r.get("decimals")),
                             r["token"], r["spender"]))

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    spenders: dict[str, dict] = {}
    for row in rows:
        if row["spender_kind"] is not None and row["spender"] not in spenders:
            spenders[row["spender"]] = {"kind": row["spender_kind"],
                                        "delegate": row["delegate"]}

    return {
        "owner": owner_lower,
        "chainId": _safe_chain(rpc_url),
        "blocks": [from_block, to_block],
        "calls": discovery["calls"],
        "log_errors": discovery["errors"],
        "tokensSupplied": supplied,
        "tokensScanned": len(token_list),
        "permit2": permit2_info,
        "candidateEvents": len(discovery["events"]),
        "counts": counts,
        "active": sum(counts.get(s, 0) for s in ACTIVE_STATUSES),
        "unlimited": counts.get("unlimited", 0),
        "operators": counts.get("operator", 0),
        "unreadable": counts.get("unreadable", 0),
        "spenders": spenders,
        "rows": rows,
        "now": now,
    }


def load_token_list(text: str) -> list[str]:
    """Accept a plain address list (corpus-style) or a token-list JSON.

    Token lists are the realistic input: no hand-typed list will be complete,
    and a JSON list is the format the ecosystem actually publishes.
    """
    stripped = (text or "").lstrip()
    if stripped.startswith("{"):
        data = json.loads(text)
        entries = data.get("tokens") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("token list JSON has no 'tokens' array")
        return [str(t["address"]) for t in entries
                if isinstance(t, dict) and t.get("address")]
    return [entry["address"] for entry in read_corpus(text)]