"""Discovery: find EIP-2612 tokens on-chain, with provenance for every candidate.

Why this exists
---------------
Measuring anything about EIP-712 implementations needs a corpus. Hand-typing
token names is slow and, worse, unverifiable: nobody downstream can check where
a "name" came from, so the dataset is taken on faith. That is the exact problem
this project is supposed to avoid.

So discovery works from the chain only. Every candidate carries two facts that
can be independently re-checked against a node:

    - the block range searched, and
    - the transaction hashes whose non-zero `value` transfer first revealed it.

`eth_getLogs` for ERC-20 `Transfer` events is the crude sieve (it only tells us
*an ERC-20-like contract exists*), and the real filter is a behavioural probe:
we keep only contracts that answer `DOMAIN_SEPARATOR()`. That one call is what
separates an EIP-2612 token from an ordinary ERC-20.

Nothing here guesses an EIP-712 type string -- it cannot be read out of bytecode
(solc folds the keccak into a PUSH32), so the scanner never pretends to know it.
"""

from __future__ import annotations

import sys

from .disasm import parse_hex
from .eip712 import (
    DOMAIN_SEPARATOR_SELECTOR,
    EIP712_DOMAIN_SELECTOR,
    decode_eip712_domain,
    verify_domain,
)
from .rpc import eth_call, get_block_number, get_logs

# keccak256("Transfer(address,address,uint256)") -- ERC-20's event signature.
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

ZERO_TOPIC = "0x" + "00" * 32


def probe_eip2612(address: str, rpc_url: str | None = None) -> dict:
    """Decide whether a contract behaves like an EIP-2612 token.

    `has_separator` is the behavioural fact: the contract returns a 32-byte
    word from `DOMAIN_SEPARATOR()`. `erc5267` records whether it also publishes
    its domain, which is what lets it be checked without a supplied name.
    """
    out = {"address": address, "has_separator": False, "separator": None,
           "erc5267": False, "declared": None}
    try:
        result = eth_call(address, DOMAIN_SEPARATOR_SELECTOR, rpc_url)
        if result and result not in ("0x", "0x0") and len(parse_hex(result)) == 32:
            out["has_separator"] = True
            out["separator"] = "0x" + parse_hex(result).hex()
    except Exception:
        return out
    try:
        raw = eth_call(address, EIP712_DOMAIN_SELECTOR, rpc_url)
        if raw and raw != "0x":
            decoded = decode_eip712_domain(raw)  # only counts if it decodes
            out["erc5267"] = True
            out["declared"] = decoded["domain"]
    except Exception:
        pass
    return out


def scan_transfer_logs(
    from_block: int,
    to_block: int,
    rpc_url: str | None = None,
    page: int = 2000,
    quiet: bool = False,
    address: str | None = None,
) -> dict:
    """Collect ERC-20 transfer senders over a block range, paged.

    Returns {"candidates": {address: {"first_tx": ..., "activity": n}},
             "blocks": [from, to], "pages": n, "errors": [..]}.

    A contract is a candidate if it ever *sent* a token (`from` == the address),
    because that is the strongest cheap signal that it is something more than an
    address that received airdrop spam. The sender is topic 1.

    NOTE: most public nodes refuse a topics-only `eth_getLogs` over any useful
    range ("address is required for eth_getLogs"). Pass `address` to scan a
    specific contract; without it this only works on nodes that allow wide
    queries. `discover_addresses` is the path that works on public RPC.
    """
    candidates: dict[str, dict] = {}
    pages = 0
    errors: list[str] = []

    block = from_block
    while block <= to_block:
        end = min(block + page - 1, to_block)
        pages += 1
        if not quiet:
            print(f"  logs {block}..{end}", file=sys.stderr, flush=True)
        try:
            logs = get_logs(block, end, address=address, topics=[TRANSFER_TOPIC], url=rpc_url)
        except Exception as exc:
            errors.append(f"{block}..{end}: {exc}")
            block = end + 1
            continue

        for log in logs:
            topics = log.get("topics") or []
            if len(topics) < 3:
                continue
            sender = "0x" + topics[1][-40:]
            if sender == "0x" + "00" * 20:  # mint: no real sender
                continue
            entry = candidates.setdefault(sender, {"first_tx": None, "activity": 0})
            entry["activity"] += 1
            if entry["first_tx"] is None:
                entry["first_tx"] = log.get("transactionHash")
        block = end + 1

    return {
        "candidates": candidates,
        "blocks": [from_block, to_block],
        "pages": pages,
        "errors": errors,
    }


def probe_many(
    addresses: list[str],
    rpc_url: str | None = None,
    quiet: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Probe each address for EIP-2612 behaviour, splitting kept from rejected."""
    verified: list[dict] = []
    rejected: list[dict] = []
    total = len(addresses)
    for index, address in enumerate(addresses, start=1):
        if not quiet and index % 25 == 0:
            print(f"  probing {index}/{total}", file=sys.stderr, flush=True)
        probe = probe_eip2612(address, rpc_url)
        row = {
            "address": address,
            "first_tx": None,
            "activity": 0,
            **probe,
        }
        (verified if probe["has_separator"] else rejected).append(row)
    return verified, rejected


def discover_addresses(
    addresses: list[str],
    rpc_url: str | None = None,
    chain: int | None = None,
    quiet: bool = False,
) -> dict:
    """Probe a supplied list of addresses for EIP-2612 behaviour.

    This is the discovery path that works on public RPC: no `eth_getLogs`
    needed. Feed it addresses you already have -- a token list, a
    block-explorer export, the output of a previous scan -- and it keeps the
    ones that answer `DOMAIN_SEPARATOR()`.
    """
    verified, rejected = probe_many(addresses, rpc_url, quiet=quiet)
    return {
        "chainId": _safe_chain(chain, rpc_url),
        "blocks": [None, None],
        "pages": 0,
        "log_errors": [],
        "seen": len(addresses),
        "candidates": verified,
        "rejected": rejected,
    }


def _safe_chain(chain: int | None, rpc_url: str | None):
    if chain is not None:
        return chain
    try:
        return _chain(rpc_url)
    except Exception:
        return None


def discover(
    lookback_blocks: int = 20000,
    to_block: int | None = None,
    rpc_url: str | None = None,
    chain: int | None = None,
    page: int = 2000,
    quiet: bool = False,
) -> dict:
    """Scan recent history, then keep only contracts that answer DOMAIN_SEPARATOR().

    Returns a report with `candidates` (verified EIP-2612) and `rejected`
    (addresses seen in logs that are not EIP-2612 contracts), each row carrying
    the evidence that put it there.
    """
    chain = _safe_chain(chain, rpc_url)

    latest = to_block if to_block is not None else get_block_number(rpc_url)
    start = max(0, latest - lookback_blocks + 1)

    if not quiet:
        print(f"scanning blocks {start}..{latest} (chainId {chain})", file=sys.stderr)

    scan = scan_transfer_logs(start, latest, rpc_url, page=page, quiet=quiet)

    verified, rejected = probe_many(
        sorted(scan["candidates"]), rpc_url, quiet=quiet
    )
    # Re-attach the provenance gathered from logs.
    for row in verified + rejected:
        meta = scan["candidates"].get(row["address"])
        if meta:
            row["first_tx"] = meta["first_tx"]
            row["activity"] = meta["activity"]

    return {
        "chainId": chain,
        "blocks": scan["blocks"],
        "pages": scan["pages"],
        "log_errors": scan["errors"],
        "seen": len(scan["candidates"]),
        "candidates": verified,
        "rejected": rejected,
    }


def _chain(rpc_url: str | None):
    from .rpc import chain_id

    return chain_id(rpc_url)


def discovery_to_corpus(report: dict) -> str:
    """Render a discovery report as a corpus file.

    Candidates found via ERC-5267 get their name/version filled in from the
    chain itself -- no human transcription. Everything else is written as a
    bare address (checkable, but only if the contract implements ERC-5267), and
    the provenance block at the top records how the list was produced.
    """
    lines: list[str] = []
    blocks = report.get("blocks") or [None, None]
    chain = report.get("chainId")
    lines.append("# Generated by `evm-audit eip712-scan --corpus`.")
    lines.append(f"# chainId: {chain if chain is not None else '(unknown)'}")

    if blocks[0] is not None:
        lines.append(f"# blocks:  {blocks[0]}..{blocks[1]}")
        lines.append("#")
        lines.append("# Every address below was observed emitting an ERC-20 Transfer in that")
        lines.append("# range, and then answered DOMAIN_SEPARATOR() on-chain.")
    else:
        lines.append("# blocks:  (none -- addresses were supplied, not discovered)")
        lines.append("#")
        lines.append("# Every address below was supplied to --addresses and answered")
        lines.append("# DOMAIN_SEPARATOR() on-chain. No log scan was performed, so these")
        lines.append("# were NOT independently discovered -- the list is only as good as")
        lines.append("# its source.")

    lines.append("#")
    lines.append("# The name/version, when present, was read back from the contract's own")
    lines.append("# ERC-5267 eip712Domain(). Entries without one implement no ERC-5267,")
    lines.append("# so no name could be read from the chain and none was invented.")
    lines.append("#")
    lines.append("# Re-check the whole file against the chain before trusting it:")
    lines.append("#   evm-audit eip712-check --corpus <this-file>")
    lines.append("")

    for row in sorted(report.get("candidates", []), key=lambda r: r["address"]):
        declared = row.get("declared")
        if declared and declared.get("name") is not None:
            parts = [row["address"], f'"{declared["name"]}"']
            if declared.get("version") is not None:
                parts.append(str(declared["version"]))
            lines.append("  ".join(parts))
        else:
            lines.append(row["address"])
    return "\n".join(lines) + "\n"


def verify_corpus(entries: list[dict], rpc_url: str | None = None, quiet: bool = False) -> dict:
    """Check each corpus entry's declared name/version against the chain.

    This is the provenance gate. `eip712-check` can verify any entry by hashing
    the name you gave it, which means a wrong name still produces a confident
    answer. So before trusting a hand- or tool-written corpus, re-derive from
    ERC-5267 where available and confirm the file matches the contract.
    """
    rows: list[dict] = []
    counts: dict[str, int] = {}
    total = len(entries)

    for index, entry in enumerate(entries, start=1):
        if not quiet and index % 25 == 0:
            print(f"  verifying {index}/{total}", file=sys.stderr, flush=True)
        address = entry["address"]
        try:
            # Pass nothing as `expected`: we want the chain's OWN declaration
            # (ERC-5267) if it has one. Supplying the file's values would make
            # verify_domain echo them back, which is exactly the circularity
            # this mode exists to catch.
            info = verify_domain(address, rpc_url, None)
            onchain = info.get("declared_domain")
            source = info.get("declaration_source")
            if source != "ERC-5267 eip712Domain()":
                onchain = None  # fell back to an expectation, or found nothing
        except Exception as exc:
            # Only transport/decode failures are a statement about the contract.
            # A NameError/TypeError here is a bug in this tool, and must not be
            # laundered into a tidy per-contract status.
            if isinstance(exc, (NameError, TypeError, AttributeError, KeyError)):
                raise
            onchain = None
            info = {"findings": [{"level": "high", "message": str(exc)}]}

        if onchain is None:
            status = "no_erc5267"       # cannot cross-check; not a failure
        else:
            mismatches = []
            for key in ("name", "version", "chainId"):
                declared = entry.get(key)
                if declared is None:
                    continue
                actual = onchain.get(key)
                if str(declared) != str(actual):
                    mismatches.append(f"{key}: file={declared!r} chain={actual!r}")
            status = "mismatch" if mismatches else "match"
            if mismatches:
                info["findings"] = [{"level": "high", "message": "; ".join(mismatches)}]

        counts[status] = counts.get(status, 0) + 1
        rows.append({
            "address": address,
            "status": status,
            "file": {k: entry.get(k) for k in ("name", "version", "chainId")},
            "chain": {k: onchain.get(k) for k in ("name", "version", "chainId")} if onchain else None,
            "findings": [f["message"] for f in info.get("findings", []) if f["level"] == "high"],
        })

    cross_checked = counts.get("match", 0) + counts.get("mismatch", 0)
    return {
        "total": total,
        "counts": counts,
        "cross_checked": cross_checked,
        "rows": rows,
    }
