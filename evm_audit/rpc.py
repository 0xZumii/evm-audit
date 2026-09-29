"""Tiny JSON-RPC client (stdlib only) to fetch contract code.

We need only a couple of methods: eth_getCode and eth_getStorageAt.
Everything else (balances, logs, traces) can be added the same way later.
"""

from __future__ import annotations

import json
import os
import urllib.request

DEFAULT_RPC = os.environ.get("EVM_AUDIT_RPC", "https://ethereum-rpc.publicnode.com")
FALLBACKS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://cloudflare-eth.com",
)


def rpc_call(url: str, method: str, params: list, timeout: int = 20):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "evm-audit/0.1"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if isinstance(body, dict) and body.get("error"):
        raise RuntimeError(body["error"])
    return body.get("result")


def _endpoints(url: str | None) -> list[str]:
    return [url] if url else list(dict.fromkeys([DEFAULT_RPC, *FALLBACKS]))


def get_code(address: str, url: str | None = None) -> str:
    """Return '0x'-prefixed runtime bytecode for an address."""
    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(endpoint, "eth_getCode", [address, "latest"])
            if result is not None:
                return result
        except Exception as exc:  # try the next endpoint
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def get_storage_at(
    address: str, slot: str, url: str | None = None, block: str = "latest"
) -> str:
    """Return the 32-byte word at a storage slot (hex string)."""
    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(endpoint, "eth_getStorageAt", [address, slot, block])
            if result is not None:
                return result
        except Exception as exc:  # try the next endpoint
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def eth_call(address: str, data: str, url: str | None = None, block: str = "latest") -> str:
    """Call a contract function that only reads state.

    Returns the '0x'-prefixed return data. A call to a selector the contract
    does not implement usually reverts, which surfaces here as a RuntimeError
    from the node -- callers that are probing for optional interfaces should
    catch it and treat it as "not implemented".
    """
    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(
                endpoint, "eth_call", [{"to": address, "data": data}, block]
            )
            if result is not None:
                return result
        except Exception as exc:  # try the next endpoint
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def chain_id(url: str | None = None) -> int:
    """Return the EIP-155 chain id of the endpoint."""
    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(endpoint, "eth_chainId", [])
            if result is not None:
                return int(result, 16) if isinstance(result, str) else int(result)
        except Exception as exc:  # try the next endpoint
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def get_block_number(url: str | None = None) -> int:
    """Latest block number, as an int."""
    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(endpoint, "eth_blockNumber", [])
            if result is not None:
                return int(result, 16) if isinstance(result, str) else int(result)
        except Exception as exc:  # try the next endpoint
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def get_logs(
    from_block,
    to_block,
    address: str | list[str] | None = None,
    topics: list | None = None,
    url: str | None = None,
) -> list[dict]:
    """Fetch logs over an inclusive block range.

    Blocks may be ints or the usual tags ('latest', 'earliest'). `topics` follows
    the JSON-RPC convention: a list where each position is a value, null, or a
    list of alternatives.

    Ranges that are too wide for a public node will error; callers doing bulk
    scans should page with `get_block_number` and keep the span modest.
    """
    params: dict = {
        "fromBlock": _block_tag(from_block),
        "toBlock": _block_tag(to_block),
    }
    if address is not None:
        params["address"] = address
    if topics is not None:
        params["topics"] = topics

    last_err: Exception | None = None
    for endpoint in _endpoints(url):
        try:
            result = rpc_call(endpoint, "eth_getLogs", [params])
            if result is not None:
                return result
        except Exception as exc:  # range too large, rate limit, ... try next
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def _block_tag(value) -> str:
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        return value if value.startswith("0x") else hex(int(value))
    raise ValueError(f"invalid block reference: {value!r}")
