"""Fetch verified Solidity source from Sourcify (no API key, stdlib only).

Sourcify stores the *decoded* source files a contract was compiled from. That
is what a reviewer wants: not a block explorer's HTML, but the text. The v2
API returns them inline:

    GET https://sourcify.dev/server/v2/contract/{chainId}/{address}?fields=sources,metadata

An unverified address answers 404, which is reported as `unverified` -- never
as "no issues". A verified address means the source matches the deployed
runtime bytecode *by Sourcify's check*; it is the best available provenance,
not proof of intent.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

SOURCIFY_API = os.environ.get(
    "EVM_AUDIT_SOURCIFY", "https://sourcify.dev/server/v2/contract"
)


def fetch_sources(address: str, chain_id: int, timeout: int = 30) -> dict:
    """Return {status, sources, metadata, address, chainId}.

    status is 'verified' with a match type, or 'unverified' when Sourcify has
    no record. Network/config problems raise RuntimeError so the caller can
    tell "not published" apart from "could not ask".
    """
    url = f"{SOURCIFY_API}/{chain_id}/{address}?fields=sources,metadata"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "evm-audit/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "unverified",
                "match": None,
                "address": address,
                "chainId": chain_id,
                "sources": {},
                "metadata": None,
            }
        if exc.code == 400:
            raise RuntimeError(
                f"Sourcify rejected chain {chain_id} (HTTP 400). Is the chain "
                "supported? Pass --chain-id explicitly."
            )
        raise RuntimeError(f"Sourcify HTTP {exc.code} for {address}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach Sourcify: {exc.reason}")

    raw_sources = data.get("sources") or {}
    sources = {
        name: entry.get("content", "")
        for name, entry in raw_sources.items()
        if isinstance(entry, dict)
    }
    return {
        "status": "verified",
        "match": data.get("match"),
        "address": address,
        "chainId": chain_id,
        "sources": sources,
        "metadata": data.get("metadata"),
    }
