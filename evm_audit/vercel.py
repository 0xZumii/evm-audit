"""WSGI adapters so the layer handlers can run as Vercel functions.

Vercel does not run a long-lived server, so `python -m evm_audit serve` is not
deployable there. The handlers are already pure functions of a request, so each
one becomes a WSGI app with a few lines in `api/`.

Two honest differences from the local server:

  - the allowance scan needs hundreds of `eth_getLogs` calls and will not fit a
    serverless timeout, so `/api/allowances` answers 501 here;
  - a public deployment should set `EVM_AUDIT_RPC`. Free public endpoints
    rate-limit datacenter IPs, which is what a serverless function looks like.
"""

from __future__ import annotations

import json
import os
from urllib.parse import parse_qs

from . import __version__
from .server import ADDRESS_RE, _json_safe

#: Vercel caps a serverless request body near 4.5 MB. Stay under it.
MAX_BODY = 4 * 1024 * 1024

_REASON = {
    200: "OK",
    400: "Bad Request",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
}


class Unsupported(Exception):
    """A layer that needs a long-lived server and is unavailable here."""


class _TooLarge(Exception):
    pass


def _respond(start_response, obj, status: int = 200):
    body = json.dumps(_json_safe(obj), default=str).encode("utf-8")
    start_response(f"{status} {_REASON.get(status, '')}".strip(), [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ])
    return [body]


def _read_json(environ) -> dict:
    length = int(environ.get("CONTENT_LENGTH") or 0)
    if length <= 0:
        return {}
    if length > MAX_BODY:
        raise _TooLarge()
    raw = environ["wsgi.input"].read(length)
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("body must be JSON")
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    return data


def make_app(handler, methods=("POST",)):
    """Wrap a pure `handler(payload: dict) -> dict` as a WSGI application."""
    allowed = tuple(m.upper() for m in methods)

    def app(environ, start_response):
        method = (environ.get("REQUEST_METHOD") or "GET").upper()
        if method not in allowed:
            return _respond(start_response, {"error": "method not allowed"}, 405)
        try:
            if method == "POST":
                payload = _read_json(environ)
            else:
                payload = {
                    key: values[0]
                    for key, values in parse_qs(
                        environ.get("QUERY_STRING") or ""
                    ).items()
                }
            return _respond(start_response, handler(payload), 200)
        except _TooLarge:
            return _respond(start_response, {"error": "body too large"}, 413)
        except Unsupported as exc:
            return _respond(start_response, {"error": str(exc)}, 501)
        except ValueError as exc:
            return _respond(start_response, {"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            return _respond(start_response, {"error": f"request failed: {exc}"}, 502)

    return app


# --- the two query-string layers -------------------------------------------

def address_handler(payload: dict) -> dict:
    from .server import analyze_address

    address = str(payload.get("address") or "").strip()
    if not ADDRESS_RE.match(address):
        raise ValueError("address must be 0x + 40 hex characters")
    chain_raw = str(payload.get("chain") or "").strip()
    try:
        chain_id = int(chain_raw) if chain_raw else None
    except ValueError:
        raise ValueError("chain must be an integer")
    return analyze_address(address, chain_id)


def resolve_handler(payload: dict) -> dict:
    from .server import resolve_payload

    target = str(payload.get("target") or "").strip()
    want = str(payload.get("features") or "") not in ("", "0", "false")
    return resolve_payload(target, want)


# --- deployment metadata ----------------------------------------------------

def health_handler(payload: dict | None = None) -> dict:
    return {
        "ok": True,
        "version": __version__,
        "deployment": "vercel",
        "allowances": False,
        "rpc": "custom (EVM_AUDIT_RPC)" if os.environ.get("EVM_AUDIT_RPC")
               else "public default",
    }


def allowances_disabled(payload: dict | None = None) -> dict:
    raise Unsupported(
        "The allowance scan issues many eth_getLogs calls and needs a long-lived "
        "server, so it is not available on this deployment. Run "
        "`python -m evm_audit serve` locally, or use the CLI: "
        "`evm-audit allowances <owner>`."
    )
