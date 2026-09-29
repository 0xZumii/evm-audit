"""The Vercel deployment: one WSGI app that serves the page and every layer.

Vercel treats a Python project as a single application when it detects one, and
`app.py` at the project root is a documented default entrypoint location. That
file re-exports `app` from here.

Why one app instead of `api/*.py`: when a Python application is detected, Vercel
routes *every* request to it and ignores file-based functions in `/api`. So this
app serves the static page out of `evm_audit/web/` and routes `/api/*` to the
same pure handlers the local server uses.

Two honest differences from `python -m evm_audit serve`:

  - the allowance scan issues hundreds of `eth_getLogs` calls and does not fit a
    serverless timeout, so `/api/allowances` answers 501;
  - a public deployment should set `EVM_AUDIT_RPC`. Free public endpoints
    rate-limit datacenter IPs, and a serverless function looks exactly like one.
"""

from __future__ import annotations

import json
import os
from urllib.parse import parse_qs

from . import __version__
from .server import (
    ADDRESS_RE,
    CONTENT_TYPES,
    WEB_ROOT,
    _json_safe,
    analyze_address,
    analyze_payload,
    calldata_payload,
    disasm_payload,
    eip712_payload,
    features_payload,
    resolve_payload,
    selector_payload,
    typed_data_payload,
)

#: Vercel caps a serverless request body near 4.5 MB. Stay under it.
MAX_BODY = 4 * 1024 * 1024

_REASON = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
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


# --- request plumbing -------------------------------------------------------

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


# --- the combined app -------------------------------------------------------

#: Path -> file in evm_audit/web/. A fixed map, so no path can escape the
#: directory and no request can ask the function to read an arbitrary file.
STATIC = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
    "/logo.svg": "logo.svg",
    "/favicon.svg": "logo.svg",
}

ROUTES = {
    "/api/analyze": make_app(analyze_payload),
    "/api/features": make_app(features_payload),
    "/api/disasm": make_app(disasm_payload),
    "/api/calldata": make_app(calldata_payload),
    "/api/typed-data": make_app(typed_data_payload),
    "/api/typeddata": make_app(typed_data_payload),  # the file-name-safe alias
    "/api/selector": make_app(selector_payload),
    "/api/eip712": make_app(eip712_payload),
    "/api/allowances": make_app(allowances_disabled),
    "/api/health": make_app(health_handler, methods=("GET",)),
    "/api/address": make_app(address_handler, methods=("GET",)),
    "/api/resolve": make_app(resolve_handler, methods=("GET",)),
}


def _serve_static(filename: str, start_response):
    full = os.path.join(WEB_ROOT, filename)
    try:
        with open(full, "rb") as fh:
            body = fh.read()
    except OSError:
        return _respond(start_response, {"error": "not found"}, 404)
    ctype = CONTENT_TYPES.get(os.path.splitext(filename)[1].lower(),
                              "application/octet-stream")
    start_response("200 OK", [
        ("Content-Type", ctype),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "public, max-age=300"),
    ])
    return [body]


def app(environ, start_response):
    """Serve the page, or route /api/* to a layer."""
    path = environ.get("PATH_INFO") or "/"
    filename = STATIC.get(path)
    if filename is not None:
        return _serve_static(filename, start_response)
    route = ROUTES.get(path)
    if route is None:
        return _respond(start_response, {"error": "not found"}, 404)
    return route(environ, start_response)
