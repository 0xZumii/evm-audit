"""A local web UI for every layer, standard library only.

It serves a small static page and a JSON endpoint per layer: source analysis,
bytecode features/disassembly/proxy resolution, calldata and EIP-712 decoding,
signature recovery, EIP-712 domain verification, and allowance exposure.

It binds to 127.0.0.1 by default and analyzes in memory. Reading a contract
from a chain is the only thing that leaves the machine, as a request to an RPC
endpoint or to Sourcify. Same rule as the CLI: places to look, never a verdict.
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, rpc
from .allowances import load_token_list, scan
from .disasm import disassemble, parse_hex
from .eip712 import verify_domain, verify_typed_data
from .features import extract_features
from .keccak import selector as selector_of
from .resolve import resolve_implementation
from .signatures import analyze_calldata, analyze_typed_data
from .sol_source import abi_signatures, analyze_sources, sources_from_json_data
from .sourcify import fetch_sources

WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_BODY = 8 * 1024 * 1024  # 8 MB of pasted input is plenty
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

#: Above this, integers are sent as strings. JavaScript parses JSON numbers as
#: doubles, so a uint256 rendered as a number loses precision -- and an
#: allowance is exactly the kind of number that must not be rounded.
MAX_SAFE_INT = 9007199254740991


def _json_safe(value):
    """JSON-safe copy, with integers too large for a JS number kept exact."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -MAX_SAFE_INT <= value <= MAX_SAFE_INT else str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
}


# ---------------------------------------------------------------------------
# Layer handlers (pure functions, so the request handling is testable
# without starting a server)
# ---------------------------------------------------------------------------

def _resolve_bytecode(target: str, raw: bool = False) -> tuple[str, bytes]:
    """Address or raw hex only -- file paths stay on the CLI, so a page bound
    to a wider interface cannot ask the server to read local files."""
    if not target:
        raise ValueError("send 'target' (an address or raw 0x-hex)")
    if raw or (target.startswith("0x") and len(target) > 42):
        return "raw bytecode", parse_hex(target)
    if ADDRESS_RE.match(target):
        code_hex = rpc.get_code(target)
        if code_hex in ("0x", "0x0"):
            raise ValueError(f"no code at {target}: an EOA, or the wrong chain/RPC")
        return target, parse_hex(code_hex)
    raise ValueError("target must be a 0x address or raw 0x-hex (files are CLI-only)")


def _facts_only(kind: str, extra: dict, notes: list[str], target: str) -> dict:
    return {
        "target": target,
        "kind": f"{kind}-facts",
        "notes": notes,
        "ast_facts": extra.get("ast_facts") or [],
        "abi_signatures": abi_signatures(extra.get("abi")),
        "findings": [],
        "counts": {"high": 0, "notable": 0, "info": 0},
        "summary": {"files": 0, "contracts": 0, "functions": 0, "state_variables": 0},
        "not_checked": [],
    }


def analyze_payload(payload: dict) -> dict:
    """Source layer: pasted source, a {path: content} map, or an artifact."""
    target = str(payload.get("name") or "Pasted.sol")
    if "artifact" in payload:
        data = payload["artifact"]
        if isinstance(data, str):
            data = json.loads(data)
        if not isinstance(data, dict):
            raise ValueError("'artifact' must be an object or a JSON string")
        sources, extra, notes = sources_from_json_data(data)
        if not sources:
            return _facts_only("artifact", extra, notes, target)
        report = analyze_sources(sources, target, "artifact")
        report["notes"] = notes
        return report

    if "sources" in payload:
        raw = payload["sources"]
        if not isinstance(raw, dict) or not raw:
            raise ValueError("'sources' must be a non-empty {path: content} map")
        sources = {str(k): str(v) for k, v in raw.items()}
    elif "source" in payload:
        sources = {target: str(payload["source"])}
    else:
        raise ValueError("send 'source', 'sources', or 'artifact'")

    if sum(len(v) for v in sources.values()) > MAX_BODY:
        raise ValueError("source is too large")
    return analyze_sources(sources, target, "source")


def features_payload(payload: dict) -> dict:
    target = str(payload.get("target") or "").strip()
    label, code = _resolve_bytecode(target, bool(payload.get("raw")))
    return {"target": label, "features": extract_features(disassemble(code))}


def disasm_payload(payload: dict) -> dict:
    target = str(payload.get("target") or "").strip()
    limit = int(payload.get("limit") or 400)
    limit = max(1, min(limit, 4000))
    label, code = _resolve_bytecode(target, bool(payload.get("raw")))
    dis = disassemble(code, strip_meta=not payload.get("keepMetadata"))
    shown = dis.instructions[:limit]
    return {
        "target": label,
        "rawSize": dis.raw_size,
        "strippedSize": len(dis.code),
        "instructionCount": len(dis.instructions),
        "metadata": dis.metadata,
        "instructions": [i.render() for i in shown],
        "truncated": max(0, len(dis.instructions) - len(shown)),
    }


def calldata_payload(payload: dict) -> dict:
    data = str(payload.get("data") or "").strip()
    if not data:
        raise ValueError("send 'data' (0x calldata)")
    return analyze_calldata(data)


def typed_data_payload(payload: dict) -> dict:
    obj = payload.get("payload")
    if isinstance(obj, str):
        obj = json.loads(obj)
    if not isinstance(obj, dict):
        raise ValueError("send 'payload' as a typed-data object or a JSON string")
    if "types" not in obj and isinstance(obj.get("params"), list):
        obj = next((p for p in obj["params"] if isinstance(p, dict)), obj)
    result = analyze_typed_data(obj)
    eip = verify_typed_data(
        obj,
        rpc_url=None,
        expected_signer=payload.get("signer") or None,
        signature=payload.get("signature") or None,
        check_domain=bool(payload.get("checkDomain")),
    )
    result["digest"] = eip["digest"]
    result["signer"] = eip["signer"]
    result["eip712_findings"] = eip["findings"]
    return result


def selector_payload(payload: dict) -> dict:
    sigs = payload.get("signatures")
    if isinstance(sigs, str):
        sigs = [s for s in re.split(r"[\n,]", sigs) if s.strip()]
    if not isinstance(sigs, list) or not sigs:
        raise ValueError("send 'signatures' as a list, or comma/newline separated text")
    rows = []
    for sig in sigs:
        sig = str(sig).strip()
        if sig:
            rows.append({"signature": sig, "selector": selector_of(sig)})
    if not rows:
        raise ValueError("no signatures found")
    return {"selectors": rows}


def eip712_payload(payload: dict) -> dict:
    target = str(payload.get("target") or "").strip()
    if not ADDRESS_RE.match(target):
        raise ValueError("target must be a contract address")
    expected: dict = {}
    if payload.get("name"):
        expected["name"] = payload["name"]
    if payload.get("version"):
        expected["version"] = str(payload["version"])
    if payload.get("salt"):
        expected["salt"] = payload["salt"]
    if payload.get("chainId"):
        expected["chainId"] = int(payload["chainId"])
    return verify_domain(target, None, expected or None)


def resolve_payload(target: str, want_features: bool) -> dict:
    if not ADDRESS_RE.match(target):
        raise ValueError("target must be a contract address")
    info = resolve_implementation(target, None)
    if want_features and info.get("implementation"):
        try:
            _, code = _resolve_bytecode(info["implementation"])
            info["implementationFeatures"] = extract_features(disassemble(code))
        except (ValueError, RuntimeError) as exc:
            info["implementationFeaturesError"] = str(exc)
    return info


def allowances_payload(payload: dict) -> dict:
    owner = str(payload.get("owner") or "").strip()
    if not ADDRESS_RE.match(owner):
        raise ValueError("owner must be a 0x address")
    tokens = None
    raw_tokens = payload.get("tokens")
    if raw_tokens:
        if isinstance(raw_tokens, list):
            tokens = [str(t).strip() for t in raw_tokens if str(t).strip()]
        else:
            tokens = load_token_list(str(raw_tokens))
        if not tokens:
            raise ValueError("no token addresses found in 'tokens'")
    lookback = max(1, min(int(payload.get("lookback") or 5000), 50000))
    max_calls = max(1, min(int(payload.get("maxCalls") or 1200), 3000))
    return scan(
        owner, tokens, lookback_blocks=lookback, max_calls=max_calls,
        rpc_url=None, quiet=True,
    )


def analyze_address(address: str, chain_id: int | None) -> dict:
    if chain_id is None:
        chain_id = rpc.chain_id()
    info = fetch_sources(address, chain_id)
    if info["status"] == "unverified":
        report = _facts_only("sourcify", {}, [
            f"No verified source for {address} on chain {chain_id} in Sourcify. "
            "Nothing to read here; this is not a clean result."
        ], address)
        report["sourcify"] = {"status": "unverified", "chainId": chain_id, "match": None}
        return report

    report = analyze_sources(info["sources"], address, "sourcify")
    report["notes"] = [
        f"Sourcify match: {info['match']} (chain {chain_id}). Provenance, not "
        "proof of intent."
    ]
    report["sourcify"] = {
        "status": "verified", "chainId": chain_id,
        "match": info["match"], "address": address,
    }
    return report


POST_ROUTES = {
    "/api/analyze": analyze_payload,
    "/api/features": features_payload,
    "/api/disasm": disasm_payload,
    "/api/calldata": calldata_payload,
    "/api/typed-data": typed_data_payload,
    "/api/selector": selector_payload,
    "/api/eip712": eip712_payload,
    "/api/allowances": allowances_payload,
}


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = f"evm-audit/{__version__}"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(_json_safe(obj), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    def _static(self, path: str) -> None:
        if path == "/":
            path = "/index.html"
        rel = os.path.normpath(path).lstrip("/\\")
        full = os.path.join(WEB_ROOT, rel)
        root = os.path.abspath(WEB_ROOT)
        if not os.path.abspath(full).startswith(root) or not os.path.isfile(full):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"not found")
            return
        with open(full, "rb") as fh:
            body = fh.read()
        ext = os.path.splitext(full)[1].lower()
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({
                "ok": True,
                "version": __version__,
                "deployment": "local",
                "allowances": True,
            })
            return
        if parsed.path == "/api/address":
            query = parse_qs(parsed.query)
            address = (query.get("address") or [""])[0].strip()
            chain_raw = (query.get("chain") or [""])[0].strip()
            if not ADDRESS_RE.match(address):
                self._error("address must be 0x + 40 hex characters")
                return
            try:
                chain_id = int(chain_raw) if chain_raw else None
            except ValueError:
                self._error("chain must be an integer")
                return
            try:
                self._json(analyze_address(address, chain_id))
            except Exception as exc:  # noqa: BLE001 - reported to the page
                self._error(str(exc), 502)
            return
        if parsed.path == "/api/resolve":
            query = parse_qs(parsed.query)
            target = (query.get("target") or [""])[0].strip()
            want = (query.get("features") or ["0"])[0] not in ("", "0", "false")
            try:
                self._json(resolve_payload(target, want))
            except ValueError as exc:
                self._error(str(exc))
            except Exception as exc:  # noqa: BLE001
                self._error(str(exc), 502)
            return
        self._static(parsed.path)

    def do_POST(self):  # noqa: N802 - stdlib name
        route = POST_ROUTES.get(urlparse(self.path).path)
        if route is None:
            self._error("not found", 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._error("empty or oversized body", 413)
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error("body must be JSON")
            return
        if not isinstance(payload, dict):
            self._error("body must be a JSON object")
            return
        try:
            self._json(route(payload))
        except ValueError as exc:
            self._error(str(exc))
        except Exception as exc:  # noqa: BLE001 - reported to the page
            self._error(f"request failed: {exc}", 502)


class _Server(ThreadingHTTPServer):
    """Bind so that a taken port fails loudly instead of being shared.

    On Windows SO_REUSEADDR lets a second process bind a port that is already
    in use and silently split connections between them, so it is disabled. On
    other platforms SO_REUSEADDR is kept, so a restart is not blocked by a
    socket in TIME_WAIT.
    """

    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port


def run(host: str = "127.0.0.1", port: int = 8787, open_browser: bool = False) -> None:
    try:
        httpd = _Server((host, port), Handler)
    except OSError as exc:
        print(f"could not bind {host}:{port}: {exc}", file=sys.stderr)
        print("is another 'evm_audit serve' already running on that port?",
              file=sys.stderr)
        return
    url = f"http://{host}:{port}/"
    print(f"evm-audit UI -> {url}")
    print("Ctrl-C to stop. The server is local; paste nothing you would not share.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
