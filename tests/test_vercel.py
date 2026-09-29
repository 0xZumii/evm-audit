import io
import json
import unittest

from evm_audit.vercel import (
    MAX_BODY,
    address_handler,
    allowances_disabled,
    app as vercel_app,
    health_handler,
    make_app,
)


def _environ(method="POST", body=None, query="", content_length=None, path=""):
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    return {
        "REQUEST_METHOD": method,
        "CONTENT_LENGTH": str(len(raw) if content_length is None else content_length),
        "wsgi.input": io.BytesIO(raw),
        "QUERY_STRING": query,
        "PATH_INFO": path,
    }


def call_bytes(app, method="POST", body=None, **kwargs):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = _environ(method=method, body=body, **kwargs)
    payload = b"".join(app(environ, start_response))
    return captured, payload


def call(app, method="POST", body=None, **kwargs):
    captured, payload = call_bytes(app, method=method, body=body, **kwargs)
    return captured, json.loads(payload)


class WsgiAdapterTests(unittest.TestCase):
    def test_post_route_returns_json(self):
        app = make_app(lambda p: {"echo": p.get("x")})
        captured, body = call(app, "POST", {"x": 1})
        self.assertTrue(captured["status"].startswith("200"))
        self.assertEqual(body, {"echo": 1})
        self.assertEqual(captured["headers"]["Content-Type"], "application/json; charset=utf-8")

    def test_method_not_allowed(self):
        app = make_app(lambda p: {}, methods=("POST",))
        captured, body = call(app, "GET")
        self.assertTrue(captured["status"].startswith("405"))
        self.assertIn("error", body)

    def test_get_route_reads_query_string(self):
        app = make_app(lambda p: {"got": p.get("x")}, methods=("GET",))
        captured, body = call(app, "GET", query="x=1&x=2")
        self.assertEqual(body["got"], "1")  # first value wins

    def test_invalid_handler_input_is_400(self):
        def handler(payload):
            raise ValueError("bad")

        captured, body = call(make_app(handler), "POST", {})
        self.assertTrue(captured["status"].startswith("400"))
        self.assertEqual(body["error"], "bad")

    def test_malformed_json_is_400(self):
        app = make_app(lambda p: {})
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_LENGTH": "3",
            "wsgi.input": io.BytesIO(b"{o]"),
            "QUERY_STRING": "",
        }
        captured = {}
        payload = b"".join(app(environ, lambda s, h: captured.update({"status": s})))
        self.assertTrue(captured["status"].startswith("400"))
        self.assertIn("JSON", json.loads(payload)["error"])

    def test_oversized_body_is_413_without_reading(self):
        app = make_app(lambda p: {})
        captured, body = call(app, "POST", {}, content_length=MAX_BODY + 1)
        self.assertTrue(captured["status"].startswith("413"))

    def test_big_integers_survive_as_strings(self):
        big = 2 ** 256 - 1
        app = make_app(lambda p: {"amount": big})
        _, body = call(app, "POST", {})
        self.assertEqual(body["amount"], str(big))

    def test_allowances_is_unsupported(self):
        captured, body = call(make_app(allowances_disabled), "POST", {})
        self.assertTrue(captured["status"].startswith("501"))
        self.assertIn("long-lived server", body["error"])

    def test_health_reports_no_allowances(self):
        captured, body = call(make_app(health_handler, methods=("GET",)), "GET")
        self.assertTrue(captured["status"].startswith("200"))
        self.assertFalse(body["allowances"])
        self.assertEqual(body["deployment"], "vercel")

    def test_address_handler_validates(self):
        with self.assertRaises(ValueError):
            address_handler({"address": "nope"})
        with self.assertRaises(ValueError):
            address_handler({"address": "0x" + "11" * 20, "chain": "abc"})


class CombinedAppTests(unittest.TestCase):
    """The single WSGI app Vercel loads (via the root app.py)."""

    def test_root_serves_the_page(self):
        captured, body = call_bytes(vercel_app, "GET", path="/")
        self.assertTrue(captured["status"].startswith("200"))
        self.assertIn("text/html", captured["headers"]["Content-Type"])
        self.assertIn(b"evm-audit", body)

    def test_static_assets_are_served_with_types(self):
        js = call_bytes(vercel_app, "GET", path="/app.js")[0]
        self.assertIn("javascript", js["headers"]["Content-Type"])
        css = call_bytes(vercel_app, "GET", path="/styles.css")[0]
        self.assertIn("text/css", css["headers"]["Content-Type"])

    def test_post_route(self):
        captured, body = call(
            vercel_app, "POST", {"signatures": ["approve(address,uint256)"]},
            path="/api/selector",
        )
        self.assertTrue(captured["status"].startswith("200"))
        self.assertEqual(body["selectors"][0]["selector"], "0x095ea7b3")

    def test_typed_data_hyphen_and_alias_both_route(self):
        for path in ("/api/typed-data", "/api/typeddata"):
            captured, body = call(vercel_app, "POST", {}, path=path)
            self.assertTrue(captured["status"].startswith("400"), path)
            self.assertIn("payload", body["error"])

    def test_health_reports_vercel(self):
        captured, body = call(vercel_app, "GET", path="/api/health")
        self.assertTrue(captured["status"].startswith("200"))
        self.assertEqual(body["deployment"], "vercel")
        self.assertFalse(body["allowances"])

    def test_allowances_answers_501(self):
        captured, body = call(vercel_app, "POST", {}, path="/api/allowances")
        self.assertTrue(captured["status"].startswith("501"))

    def test_wrong_method_is_405(self):
        captured, _ = call(vercel_app, "GET", path="/api/selector")
        self.assertTrue(captured["status"].startswith("405"))

    def test_unknown_path_is_404(self):
        captured, _ = call(vercel_app, "GET", path="/api/nope")
        self.assertTrue(captured["status"].startswith("404"))

    def test_no_path_traversal(self):
        for path in ("/../app.py", "/..%2fapp.py", "/evm_audit/vercel.py"):
            captured, _ = call(vercel_app, "GET", path=path)
            self.assertTrue(captured["status"].startswith("404"), path)


if __name__ == "__main__":
    unittest.main()
