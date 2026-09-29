import io
import json
import unittest

from evm_audit.vercel import (
    MAX_BODY,
    address_handler,
    allowances_disabled,
    health_handler,
    make_app,
)


def call(app, method="POST", body=None, query="", content_length=None):
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "CONTENT_LENGTH": str(len(raw) if content_length is None else content_length),
        "wsgi.input": io.BytesIO(raw),
        "QUERY_STRING": query,
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
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


if __name__ == "__main__":
    unittest.main()
