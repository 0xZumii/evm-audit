import unittest

from evm_audit.abi import MAX_UINT256
from evm_audit.keccak import selector
from evm_audit.signatures import analyze_calldata, analyze_typed_data

SPENDER = "0x1111111111111111111111111111111111111111"


def enc_address(addr: str) -> str:
    return addr[2:].rjust(64, "0")


def enc_uint(n: int) -> str:
    return format(n, "064x")


class CalldataTests(unittest.TestCase):
    def test_unlimited_approve_is_flagged_high(self):
        data = "0x" + selector("approve(address,uint256)")[2:]
        data += enc_address(SPENDER) + enc_uint(MAX_UINT256)
        result = analyze_calldata(data)
        self.assertTrue(result["known"])
        self.assertEqual(result["args"][0]["value"], SPENDER)
        levels = [f["level"] for f in result["findings"]]
        self.assertIn("high", levels)

    def test_finite_approve_is_notable(self):
        data = "0x" + selector("approve(address,uint256)")[2:]
        data += enc_address(SPENDER) + enc_uint(1000)
        result = analyze_calldata(data)
        self.assertEqual(result["args"][1]["value"], 1000)
        self.assertNotIn("high", [f["level"] for f in result["findings"]])

    def test_set_approval_for_all_true(self):
        data = "0x" + selector("setApprovalForAll(address,bool)")[2:]
        data += enc_address(SPENDER) + enc_uint(1)
        result = analyze_calldata(data)
        self.assertIn("high", [f["level"] for f in result["findings"]])

    def test_unknown_selector_handled(self):
        result = analyze_calldata("0xdeadbeef" + "00" * 32)
        self.assertFalse(result["known"])

    def test_too_short(self):
        self.assertIn("error", analyze_calldata("0x1234"))


class TypedDataTests(unittest.TestCase):
    def test_eip2612_permit_flags_high(self):
        payload = {
            "types": {"Permit": []},
            "primaryType": "Permit",
            "domain": {
                "name": "USD Coin", "version": "2",
                "chainId": 1, "verifyingContract": "0xA0b8",
            },
            "message": {
                "owner": "0x2222222222222222222222222222222222222222",
                "spender": SPENDER,
                "value": MAX_UINT256,
                "deadline": 0,
            },
        }
        result = analyze_typed_data(payload)
        levels = [f["level"] for f in result["findings"]]
        self.assertIn("high", levels)
        self.assertEqual(result["primaryType"], "Permit")
        # 2^256-1 should surface as an explicit unlimited finding
        self.assertTrue(any("Unlimited" in f["message"] for f in result["findings"]))

    def test_benign_typed_data(self):
        payload = {
            "types": {"Mail": []},
            "primaryType": "Mail",
            "domain": {"name": "App", "version": "1", "chainId": 1},
            "message": {"contents": "hello", "to": "0x3333"},
        }
        result = analyze_typed_data(payload)
        self.assertTrue(any("No high-risk" in f["message"] for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
