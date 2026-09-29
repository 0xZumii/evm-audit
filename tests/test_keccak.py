import unittest

from evm_audit.keccak import keccak256, selector


class KeccakTests(unittest.TestCase):
    def test_empty_vector(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc_vector(self):
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_known_selectors(self):
        cases = {
            "approve(address,uint256)": "0x095ea7b3",
            "setApprovalForAll(address,bool)": "0xa22cb465",
            "transferFrom(address,address,uint256)": "0x23b872dd",
            "safeTransferFrom(address,address,uint256)": "0x42842e0e",
            "increaseAllowance(address,uint256)": "0x39509351",
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": "0xd505accf",
            "approve(address,address,uint160,uint48)": "0x87517c45",
            "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)": "0x2b67b570",
        }
        for sig, expected in cases.items():
            with self.subTest(sig=sig):
                self.assertEqual(selector(sig), expected)


if __name__ == "__main__":
    unittest.main()
