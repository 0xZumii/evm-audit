import unittest

from evm_audit.disasm import disassemble, parse_hex, strip_metadata
from evm_audit.features import extract_features, is_minimal_proxy

# PUSH1 0x01; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN
SIMPLE = "0x600160005260206000f3"


class DisasmTests(unittest.TestCase):
    def test_push_operand_consumed(self):
        dis = disassemble(parse_hex(SIMPLE))
        self.assertEqual(
            [i.mnemonic for i in dis.instructions],
            ["PUSH1", "PUSH1", "MSTORE", "PUSH1", "PUSH1", "RETURN"],
        )
        self.assertEqual(dis.instructions[0].operand_int, 1)
        self.assertEqual(dis.instructions[0].size, 2)

    def test_jumpdest_is_not_inside_push_data(self):
        # PUSH1 0x5b would look like a JUMPDEST if we walked byte-by-byte.
        dis = disassemble(parse_hex("0x605b5b00"))
        # 0x00 at pc0 pushes 0x5b (data), then a real JUMPDEST at pc2.
        self.assertEqual(dis.jumpdests, {2})
        self.assertEqual(dis.instructions[0].mnemonic, "PUSH1")

    def test_jump_target_annotation(self):
        # PUSH1 0x04; JUMP; INVALID; INVALID; JUMPDEST
        dis = disassemble(parse_hex("0x60045600" + "5b"))
        jump = [i for i in dis.instructions if i.mnemonic == "JUMP"][0]
        self.assertEqual(jump.target, 4)

    def test_metadata_strip(self):
        body = bytes.fromhex("600160005260206000f3")
        meta = b"\xa2\x64ipfs\x58\x22" + bytes(range(34)) + b"\x64solc\x43\x00\x08\x13"
        code = body + meta + len(meta).to_bytes(2, "big")
        stripped, info = strip_metadata(code)
        self.assertEqual(stripped, body)
        self.assertEqual(info["solc"], "0.8.19")
        self.assertEqual(info["ipfs"], "0x" + bytes(range(34)).hex())

    def test_minimal_proxy_detected(self):
        proxy = bytes.fromhex("363d3d373d3d3d363d73") + bytes(20) + bytes.fromhex(
            "5af43d82803e903d91602b57fd5bf3"
        )
        self.assertTrue(is_minimal_proxy(proxy))
        feats = extract_features(disassemble(proxy))
        self.assertTrue(feats["is_minimal_proxy"])
        self.assertIsNotNone(feats["minimal_proxy_target"])


if __name__ == "__main__":
    unittest.main()
