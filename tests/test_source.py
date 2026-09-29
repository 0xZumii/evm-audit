import json
import os
import tempfile
import unittest

from evm_audit.server import (
    _json_safe,
    analyze_payload,
    calldata_payload,
    disasm_payload,
    features_payload,
    selector_payload,
    typed_data_payload,
)
from evm_audit.sol_source import (
    abi_signatures,
    analyze_sources,
    collect_files,
    parse_file,
    sources_from_json,
    tokenize,
)


def analyze(src, path="X.sol"):
    return analyze_sources({path: src}, path)


def rules(report):
    return [f["rule"] for f in report["findings"]]


def only(report, rule):
    return [f for f in report["findings"] if f["rule"] == rule]


class LexerTests(unittest.TestCase):
    def test_comments_and_strings_are_not_code(self):
        src = '''
// contract Fake {}
/* function bogus() {} */
contract C {
    string public s = "} { // not code";
    function f() public { /* x */ }
}
'''
        model = parse_file("C.sol", src)
        self.assertEqual([c.name for c in model.contracts], ["C"])
        self.assertEqual([f.name for f in model.contracts[0].functions], ["f"])
        self.assertEqual([v.name for v in model.contracts[0].state_vars], ["s"])

    def test_string_token_is_a_single_token(self):
        toks = tokenize('string s = "a { b } c";')
        strings = [t for t in toks if t.kind == "str"]
        self.assertEqual(strings[0].text, '"a { b } c"')

    def test_line_numbers_survive_block_comments(self):
        src = "/*\n\n*/\ncontract C {}\n"
        model = parse_file("C.sol", src)
        self.assertEqual(model.contracts[0].line, 4)

    def test_two_char_operators_do_not_collide(self):
        toks = tokenize("a == b => c != d = e")
        self.assertIn("==", [t.text for t in toks])
        self.assertIn("=>", [t.text for t in toks])
        self.assertIn("=", [t.text for t in toks])
        self.assertNotIn("= =", [t.text for t in toks])


class StructureTests(unittest.TestCase):
    def test_inheritance_visibility_modifiers_and_state_vars(self):
        src = """
pragma solidity 0.8.20;
contract Base {}
contract A is Base, Other {
    uint256 public total;
    mapping(address => uint256) internal bal;
    modifier onlyOwner() { _; }
    function mint(address to, uint256 amt) external onlyOwner returns (bool) {
        total += amt;
        return true;
    }
}
"""
        model = parse_file("A.sol", src)
        a = model.contracts[1]
        self.assertEqual(a.bases, ["Base", "Other"])
        self.assertEqual({v.name for v in a.state_vars}, {"total", "bal"})
        mint = next(f for f in a.functions if f.name == "mint")
        self.assertEqual(mint.visibility, "external")
        self.assertIn("onlyOwner", mint.modifiers)
        self.assertIsNotNone(mint.body)

    def test_interface_declaration_has_no_body(self):
        src = "interface I { function f() external; }"
        model = parse_file("I.sol", src)
        self.assertIsNone(model.contracts[0].functions[0].body)


class RuleTests(unittest.TestCase):
    def test_tx_origin_is_high(self):
        report = analyze("contract C { function f() external { require(tx.origin == msg.sender); } }")
        self.assertEqual(only(report, "tx-origin")[0]["level"], "high")

    def test_selfdestruct_is_high(self):
        report = analyze("contract C { function f() external { selfdestruct(payable(msg.sender)); } }")
        self.assertEqual(only(report, "selfdestruct")[0]["level"], "high")

    def test_unchecked_call_flagged_but_require_wrapped_is_not(self):
        bad = analyze("""
contract C {
    function u(address to) external { IERC20(to).transfer(msg.sender, 1); }
}
""")
        self.assertEqual(len(only(bad, "unchecked-call")), 1)

        good = analyze("""
contract C {
    function u(address to) external { require(IERC20(to).transfer(msg.sender, 1)); }
}
""")
        self.assertEqual(only(good, "unchecked-call"), [])

    def test_captured_call_result_is_not_flagged(self):
        report = analyze("""
contract C {
    function u(address to) external {
        (bool ok, ) = to.call("");
        require(ok);
    }
}
""")
        self.assertEqual(only(report, "unchecked-call"), [])

    def test_delegatecall_to_msg_sender_is_high(self):
        report = analyze("""
contract C {
    function f() external { msg.sender.delegatecall(""); }
}
""")
        hits = only(report, "delegatecall-target")
        self.assertEqual(hits[0]["level"], "high")

    def test_delegatecall_to_untrusted_address_is_notable(self):
        report = analyze("""
contract C {
    function f(address a) external { a.delegatecall(""); }
}
""")
        self.assertEqual(only(report, "delegatecall-target")[0]["level"], "notable")

    def test_missing_access_control_high_and_suppressed_by_modifier(self):
        bad = analyze("contract C { function mint(address to) external { } }")
        hits = only(bad, "missing-access-control")
        self.assertEqual(hits[0]["level"], "high")

        good = analyze("""
contract C {
    modifier onlyOwner() { _; }
    function mint(address to) external onlyOwner { }
}
""")
        self.assertEqual(only(good, "missing-access-control"), [])

    def test_missing_access_control_suppressed_by_inline_check(self):
        report = analyze("""
contract C {
    address owner;
    function rescue() external { require(msg.sender == owner, "no"); }
}
""")
        self.assertEqual(only(report, "missing-access-control"), [])

    def test_unclear_modifier_is_info_not_high(self):
        report = analyze("""
contract C {
    address admin;
    modifier ifAdmin() { if (msg.sender == admin) { _; } else { _; } }
    function upgradeTo(address newImpl) external ifAdmin { admin = newImpl; }
}
""")
        self.assertEqual(only(report, "missing-access-control"), [])
        hits = only(report, "unclear-access-control")
        self.assertEqual(hits[0]["level"], "info")

    def test_unprotected_initializer(self):
        bad = analyze("contract C { function initialize(address o) external { } }")
        self.assertEqual(only(bad, "unprotected-initializer")[0]["level"], "high")

        good = analyze("""
contract C {
    bool private _init;
    modifier initializer() { require(!_init); _init = true; _; }
    function initialize(address o) external initializer { }
}
""")
        self.assertEqual(only(good, "unprotected-initializer"), [])

    def test_state_written_after_external_call(self):
        report = analyze("""
contract C {
    mapping(address => uint256) public bal;
    function withdraw() external {
        (bool ok, ) = msg.sender.call("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
""")
        self.assertEqual(only(report, "state-after-call")[0]["level"], "notable")

    def test_nonreentrant_suppresses_state_after_call(self):
        report = analyze("""
contract C {
    mapping(address => uint256) public bal;
    modifier nonReentrant() { _; }
    function withdraw() external nonReentrant {
        (bool ok, ) = msg.sender.call("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
""")
        self.assertEqual(only(report, "state-after-call"), [])

    def test_ecrecover_without_zero_check(self):
        report = analyze("""
contract C {
    function v(bytes32 h, uint8 a, bytes32 b, bytes32 c) public pure returns (address) {
        return ecrecover(h, a, b, c);
    }
}
""")
        self.assertEqual(only(report, "ecrecover-zero")[0]["level"], "notable")

    def test_ecrecover_with_zero_check_is_clear(self):
        report = analyze("""
contract C {
    function v(bytes32 h, uint8 a, bytes32 b, bytes32 c) public pure returns (address) {
        address signer = ecrecover(h, a, b, c);
        require(signer != address(0), "bad");
        return signer;
    }
}
""")
        self.assertEqual(only(report, "ecrecover-zero"), [])

    def test_pragma_rules(self):
        pinned = analyze("pragma solidity 0.8.20; contract C {}")
        self.assertEqual(only(pinned, "floating-pragma"), [])
        self.assertEqual(only(pinned, "pre-0.8-pragma"), [])

        old = analyze("pragma solidity ^0.7.6; contract C {}")
        self.assertEqual(len(only(old, "pre-0.8-pragma")), 1)
        self.assertEqual(len(only(old, "floating-pragma")), 1)

    def test_token_level_rules(self):
        src = """
pragma solidity 0.8.20;
contract C {
    bytes32 constant S = 0x0000000000000000000000000000000000000000000000000000000000000001;
    function a() external { assembly { let x := sload(0) } }
    function b(uint256 x) external pure returns (uint256) { unchecked { return x + 1; } }
    function c(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
    function d() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.number)));
    }
}
"""
        report = analyze(src)
        for rule in ("assembly", "unchecked", "encode-packed", "hardcoded-32-bytes"):
            self.assertIn(rule, rules(report), rule)
        self.assertIn("weak-randomness", rules(report))

    def test_selfdestruct_in_a_file_that_uses_delegatecall(self):
        report = analyze("""
contract Impl {
    function destroy() external { selfdestruct(payable(msg.sender)); }
    function f(address a) external { a.delegatecall(""); }
}
""")
        found = rules(report)
        self.assertIn("selfdestruct-in-proxy", found)
        self.assertNotIn("selfdestruct", found)
        self.assertEqual(only(report, "selfdestruct-in-proxy")[0]["level"], "high")

    def test_plain_selfdestruct_has_no_proxy_rule(self):
        report = analyze("contract C { function f() external { selfdestruct(payable(msg.sender)); } }")
        self.assertIn("selfdestruct", rules(report))
        self.assertNotIn("selfdestruct-in-proxy", rules(report))

    def test_spot_price_from_amm_reserves(self):
        report = analyze("""
contract O {
    function price(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IPair(pair).getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }
}
""")
        self.assertEqual(only(report, "spot-price-oracle")[0]["level"], "notable")

    def test_spot_price_from_balance_ratio(self):
        report = analyze("""
contract T {
    function sharePrice() external view returns (uint256) {
        return IERC20(token).balanceOf(address(this)) * 1e18 / totalSupply;
    }
}
""")
        self.assertIn("spot-price-oracle", rules(report))

    def test_oracle_staleness_and_its_suppression(self):
        bad = analyze("""
contract O {
    function get() external view returns (int256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return answer;
    }
}
""")
        self.assertEqual(only(bad, "oracle-staleness")[0]["level"], "notable")

        good = analyze("""
contract O {
    function get() external view returns (int256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        return answer;
    }
}
""")
        self.assertEqual(only(good, "oracle-staleness"), [])

    def test_signature_nonce_and_chainid(self):
        report = analyze("""
contract S {
    function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0), "bad");
        payable(signer).transfer(1);
    }
}
""")
        self.assertEqual(only(report, "signature-nonce")[0]["level"], "notable")
        self.assertEqual(only(report, "signature-chainid")[0]["level"], "info")

    def test_signature_rules_suppressed_by_nonce_and_chainid(self):
        report = analyze("""
contract S {
    mapping(address => uint256) public nonces;
    function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
        require(block.chainid == 1, "wrong chain");
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0), "bad");
        nonces[signer]++;
    }
}
""")
        self.assertEqual(only(report, "signature-nonce"), [])
        self.assertEqual(only(report, "signature-chainid"), [])

    def test_dedup_keeps_one_finding_per_rule_per_line(self):
        report = analyze("contract C { function f() external { require(tx.origin == tx.origin); } }")
        self.assertEqual(len(only(report, "tx-origin")), 1)

    def test_counts_and_not_checked_present(self):
        report = analyze("contract C { function f() external { require(tx.origin == msg.sender); } }")
        self.assertEqual(sum(report["counts"].values()), len(report["findings"]))
        self.assertTrue(report["not_checked"])


class ArtifactTests(unittest.TestCase):
    def test_standard_json_input_sources(self):
        payload = {
            "language": "Solidity",
            "sources": {"src/A.sol": {"content": "pragma solidity 0.8.20; contract A {}"}},
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "in.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            sources, extra, notes = sources_from_json(path)
        self.assertIn("src/A.sol", sources)
        self.assertEqual(notes, [])

    def test_foundry_artifact_has_ast_and_abi_only(self):
        payload = {
            "abi": [{"type": "function", "name": "transfer", "inputs": [
                {"type": "address"}, {"type": "uint256"}]}],
            "ast": {"nodeType": "SourceUnit", "nodes": [
                {"nodeType": "ContractDefinition", "name": "A", "contractKind": "contract",
                 "nodes": [{"nodeType": "FunctionDefinition", "name": "f",
                            "visibility": "public", "stateMutability": "nonpayable",
                            "parameters": {"parameters": []}, "modifiers": []}]}]},
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "A.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            sources, extra, notes = sources_from_json(path)
        self.assertEqual(sources, {})
        self.assertTrue(extra["ast_facts"])
        self.assertTrue(notes)
        sigs = abi_signatures(extra["abi"])
        self.assertEqual(sigs[0]["signature"], "transfer(address,uint256)")
        self.assertEqual(sigs[0]["selector"], "0xa9059cbb")

    def test_abi_tuple_flattening(self):
        abi = [{"type": "function", "name": "foo", "inputs": [
            {"type": "tuple", "components": [{"type": "address"}, {"type": "uint256"}]},
            {"type": "uint256"}]}]
        sigs = abi_signatures(abi)
        self.assertEqual(sigs[0]["signature"], "foo((address,uint256),uint256)")


class ImportTests(unittest.TestCase):
    def test_relative_imports_are_followed(self):
        with tempfile.TemporaryDirectory() as d:
            helper = os.path.join(d, "Helper.sol")
            main = os.path.join(d, "Main.sol")
            with open(helper, "w", encoding="utf-8") as fh:
                fh.write("pragma solidity 0.8.20; contract Helper {}")
            with open(main, "w", encoding="utf-8") as fh:
                fh.write('import "./Helper.sol";\ncontract Main {}')
            sources = collect_files(main)
        self.assertEqual(set(sources), {"Main.sol", "Helper.sol"})
        report = analyze_sources(sources, "Main.sol")
        self.assertEqual(report["summary"]["contracts"], 2)

    def test_external_imports_are_not_invented(self):
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "Main.sol")
            with open(main, "w", encoding="utf-8") as fh:
                fh.write('import "@openzeppelin/Ownable.sol";\ncontract Main {}')
            sources = collect_files(main)
        self.assertEqual(set(sources), {"Main.sol"})


class WebPayloadTests(unittest.TestCase):
    """The web server's request parsing, without starting a server."""

    def test_source_payload(self):
        report = analyze_payload({
            "source": "contract C { function f() external { require(tx.origin == msg.sender); } }",
            "name": "C.sol",
        })
        self.assertEqual(report["kind"], "source")
        self.assertEqual(report["target"], "C.sol")
        self.assertIn("tx-origin", [f["rule"] for f in report["findings"]])

    def test_sources_map_payload(self):
        report = analyze_payload({"sources": {"A.sol": "contract A {}", "B.sol": "contract B {}"}})
        self.assertEqual(report["summary"]["contracts"], 2)

    def test_artifact_payload_without_source_is_facts_only(self):
        report = analyze_payload({"artifact": {
            "abi": [{"type": "function", "name": "f", "inputs": []}],
            "ast": {"nodeType": "SourceUnit", "nodes": []},
        }})
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["abi_signatures"][0]["signature"], "f()")

    def test_missing_input_is_an_error(self):
        with self.assertRaises(ValueError):
            analyze_payload({})

    def test_artifact_as_json_string(self):
        report = analyze_payload({"artifact": json.dumps({
            "sources": {"A.sol": {"content": "pragma solidity 0.8.20; contract A {}"}},
        })})
        self.assertEqual(report["summary"]["contracts"], 1)

    def test_selector_payload_accepts_list_and_text(self):
        from_list = selector_payload({"signatures": ["approve(address,uint256)"]})
        self.assertEqual(from_list["selectors"][0]["selector"], "0x095ea7b3")
        from_text = selector_payload({"signatures": "foo()\nbar(uint256)"})
        self.assertEqual(len(from_text["selectors"]), 2)

    def test_features_and_disasm_from_raw_hex(self):
        target = "0x600160005260206000f3"
        feats = features_payload({"target": target, "raw": True})
        self.assertEqual(feats["features"]["code_size"], 10)
        dis = disasm_payload({"target": target, "raw": True})
        self.assertIn("RETURN", dis["instructions"][-1])

    def test_calldata_unlimited_approval(self):
        data = "0x095ea7b3" + ("0" * 24) + ("11" * 20) + ("f" * 64)
        out = calldata_payload({"data": data})
        self.assertEqual(out["selector"], "0x095ea7b3")
        self.assertTrue(any("UNLIMITED" in f["message"] for f in out["findings"]))

    def test_bytecode_layer_rejects_file_paths(self):
        with self.assertRaises(ValueError):
            features_payload({"target": "requirements.txt"})

    def test_typed_data_rejects_non_json(self):
        with self.assertRaises(ValueError):
            typed_data_payload({"payload": "not json"})

    def test_json_safe_keeps_big_integers_exact(self):
        big = 2 ** 256 - 1
        out = _json_safe({"amount": big, "small": 5, "nested": [big], "flag": True})
        self.assertEqual(out["amount"], str(big))
        self.assertEqual(out["small"], 5)
        self.assertEqual(out["nested"], [str(big)])
        self.assertIs(out["flag"], True)


if __name__ == "__main__":
    unittest.main()
