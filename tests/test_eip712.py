import unittest

from evm_audit.keccak import selector
from evm_audit.eip712 import (
    DOMAIN_SEPARATOR_SELECTOR,
    EIP712_DOMAIN_SELECTOR,
    batch_verify,
    check_domain,
    classify,
    decode_eip712_domain,
    domain_separator,
    encode_type,
    hash_typed_data,
    public_key_to_address,
    read_corpus,
    recover_address,
    recover_public_key,
)
from evm_audit.eip712 import _G

# --- The EIP-712 spec's own "Mail" example ---------------------------------
MAIL_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"},
    ],
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"},
    ],
}
MAIL_DOMAIN = {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
}
MAIL_MESSAGE = {
    "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!",
}
# Published in EIP-712 alongside the example above.
MAIL_SIGNATURE = (
    "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
    "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562" "1c"
)
MAIL_SIGNER = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"


def enc_word(n: int) -> str:
    return format(n, "064x")


class SelectorTests(unittest.TestCase):
    def test_erc5267_and_eip2612_selectors(self):
        self.assertEqual(EIP712_DOMAIN_SELECTOR, "0x84b0196e")
        self.assertEqual(DOMAIN_SEPARATOR_SELECTOR, "0x3644e515")


class EncodingTests(unittest.TestCase):
    def test_encode_type_appends_referenced_structs_sorted(self):
        self.assertEqual(
            encode_type("Mail", MAIL_TYPES),
            "Mail(Person from,Person to,string contents)"
            "Person(string name,address wallet)",
        )

    def test_domain_separator_skips_absent_fields(self):
        # A domain with only name+chainId must encode a 2-field struct.
        sep = domain_separator({"name": "X", "chainId": 1})
        self.assertEqual(len(sep), 32)
        # ...and differ from the same domain once version is added.
        self.assertNotEqual(sep, domain_separator({"name": "X", "chainId": 1, "version": "1"}))


class SpecVectorTests(unittest.TestCase):
    """The EIP-712 spec signature is an independent implementation's output.

    If our domainSeparator, typeHash, encodeData, and secp256k1 recovery are all
    correct, we recover the address the spec says signed it. Nothing here is
    self-referential.
    """

    def test_recovers_the_spec_signer(self):
        digest = hash_typed_data(MAIL_DOMAIN, MAIL_TYPES, "Mail", MAIL_MESSAGE)
        self.assertEqual(recover_address(digest, MAIL_SIGNATURE), MAIL_SIGNER)

    def test_public_key_for_scalar_one_is_generator(self):
        # G's address is a fixed, well-known constant -- checks curve + keccak.
        self.assertEqual(
            public_key_to_address(_G), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        )

    def test_recover_accepts_legacy_and_eip155_v(self):
        # v=28 (recid 1) and its EIP-155 form for chainId 1: 2*1+35+1 = 38.
        for v, sig in (
            (28, MAIL_SIGNATURE),
            (38, MAIL_SIGNATURE[:-2] + "26"),
        ):
            with self.subTest(v=v):
                digest = hash_typed_data(MAIL_DOMAIN, MAIL_TYPES, "Mail", MAIL_MESSAGE)
                self.assertEqual(recover_address(digest, sig), MAIL_SIGNER)

    def test_reject_out_of_range_recovery_id(self):
        digest = hash_typed_data(MAIL_DOMAIN, MAIL_TYPES, "Mail", MAIL_MESSAGE)
        r = int(MAIL_SIGNATURE[2:66], 16)
        s = int(MAIL_SIGNATURE[66:130], 16)
        with self.assertRaises(ValueError):
            recover_public_key(digest, 2, r, s)  # 2 is not a valid recovery id


class Erc5267DecodeTests(unittest.TestCase):
    def _build_return(self) -> str:
        # fields = 0x0d -> bits 0,2,3 -> name, chainId, verifyingContract
        head = [
            "0d" + "00" * 31,  # bytes1 fields is left-aligned in its slot
            enc_word(224),      # name
            enc_word(288),      # version (absent; value unspecified)
            enc_word(1),        # chainId
            "0" * 24 + "0" * 39 + "1",  # verifyingContract = 0x...01
            enc_word(0),        # salt
            enc_word(320),      # extensions
        ]
        name = enc_word(7) + "Example".encode().hex() + "00" * 25
        version = enc_word(0)
        extensions = enc_word(0)
        return "0x" + "".join(head) + name + version + extensions

    def test_decodes_present_fields_only(self):
        decoded = decode_eip712_domain(self._build_return())
        self.assertEqual(decoded["present"], ["name", "chainId", "verifyingContract"])
        self.assertEqual(
            decoded["domain"],
            {
                "name": "Example",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000001",
            },
        )
        self.assertEqual(decoded["extensions"], [])


class CheckDomainTests(unittest.TestCase):
    def test_match_is_not_a_finding(self):
        sep = "0x" + domain_separator(MAIL_DOMAIN).hex()
        out = check_domain(MAIL_DOMAIN, sep, node_chain_id=1, address=MAIL_DOMAIN["verifyingContract"])
        self.assertTrue(out["match"])
        self.assertNotIn("high", [f["level"] for f in out["findings"]])

    def test_mismatch_is_high(self):
        out = check_domain(MAIL_DOMAIN, "0x" + "00" * 32, node_chain_id=1)
        self.assertFalse(out["match"])
        self.assertIn("high", [f["level"] for f in out["findings"]])

    def test_chain_id_mismatch_is_high(self):
        sep = "0x" + domain_separator(MAIL_DOMAIN).hex()
        out = check_domain(MAIL_DOMAIN, sep, node_chain_id=10)
        self.assertIn("high", [f["level"] for f in out["findings"]])

    def test_missing_separator_is_notable_not_silent(self):
        out = check_domain(MAIL_DOMAIN, None)
        self.assertIsNone(out["match"])
        self.assertIn("notable", [f["level"] for f in out["findings"]])


class CorpusParsingTests(unittest.TestCase):
    def test_reads_name_version_and_chain_id(self):
        entries = read_corpus(
            "# a comment\n"
            '0xAAAA  "USD Coin"  2\n'
            "0xBBBB\n"
            '0xCCCC  "Dai Stablecoin"  1  1\n'
            "\n"
        )
        self.assertEqual(len(entries), 3)
        self.assertEqual(
            entries[0], {"address": "0xAAAA", "name": "USD Coin", "version": "2", "chainId": None}
        )
        self.assertIsNone(entries[1]["name"])
        self.assertEqual(entries[2]["chainId"], 1)

    def test_names_with_spaces_stay_whole(self):
        entries = read_corpus('0xDDDD  "Ether Mail Token v2"  3')
        self.assertEqual(entries[0]["name"], "Ether Mail Token v2")
        self.assertEqual(entries[0]["version"], "3")


class ClassifyTests(unittest.TestCase):
    """The regression that mattered: a contract WITH a separator and a supplied
    domain must be reported as verified, not silently dropped as `no_domain`."""

    def test_pre_erc5267_token_with_supplied_domain_is_checked(self):
        info = {
            "has_domain_separator": True,
            "declared_domain": MAIL_DOMAIN,
            "match": True,
            "findings": [{"level": "info", "message": "ok"}],
        }
        self.assertEqual(classify(info), "ok")

    def test_mismatch_wins_even_with_separator(self):
        info = {
            "has_domain_separator": True,
            "declared_domain": MAIL_DOMAIN,
            "match": False,
            "findings": [{"level": "high", "message": "bad"}],
        }
        self.assertEqual(classify(info), "mismatch")

    def test_no_separator_with_declared_domain_is_unverified(self):
        info = {
            "has_domain_separator": False,
            "declared_domain": MAIL_DOMAIN,
            "match": None,
            "findings": [],
        }
        self.assertEqual(classify(info), "unverified")

    def test_separator_without_declared_domain_is_no_domain(self):
        info = {
            "has_domain_separator": True,
            "declared_domain": None,
            "match": None,
            "findings": [],
        }
        self.assertEqual(classify(info), "no_domain")

    def test_nothing_at_all_is_no_domain(self):
        info = {
            "has_domain_separator": False,
            "declared_domain": None,
            "match": None,
            "findings": [],
        }
        self.assertEqual(classify(info), "no_domain")


class BatchTests(unittest.TestCase):
    def test_counts_and_rate_only_include_verifiable(self):
        original = batch_verify.__globals__["verify_domain"]

        def fake(address, rpc_url=None, expected=None):
            return {
                "has_domain_separator": expected is not None or address == "0xAA",
                "declared_domain": expected or ({"name": "x"} if address == "0xAA" else None),
                "match": {"0xAA": True, "0xBB": False}.get(address),
                "findings": [],
            }

        batch_verify.__globals__["verify_domain"] = fake
        try:
            report = batch_verify(
                [
                    {"address": "0xAA", "name": None, "version": None, "chainId": None},
                    {"address": "0xBB", "name": "T", "version": "1", "chainId": None},
                    {"address": "0xCC", "name": None, "version": None, "chainId": None},
                ],
                quiet=True,
            )
        finally:
            batch_verify.__globals__["verify_domain"] = original

        self.assertEqual(report["checked"], 2)
        self.assertEqual(report["counts"], {"ok": 1, "mismatch": 1, "no_domain": 1})
        self.assertAlmostEqual(report["mismatch_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
