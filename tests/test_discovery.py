import unittest

from evm_audit.discovery import (
    TRANSFER_TOPIC,
    ZERO_TOPIC,
    discovery_to_corpus,
    probe_eip2612,
    scan_transfer_logs,
)

import evm_audit.discovery as discovery


def addr_topic(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


class ScanLogsTests(unittest.TestCase):
    def setUp(self):
        self._orig = discovery.get_logs

    def tearDown(self):
        discovery.get_logs = self._orig

    def test_pages_the_range_and_collects_senders(self):
        calls = []

        def fake_get_logs(from_block, to_block, address=None, topics=None, url=None):
            calls.append((from_block, to_block))
            return [
                {"topics": [TRANSFER_TOPIC, addr_topic("0x" + "aa" * 20), addr_topic("0x" + "bb" * 20)],
                 "transactionHash": "0x" + "01" * 32},
                {"topics": [TRANSFER_TOPIC, addr_topic("0x" + "aa" * 20), addr_topic("0x" + "cc" * 20)],
                 "transactionHash": "0x" + "02" * 32},
            ]

        discovery.get_logs = fake_get_logs
        report = scan_transfer_logs(0, 2999, page=2000, quiet=True)

        self.assertEqual(calls, [(0, 1999), (2000, 2999)])
        self.assertIn("0x" + "aa" * 20, report["candidates"])
        # The fixture returns both logs on each of the two pages, so the sender
        # is counted once per page. The scanner does not dedupe by design --
        # `activity` is an occurrence count over the searched range.
        self.assertEqual(report["candidates"]["0x" + "aa" * 20]["activity"], 4)
        # first_tx must be the first one seen, for provenance
        self.assertEqual(
            report["candidates"]["0x" + "aa" * 20]["first_tx"], "0x" + "01" * 32
        )

    def test_mint_logs_are_ignored(self):
        discovery.get_logs = lambda *a, **k: [
            {"topics": [TRANSFER_TOPIC, ZERO_TOPIC, addr_topic("0x" + "bb" * 20)],
             "transactionHash": "0x" + "03" * 32},
        ]
        report = scan_transfer_logs(0, 10, quiet=True)
        self.assertEqual(report["candidates"], {})

    def test_log_errors_do_not_abort_the_scan(self):
        state = {"n": 0}

        def flaky(*a, **k):
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("range too large")
            return [{"topics": [TRANSFER_TOPIC, addr_topic("0x" + "aa" * 20), ZERO_TOPIC],
                     "transactionHash": "0x" + "04" * 32}]

        discovery.get_logs = flaky
        report = scan_transfer_logs(0, 3999, page=2000, quiet=True)
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("0x" + "aa" * 20, report["candidates"])


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self._orig = discovery.eth_call

    def tearDown(self):
        discovery.eth_call = self._orig

    def test_non_token_is_not_a_candidate(self):
        def reverts(*a, **k):
            raise RuntimeError("execution reverted")

        discovery.eth_call = reverts
        result = probe_eip2612("0x" + "11" * 20)
        self.assertFalse(result["has_separator"])

    def test_separator_alone_is_enough_without_erc5267(self):
        sep = "0x" + "ab" * 32

        def sep_only(address, data, url=None, block="latest"):
            if data.startswith("0x3644e515"):
                return sep
            raise RuntimeError("execution reverted")

        discovery.eth_call = sep_only
        result = probe_eip2612("0x" + "22" * 20)
        self.assertTrue(result["has_separator"])
        self.assertEqual(result["separator"], sep)
        self.assertFalse(result["erc5267"])
        self.assertIsNone(result["declared"])

    def test_short_return_is_not_a_separator(self):
        discovery.eth_call = lambda *a, **k: "0x1234"
        self.assertFalse(probe_eip2612("0x" + "33" * 20)["has_separator"])


class CorpusVerifyTests(unittest.TestCase):
    """The cross-check must not launder a tool bug into a per-contract status."""

    def setUp(self):
        self._orig = discovery.verify_domain

    def tearDown(self):
        discovery.verify_domain = self._orig

    def test_code_defect_propagates_instead_of_becoming_no_erc5267(self):
        def boom(*a, **k):
            raise NameError("name 'verify_domain' is not defined")

        discovery.verify_domain = boom
        with self.assertRaises(NameError):
            discovery.verify_corpus(
                [{"address": "0xAA", "name": "X", "version": "1", "chainId": None}],
                quiet=True,
            )

    def test_genuine_no_erc5267_is_reported_as_such(self):
        discovery.verify_domain = lambda *a, **k: {
            "declared_domain": None, "declaration_source": None, "findings": []
        }
        report = discovery.verify_corpus(
            [{"address": "0xAA", "name": "X", "version": "1", "chainId": None}],
            quiet=True,
        )
        self.assertEqual(report["counts"], {"no_erc5267": 1})

    def test_wrong_name_is_flagged_even_though_it_would_hash_fine(self):
        discovery.verify_domain = lambda *a, **k: {
            "declared_domain": {"name": "Real", "version": "2", "chainId": 1},
            "declaration_source": "ERC-5267 eip712Domain()",
            "findings": [],
        }
        report = discovery.verify_corpus(
            [{"address": "0xAA", "name": "Fake", "version": "9", "chainId": None}],
            quiet=True,
        )
        self.assertEqual(report["rows"][0]["status"], "mismatch")
        self.assertIn("Real", report["rows"][0]["findings"][0])


class CorpusRenderTests(unittest.TestCase):
    def test_names_are_only_written_when_read_from_the_chain(self):
        report = {
            "chainId": 1,
            "blocks": [100, 200],
            "candidates": [
                {"address": "0xAA", "activity": 2, "erc5267": True,
                 "declared": {"name": "Chain Named", "version": "1"}},
                {"address": "0xBB", "activity": 1, "erc5267": False, "declared": None},
            ],
        }
        text = discovery_to_corpus(report)
        self.assertIn('0xAA  "Chain Named"  1', text)
        self.assertIn("\n0xBB\n", text)
        # provenance is recorded, so the file can be regenerated and compared
        self.assertIn("blocks:  100..200", text)
        self.assertIn("chainId: 1", text)

    def test_supplied_addresses_do_not_claim_discovery(self):
        # The header must not say these were "observed" in logs when no log
        # scan ran. A false provenance claim is worse than none.
        text = discovery_to_corpus(
            {"chainId": 1, "blocks": [None, None], "candidates": []}
        )
        self.assertIn("supplied", text)
        self.assertNotIn("was observed emitting", text)
        self.assertNotIn("None..None", text)

    def test_entries_round_trip_through_read_corpus(self):
        from evm_audit.eip712 import read_corpus

        report = {
            "chainId": 1,
            "blocks": [1, 2],
            "candidates": [
                {"address": "0xAA", "activity": 1, "erc5267": True,
                 "declared": {"name": "Two Words", "version": "2"}},
            ],
        }
        entries = read_corpus(discovery_to_corpus(report))
        self.assertEqual(entries, [{"address": "0xAA", "name": "Two Words",
                                    "version": "2", "chainId": None}])


if __name__ == "__main__":
    unittest.main()
