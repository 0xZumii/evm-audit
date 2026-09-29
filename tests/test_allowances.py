import io
import json
import unittest
from contextlib import redirect_stdout

import evm_audit.allowances as allowances
from evm_audit.abi import MAX_UINT160, MAX_UINT256
from evm_audit.allowances import (
    ALLOWANCE_SELECTOR,
    APPROVAL_FOR_ALL_TOPIC,
    APPROVAL_TOPIC,
    APPROVAL_TOPICS,
    BALANCE_OF_SELECTOR,
    DECIMALS_SELECTOR,
    IS_APPROVED_FOR_ALL_SELECTOR,
    MAX_UINT48,
    PERMIT2_ALLOWANCE_SELECTOR,
    PERMIT2_APPROVAL_TOPIC,
    PERMIT2_PERMIT_TOPIC,
    SYMBOL_SELECTOR,
    _classify,
    _decode_event,
    classify_spender,
    decode_symbol,
    describe_row,
    discover_events,
    format_units,
    load_token_list,
    read_allowance,
    read_permit2_allowance,
    scan,
)
from evm_audit.cli import _print_allowances

OWNER = "0x" + "aa" * 20
TOKEN_A = "0x" + "b1" * 20
TOKEN_B = "0x" + "b2" * 20
TOKEN_C = "0x" + "b3" * 20
TOKEN_D = "0x" + "b4" * 20
SPENDER_EOA = "0x" + "c1" * 20
SPENDER_CONTRACT = "0x" + "c2" * 20
SPENDER_DELEGATED = "0x" + "c3" * 20
DELEGATE_TARGET = "0x" + "d4" * 20
PERMIT2 = allowances.PERMIT2_ADDRESS.lower()


def addr_topic(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def word(value: int) -> str:
    return "0x" + format(value, "064x")


def abi_string(text: str) -> str:
    raw = text.encode()
    return "0x" + format(32, "064x") + format(len(raw), "064x") + raw.hex().ljust(64, "0")


def bytes32_text(text: str) -> str:
    return "0x" + text.encode().ljust(32, b"\x00").hex()


def event_log(topic0: str, contract: str, indexed: list, block: int = 100,
              tx: str = "0x" + "01" * 32) -> dict:
    topics = [topic0, addr_topic(OWNER)] + [addr_topic(item) for item in indexed]
    return {"address": contract, "topics": topics, "blockNumber": hex(block),
            "transactionHash": tx}


class DerivationTests(unittest.TestCase):
    """Selectors and topics are derived; these pin them to published values."""

    def test_published_erc20_constants(self):
        self.assertEqual(
            APPROVAL_TOPIC,
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")
        self.assertEqual(
            APPROVAL_FOR_ALL_TOPIC,
            "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31")
        self.assertEqual(ALLOWANCE_SELECTOR, "0xdd62ed3e")
        self.assertEqual(IS_APPROVED_FOR_ALL_SELECTOR, "0xe985e9c5")
        self.assertEqual(BALANCE_OF_SELECTOR, "0x70a08231")
        self.assertEqual(SYMBOL_SELECTOR, "0x95d89b41")
        self.assertEqual(DECIMALS_SELECTOR, "0x313ce567")

    def test_permit2_constants_are_derived_not_transcribed(self):
        # The two event topics were confirmed against real Permit2 logs on
        # mainnet; unlike the ERC-20 constants above they have no other public
        # reference to pin against here.
        self.assertEqual(PERMIT2_ALLOWANCE_SELECTOR, "0x927da105")
        self.assertEqual(len(PERMIT2_APPROVAL_TOPIC), 66)
        self.assertEqual(len(PERMIT2_PERMIT_TOPIC), 66)
        self.assertEqual(APPROVAL_TOPICS[0], APPROVAL_TOPIC)


class EventDecodingTests(unittest.TestCase):
    def test_erc20_approval(self):
        log = event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA], block=16)
        event = _decode_event(log, OWNER)
        self.assertEqual(event["kind"], "erc20")
        self.assertEqual(event["token"], TOKEN_A)
        self.assertEqual(event["spender"], SPENDER_EOA)
        self.assertEqual(event["block"], 16)

    def test_operator_approval(self):
        event = _decode_event(
            event_log(APPROVAL_FOR_ALL_TOPIC, TOKEN_B, [SPENDER_DELEGATED]), OWNER)
        self.assertEqual(event["kind"], "operator")
        self.assertEqual(event["token"], TOKEN_B)
        self.assertEqual(event["spender"], SPENDER_DELEGATED)

    def test_permit2_reads_token_from_topic_two_not_the_log_address(self):
        log = event_log(PERMIT2_APPROVAL_TOPIC, PERMIT2, [TOKEN_A, SPENDER_CONTRACT])
        event = _decode_event(log, OWNER)
        self.assertEqual(event["kind"], "permit2")
        self.assertEqual(event["token"], TOKEN_A)
        self.assertEqual(event["permit2"], PERMIT2)
        self.assertEqual(event["spender"], SPENDER_CONTRACT)

    def test_permit2_permit_event_is_the_same_shape(self):
        log = event_log(PERMIT2_PERMIT_TOPIC, PERMIT2, [TOKEN_A, SPENDER_EOA])
        self.assertEqual(_decode_event(log, OWNER)["kind"], "permit2")

    def test_a_log_for_another_owner_is_rejected(self):
        # A hostile endpoint can return anything; the owner is re-checked.
        log = event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA])
        log["topics"][1] = addr_topic("0x" + "ee" * 20)
        self.assertIsNone(_decode_event(log, OWNER))

    def test_malformed_logs_are_ignored(self):
        self.assertIsNone(_decode_event({"topics": [APPROVAL_TOPIC]}, OWNER))
        self.assertIsNone(_decode_event(
            {"topics": [APPROVAL_TOPIC, addr_topic(OWNER)], "address": TOKEN_A}, OWNER))
        # Permit2 needs four topics; three is malformed.
        self.assertIsNone(_decode_event(
            {"topics": [PERMIT2_APPROVAL_TOPIC, addr_topic(OWNER), addr_topic(TOKEN_A)],
             "address": PERMIT2}, OWNER))


class DiscoverEventsTests(unittest.TestCase):
    def setUp(self):
        self._orig = allowances.get_logs

    def tearDown(self):
        allowances.get_logs = self._orig

    def test_pages_the_block_range(self):
        calls = []

        def fake(from_block, to_block, address=None, topics=None, url=None):
            calls.append((from_block, to_block))
            return []

        allowances.get_logs = fake
        discover_events(OWNER, [TOKEN_A], 0, 2999, page=2000, quiet=True)
        self.assertEqual(calls, [(0, 1999), (2000, 2999)])

    def test_addresses_are_chunked_into_separate_filters(self):
        groups = []

        def fake(from_block, to_block, address=None, topics=None, url=None):
            groups.append(list(address))
            return []

        allowances.get_logs = fake
        discover_events(OWNER, [TOKEN_A, TOKEN_B, TOKEN_C], 0, 9, page=10,
                        chunk=2, quiet=True)
        self.assertEqual([len(g) for g in groups], [2, 1])

    def test_events_are_deduplicated_with_provenance(self):
        log = event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA], block=100)
        other = event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA], block=250,
                          tx="0x" + "02" * 32)
        allowances.get_logs = lambda *a, **k: [log]
        report = discover_events(OWNER, [TOKEN_A], 0, 999, page=1000, quiet=True)
        self.assertEqual(len(report["events"]), 1)
        self.assertEqual(report["events"][0]["count"], 1)

        # Same candidate on two pages. The fixture returns both logs on every
        # page, so over the three pages (0..4 at 2 blocks each) the count is 6;
        # what matters is that it is one row, with first/last block kept.
        allowances.get_logs = lambda *a, **k: [log, other]
        report = discover_events(OWNER, [TOKEN_A], 0, 4, page=2, quiet=True)
        row = report["events"][0]
        self.assertEqual(row["count"], 6)
        self.assertEqual(row["first_block"], 100)
        self.assertEqual(row["last_block"], 250)

    def test_a_rejected_filter_is_split_not_abandoned(self):
        # A node that refuses filters larger than two addresses -- as public
        # nodes do -- must be handled by splitting, not by giving up.
        calls = []

        def picky(from_block, to_block, address=None, topics=None, url=None):
            calls.append(len(address))
            if len(address) > 2:
                raise RuntimeError("filter too large")
            return ([event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA])]
                    if TOKEN_A in address else [])

        allowances.get_logs = picky
        report = discover_events(OWNER, [TOKEN_A, TOKEN_B, TOKEN_C, TOKEN_D],
                                 0, 9, page=10, chunk=8, quiet=True)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["events"]), 1)
        self.assertIn(4, calls)  # the oversized filter was tried before splitting

    def test_a_transient_range_error_is_recovered_by_splitting(self):
        state = {"first": True}

        def flaky(from_block, to_block, address=None, topics=None, url=None):
            if state["first"]:
                state["first"] = False
                raise RuntimeError("range too large")
            return [event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA])]

        allowances.get_logs = flaky
        report = discover_events(OWNER, [TOKEN_A], 0, 3999, page=2000, quiet=True)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["events"]), 1)

    def test_a_dead_endpoint_stops_instead_of_fanning_out(self):
        def down(*a, **k):
            raise RuntimeError("all RPC endpoints failed")

        allowances.get_logs = down
        report = discover_events(OWNER, [TOKEN_A, TOKEN_B, TOKEN_C, TOKEN_D],
                                 0, 3999, page=2000, chunk=8, quiet=True)
        self.assertEqual(report["events"], [])
        self.assertTrue(report["errors"])
        # It must give up quickly, not attempt one call per address and block.
        self.assertLess(report["calls"], 40)


class StateReadTests(unittest.TestCase):
    def setUp(self):
        self._orig = allowances.eth_call

    def tearDown(self):
        allowances.eth_call = self._orig

    def test_allowance_value(self):
        allowances.eth_call = lambda *a, **k: word(1234)
        result = read_allowance(TOKEN_A, OWNER, SPENDER_EOA)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["value"], 1234)

    def test_revert_is_unreadable_not_zero(self):
        def reverts(*a, **k):
            raise RuntimeError("execution reverted")

        allowances.eth_call = reverts
        result = read_allowance(TOKEN_A, OWNER, SPENDER_EOA)
        self.assertEqual(result["status"], "unreadable")
        self.assertIsNone(result["value"])
        self.assertIn("reverted", result["reason"])

    def test_short_return_is_unreadable(self):
        allowances.eth_call = lambda *a, **k: "0x1234"
        self.assertEqual(read_allowance(TOKEN_A, OWNER, SPENDER_EOA)["status"],
                         "unreadable")

    def test_code_defect_propagates_instead_of_becoming_unreadable(self):
        def boom(*a, **k):
            raise TypeError("bug in this tool")

        allowances.eth_call = boom
        with self.assertRaises(TypeError):
            read_allowance(TOKEN_A, OWNER, SPENDER_EOA)

    def test_permit2_packed_word_is_unpacked(self):
        amount, expiration, nonce = 1000, 1_800_000_000, 7
        packed = amount | (expiration << 160) | (nonce << 208)
        allowances.eth_call = lambda *a, **k: word(packed)
        result = read_permit2_allowance(PERMIT2, OWNER, TOKEN_A, SPENDER_CONTRACT)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["amount"], amount)
        self.assertEqual(result["expiration"], expiration)
        self.assertEqual(result["nonce"], nonce)

    def test_is_approved_for_all_true_and_false(self):
        from evm_audit.allowances import read_is_approved_for_all

        allowances.eth_call = lambda *a, **k: word(1)
        self.assertTrue(read_is_approved_for_all(TOKEN_B, OWNER, SPENDER_EOA)["value"])
        allowances.eth_call = lambda *a, **k: word(0)
        self.assertFalse(read_is_approved_for_all(TOKEN_B, OWNER, SPENDER_EOA)["value"])


class ClassifyTests(unittest.TestCase):
    NOW = 1_700_000_000

    def test_erc20_three_way(self):
        self.assertEqual(_classify("erc20", {"status": "ok", "value": MAX_UINT256}, self.NOW),
                         "unlimited")
        self.assertEqual(_classify("erc20", {"status": "ok", "value": 0}, self.NOW),
                         "revoked")
        self.assertEqual(_classify("erc20", {"status": "ok", "value": 5}, self.NOW),
                         "active")

    def test_erc20_near_max_is_also_unlimited(self):
        # Protocols use max-minus-a-reserve; that is still infinite in practice,
        # and must not be reported as a 74-digit "allowance".
        self.assertEqual(_classify("erc20", {"status": "ok", "value": 1 << 255},
                                   self.NOW), "unlimited")
        self.assertEqual(_classify("erc20", {"status": "ok", "value": MAX_UINT256 - 50_000_000},
                                   self.NOW), "unlimited")
        self.assertEqual(_classify("erc20", {"status": "ok", "value": (1 << 255) - 1},
                                   self.NOW), "active")

    def test_operator_three_way(self):
        self.assertEqual(_classify("operator", {"status": "ok", "value": True}, self.NOW),
                         "operator")
        self.assertEqual(_classify("operator", {"status": "ok", "value": False}, self.NOW),
                         "revoked")

    def test_permit2_expiration_decides(self):
        base = {"status": "ok", "amount": 5}
        self.assertEqual(_classify("permit2", {**base, "expiration": self.NOW - 1}, self.NOW),
                         "expired")
        # Permit2 treats expiration 0 as already expired; it must not read active.
        self.assertEqual(_classify("permit2", {**base, "expiration": 0}, self.NOW),
                         "expired")
        self.assertEqual(_classify("permit2", {**base, "expiration": self.NOW + 1}, self.NOW),
                         "active")
        self.assertEqual(_classify("permit2",
                                   {"status": "ok", "amount": MAX_UINT160,
                                    "expiration": MAX_UINT48}, self.NOW),
                         "unlimited")
        self.assertEqual(_classify("permit2",
                                   {"status": "ok", "amount": 1 << 159,
                                    "expiration": self.NOW + 1}, self.NOW),
                         "unlimited")

    def test_unreadable_outranks_everything(self):
        for kind in ("erc20", "operator", "permit2"):
            self.assertEqual(_classify(kind, {"status": "unreadable"}, self.NOW),
                             "unreadable")


class SpenderClassTests(unittest.TestCase):
    def test_eoa(self):
        self.assertEqual(classify_spender("0x")["kind"], "eoa")

    def test_contract(self):
        self.assertEqual(classify_spender("0x60016000")["kind"], "contract")

    def test_eip7702_delegation_is_decoded(self):
        designator = "0xef0100" + DELEGATE_TARGET[2:]
        info = classify_spender(designator)
        self.assertEqual(info["kind"], "delegated")
        self.assertEqual(info["delegate"], DELEGATE_TARGET)

    def test_unreadable_code_is_unknown_not_eoa(self):
        self.assertEqual(classify_spender(None)["kind"], "unknown")


class SymbolDecodeTests(unittest.TestCase):
    def test_abi_string(self):
        raw = bytes.fromhex(abi_string("USDC")[2:])
        self.assertEqual(decode_symbol(raw), "USDC")

    def test_bytes32(self):
        raw = bytes.fromhex(bytes32_text("MKR")[2:])
        self.assertEqual(decode_symbol(raw), "MKR")

    def test_bare_short_bytes(self):
        self.assertEqual(decode_symbol(b"ABC"), "ABC")

    def test_control_characters_are_removed(self):
        # The realistic injection is a token returning an ANSI escape inside an
        # ABI string. It must not reach the terminal as an escape.
        raw = bytes.fromhex(abi_string("US\x1b[31mDC")[2:])
        decoded = decode_symbol(raw)
        self.assertIsNotNone(decoded)
        self.assertNotIn("\x1b", decoded)
        self.assertTrue(decoded.startswith("US"))

    def test_a_bytes32_with_control_bytes_is_rejected(self):
        # For the bytes32 form there is no need to sanitise: it is not a
        # plausible symbol, so it is dropped rather than displayed.
        raw = bytes.fromhex(bytes32_text("US\x1bDC")[2:])
        self.assertIsNone(decode_symbol(raw))

    def test_empty_is_none(self):
        self.assertIsNone(decode_symbol(b""))


class ScanTests(unittest.TestCase):
    """End to end, with the network faked. The point is what the report says
    when a read fails: unknown, never clean."""

    def setUp(self):
        self._saved = {name: getattr(allowances, name) for name in
                       ("eth_call", "get_logs", "get_code", "get_block_number", "chain_id")}

        def fake_get_logs(from_block, to_block, address=None, topics=None, url=None):
            logs = []
            for token in address or []:
                for log in {
                    TOKEN_A: [event_log(APPROVAL_TOPIC, TOKEN_A, [SPENDER_EOA], 95000)],
                    TOKEN_B: [event_log(APPROVAL_FOR_ALL_TOPIC, TOKEN_B,
                                        [SPENDER_DELEGATED], 96000)],
                    TOKEN_C: [event_log(APPROVAL_TOPIC, TOKEN_C, [SPENDER_EOA], 97000)],
                    TOKEN_D: [event_log(APPROVAL_TOPIC, TOKEN_D,
                                        [SPENDER_CONTRACT], 98000)],
                    PERMIT2: [event_log(PERMIT2_APPROVAL_TOPIC, PERMIT2,
                                        [TOKEN_A, SPENDER_CONTRACT], 99000)],
                }.get(token.lower(), []):
                    block = int(log["blockNumber"], 16)
                    if from_block <= block <= to_block:
                        logs.append(log)
            return logs

        returns = {
            (TOKEN_A, ALLOWANCE_SELECTOR): word(MAX_UINT256),
            (TOKEN_A, SYMBOL_SELECTOR): abi_string("USDC"),
            (TOKEN_A, DECIMALS_SELECTOR): word(6),
            (TOKEN_A, BALANCE_OF_SELECTOR): word(5_000_000),
            (TOKEN_B, IS_APPROVED_FOR_ALL_SELECTOR): word(1),
            (TOKEN_B, SYMBOL_SELECTOR): bytes32_text("NFT"),
            (TOKEN_C, ALLOWANCE_SELECTOR): word(0),
            (TOKEN_C, SYMBOL_SELECTOR): abi_string("OLD"),
            (TOKEN_C, DECIMALS_SELECTOR): word(18),
            (TOKEN_C, BALANCE_OF_SELECTOR): word(0),
            (PERMIT2, PERMIT2_ALLOWANCE_SELECTOR): word(
                1000 | (1_800_000_000 << 160) | (7 << 208)),
        }

        def fake_eth_call(address, data, url=None):
            key = (address.lower(), data[:10])
            if key in returns:
                return returns[key]
            raise RuntimeError("execution reverted")

        codes = {
            PERMIT2: "0x60016000",
            SPENDER_EOA: "0x",
            SPENDER_CONTRACT: "0x60016000",
            SPENDER_DELEGATED: "0xef0100" + DELEGATE_TARGET[2:],
        }

        allowances.get_logs = fake_get_logs
        allowances.eth_call = fake_eth_call
        allowances.get_code = lambda address, url=None: codes.get(address.lower(), "0x")
        allowances.get_block_number = lambda url=None: 100000
        allowances.chain_id = lambda url=None: 1

        self.report = scan(OWNER, [TOKEN_A, TOKEN_B, TOKEN_C, TOKEN_D],
                           from_block=90000, to_block=100000, quiet=True)

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(allowances, name, value)

    def row_for(self, kind, token):
        return next(r for r in self.report["rows"]
                    if r["kind"] == kind and r["token"] == token)

    def test_statuses_are_classified_per_current_state(self):
        counts = self.report["counts"]
        self.assertEqual(counts.get("unlimited"), 1)   # TOKEN_A
        self.assertEqual(counts.get("operator"), 1)    # TOKEN_B
        self.assertEqual(counts.get("revoked"), 1)     # TOKEN_C
        self.assertEqual(counts.get("unreadable"), 1)  # TOKEN_D
        self.assertEqual(counts.get("active"), 1)      # Permit2
        self.assertEqual(self.report["active"], 3)

    def test_a_failed_read_is_never_reported_as_revoked(self):
        row = self.row_for("erc20", TOKEN_D)
        self.assertEqual(row["status"], "unreadable")
        self.assertNotEqual(row["status"], "revoked")
        self.assertIn("NOT a revocation", row["message"])

    def test_state_is_re_read_not_taken_from_the_log(self):
        # TOKEN_C approved this spender in a log, but the current value is zero.
        self.assertEqual(self.row_for("erc20", TOKEN_C)["status"], "revoked")

    def test_unlimited_allowance_is_bounded_by_the_read_balance(self):
        row = self.row_for("erc20", TOKEN_A)
        self.assertEqual(row["status"], "unlimited")
        self.assertEqual(row["balance"], 5_000_000)
        self.assertIn("UNLIMITED", row["message"])
        self.assertIn("Your balance is 5", row["message"])

    def test_permit2_row_is_re_read_from_permit2_state(self):
        permit_row = next(r for r in self.report["rows"] if r["kind"] == "permit2")
        self.assertEqual(permit_row["status"], "active")
        self.assertEqual(permit_row["amount"], 1000)
        self.assertEqual(permit_row["exposure"], 1000)
        self.assertEqual(permit_row["decimals"], 6)

    def test_spenders_are_classified_from_code(self):
        spenders = self.report["spenders"]
        self.assertEqual(spenders[SPENDER_EOA]["kind"], "eoa")
        self.assertEqual(spenders[SPENDER_DELEGATED]["kind"], "delegated")
        self.assertEqual(spenders[SPENDER_CONTRACT]["kind"], "contract")
        # An EOA spender is called out in the message: a key can take.
        self.assertIn("is an EOA (no code)", self.row_for("erc20", TOKEN_A)["message"])

    def test_permit2_presence_is_stated_not_assumed(self):
        self.assertEqual(self.report["permit2"]["status"], "verified")
        self.assertEqual(self.report["permit2"]["code_size"], 4)

    def test_a_self_approval_is_not_counted_as_exposure(self):
        # The owner approving itself appears constantly on-chain (routers do
        # it), and counting it would be a false positive.
        allowances.get_logs = lambda *a, **k: [
            event_log(APPROVAL_TOPIC, TOKEN_A, [OWNER], 95000)]
        allowances.eth_call = lambda address, data, url=None: word(MAX_UINT256)
        allowances.get_code = lambda address, url=None: "0x60016000"
        report = scan(OWNER, [TOKEN_A], from_block=90000, to_block=100000, quiet=True)
        row = next(r for r in report["rows"] if r["token"] == TOKEN_A)
        self.assertEqual(row["status"], "self")
        self.assertEqual(report["active"], 0)
        self.assertIn("self-approval", row["message"])

    def test_report_carries_its_own_bounds(self):
        self.assertTrue(self.report["tokensSupplied"])
        self.assertEqual(self.report["tokensScanned"], 4)
        self.assertEqual(self.report["blocks"], [90000, 100000])

    def test_render_is_honest_about_what_it_did_not_check(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            _print_allowances(self.report, show_all=False)
        text = buffer.getvalue()
        self.assertIn("not checked", text)
        self.assertIn("outside the scanned range", text)
        self.assertIn("supplied list", text)
        self.assertIn("'unreadable' is not 'revoked'", text)
        self.assertIn("--all shows them", text)
        # The revoked row is counted but hidden by default...
        self.assertNotIn("current on-chain value is zero", text)

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            _print_allowances(self.report, show_all=True)
        self.assertIn("current on-chain value is zero", buffer.getvalue())

    def test_bundled_seed_is_labelled_as_not_a_token_list(self):
        allowances.get_logs = lambda *a, **k: []
        report = scan(OWNER, None, from_block=1, to_block=1, quiet=True)
        self.assertFalse(report["tokensSupplied"])
        self.assertEqual(report["tokensScanned"], 10)
        self.assertEqual(report["candidateEvents"], 0)

    def test_invalid_owner_is_rejected_before_any_call(self):
        with self.assertRaises(ValueError):
            scan("not-an-address", [TOKEN_A])


class TokenListTests(unittest.TestCase):
    def test_plain_address_list(self):
        text = "# tokens\n" + TOKEN_A + "\n" + TOKEN_B + '  "Name"\n'
        self.assertEqual(load_token_list(text), [TOKEN_A, TOKEN_B])

    def test_standard_token_list_json(self):
        payload = json.dumps({"tokens": [
            {"address": TOKEN_A, "chainId": 1, "symbol": "A"},
            {"address": TOKEN_B, "chainId": 1, "symbol": "B"},
        ]})
        self.assertEqual(load_token_list(payload), [TOKEN_A, TOKEN_B])

    def test_json_without_tokens_array_is_an_error(self):
        with self.assertRaises(ValueError):
            load_token_list('{"name": "not a token list"}')


class FormatTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(format_units(1_500_000, 6), "1.5")
        self.assertEqual(format_units(0, 18), "0")
        self.assertEqual(format_units(1234, None), "1234")
        self.assertEqual(format_units(None, 6), "?")

    def test_expiry(self):
        from evm_audit.allowances import format_expiry

        self.assertEqual(format_expiry(MAX_UINT48, 0), "never")
        self.assertIn("(past)", format_expiry(1_000_000_000, 1_700_000_000))


if __name__ == "__main__":
    unittest.main()