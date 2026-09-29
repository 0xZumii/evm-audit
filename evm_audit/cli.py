"""Command-line entry point.

Examples:
    python -m evm_audit disasm 0xA0b8...eB48
    python -m evm_audit features 0xA0b8...eB48 --json
    python -m evm_audit compare 0xA0b8...eB48 0x7a25...488D
    python -m evm_audit resolve 0xA0b8...eB48 --features
    python -m evm_audit selector "approve(address,uint256)"
    python -m evm_audit calldata 0x095ea7b3<...>
    python -m evm_audit typed-data permit.json
    python -m evm_audit eip712 0xA0b8...eB48 --name "USD Coin" --version 2
    python -m evm_audit eip712-scan --lookback 20000 --corpus
    python -m evm_audit eip712-check corpus.txt --csv
    python -m evm_audit allowances 0xOwner... --tokens tokenlist.json
    python -m evm_audit source contracts/MyToken.sol
    python -m evm_audit source 0xA0b8...eB48 --min-level notable
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import rpc
from .allowances import (
    PERMIT2_ADDRESS,
    VISIBLE_STATUSES,
    load_token_list,
    scan,
)
from .disasm import disassemble, parse_hex
from .discovery import discover, discover_addresses, discovery_to_corpus, verify_corpus
from .eip712 import batch_verify, read_corpus, verify_domain, verify_typed_data
from .features import extract_features
from .keccak import selector as selector_of
from .resolve import resolve_implementation
from .signatures import analyze_calldata, analyze_typed_data
from .sol_source import (
    LEVEL_ORDER,
    abi_signatures,
    analyze_sources,
    collect_directory,
    collect_files,
    sources_from_json,
)
from .sourcify import fetch_sources

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def resolve_target(target: str, rpc_url: str | None, raw: bool) -> tuple[str, bytes]:
    if raw or (target.startswith("0x") and len(target) > 42):
        return "raw bytecode", parse_hex(target)
    if ADDRESS_RE.match(target):
        code_hex = rpc.get_code(target, rpc_url)
        if code_hex in ("0x", "0x0"):
            raise SystemExit(
                f"No code at {target}. Address is an EOA, or you are on the wrong chain/RPC."
            )
        return target, parse_hex(code_hex)
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8") as fh:
            return target, parse_hex(fh.read())
    raise SystemExit("target must be a 0x address, raw 0x-hex, or a file path")


def features_for(target: str, rpc_url: str | None, raw: bool) -> tuple[str, dict]:
    label, code = resolve_target(target, rpc_url, raw)
    return label, extract_features(disassemble(code))


def _print_summary(label: str, dis, feats: dict | None = None) -> None:
    print(f"target          : {label}")
    print(f"bytecode size   : {dis.raw_size} bytes "
          f"({len(dis.code)} after metadata strip)")
    print(f"instructions    : {len(dis.instructions)}")
    print(f"jumpdests       : {len(dis.jumpdests)}")
    if dis.metadata:
        bits = []
        if dis.metadata.get("solc"):
            bits.append(f"solc {dis.metadata['solc']}")
        if dis.metadata.get("ipfs"):
            bits.append(f"ipfs {dis.metadata['ipfs'][:14]}...")
        if bits:
            print(f"metadata        : {', '.join(bits)}")
    if feats is None:
        return
    print(f"entropy         : {feats['bytecode_entropy']}/8.0 bits/byte")
    print(f"selectors       : {len(feats['function_selectors'])} recovered")
    if feats["is_minimal_proxy"]:
        print(f"proxy           : minimal proxy -> {feats['minimal_proxy_target']}")
    elif feats["proxy_like"]:
        print("proxy           : proxy-like (delegatecall/slots)")


def _print_signals(feats: dict) -> None:
    signals = feats["risk_signals"]
    print("\nsignals")
    if not signals:
        print("  (none)")
    for s in signals:
        print(f"  [{s['level']:<7}] {s['message']}")


def cmd_disasm(args) -> int:
    label, code = resolve_target(args.target, args.rpc, args.raw)
    dis = disassemble(code, strip_meta=not args.keep_metadata)
    _print_summary(label, dis)

    shown = dis.instructions[: args.limit] if args.limit else dis.instructions
    print("\npc      opcode        operand")
    for ins in shown:
        print(ins.render())
    if args.limit and len(dis.instructions) > args.limit:
        print(f"... {len(dis.instructions) - args.limit} more instructions "
              f"(raise --limit to see them)")
    return 0


def cmd_features(args) -> int:
    label, code = resolve_target(args.target, args.rpc, args.raw)
    dis = disassemble(code, strip_meta=not args.keep_metadata)
    feats = extract_features(dis)
    if args.json:
        print(json.dumps({"target": label, "features": feats}, indent=2))
        return 0

    _print_summary(label, dis, feats)
    _print_signals(feats)

    print("\ntop opcodes")
    for name, count in list(feats["opcode_counts"].items())[: args.top]:
        print(f"  {name:<14} {count}")

    if feats["function_selectors"]:
        print("\nfunction selectors")
        for sel in feats["function_selectors"]:
            print(f"  {sel}")

    if feats["audit_notes"]:
        print("\nwhy these matter")
        for n in feats["audit_notes"]:
            print(f"  {n['opcode']} (x{n['count']}): {n['note']}")
    return 0


def cmd_fetch(args) -> int:
    label, code = resolve_target(args.target, args.rpc, False)
    out = args.out or (re.sub(r"[^0-9a-fA-F]", "", label)[:12] + ".hex")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("0x" + code.hex())
    print(f"wrote {len(code)} bytes to {out}")
    return 0


def cmd_compare(args) -> int:
    la, fa = features_for(args.a, args.rpc, args.raw)
    lb, fb = features_for(args.b, args.rpc, args.raw)

    if args.json:
        print(json.dumps({"a": {"target": la, "features": fa},
                          "b": {"target": lb, "features": fb}}, indent=2))
        return 0

    def n(f, key):
        return len(f[key]) if key == "function_selectors" else f[key]

    rows = [
        ("code_size", "code_size"),
        ("instruction_count", "instruction_count"),
        ("bytecode_entropy", "bytecode_entropy"),
        ("proxy_like", "proxy_like"),
        ("is_minimal_proxy", "is_minimal_proxy"),
        ("delegatecall_count", "delegatecall_count"),
        ("storage_writes", "storage_writes"),
        ("storage_reads", "storage_reads"),
        ("log_count", "log_count"),
        ("unknown_opcode_count", "unknown_opcode_count"),
        ("function_selectors", "function_selectors"),
    ]
    print(f"{'feature':<22} {'A':<22} B")
    print(f"{'A = ' + la:<45} B = {lb}")
    print("-" * 78)
    for label, key in rows:
        print(f"{label:<22} {str(n(fa, key)):<22} {n(fb, key)}")

    sel_a = set(fa["function_selectors"])
    sel_b = set(fb["function_selectors"])
    only_a = sel_a - sel_b
    only_b = sel_b - sel_a
    if only_a or only_b:
        print("\nselectors")
        if only_a:
            print(f"  only in A: {', '.join(sorted(only_a))}")
        if only_b:
            print(f"  only in B: {', '.join(sorted(only_b))}")
        print(f"  shared  : {', '.join(sorted(sel_a & sel_b)) or '(none)'}")
    return 0


def cmd_resolve(args) -> int:
    info = resolve_implementation(args.target, args.rpc)
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"address         : {info['address']}")
        print(f"kind            : {info['kind']}")
        if info["implementation"]:
            print(f"implementation  : {info['implementation']}")
        if info["beacon"]:
            print(f"beacon          : {info['beacon']}")
        if info["admin"]:
            print(f"admin           : {info['admin']}")

    if args.features and info["implementation"]:
        label, code = resolve_target(info["implementation"], args.rpc, False)
        feats = extract_features(disassemble(code))
        print(f"\n--- implementation {info['implementation']} ---")
        _print_signals(feats)
        print(f"\nselectors: {', '.join(feats['function_selectors']) or '(none)'}")
    return 0


def cmd_selector(args) -> int:
    for sig in args.signatures:
        print(f"{selector_of(sig)}  {sig}")
    return 0


def cmd_calldata(args) -> int:
    result = analyze_calldata(args.data)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    if result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    print(f"selector        : {result['selector']}")
    print(f"signature       : {result['signature'] or 'unknown'}")
    print(f"label           : {result['label'] or '-'}")
    if result["args"]:
        print("\narguments")
        for a in result["args"]:
            print(f"  {a['name']:<12} {a['type']:<10} {a['value']}")
    print("\nfindings")
    for f in result["findings"]:
        print(f"  [{f['level']:<7}] {f['message']}")
    return 0


def cmd_typed_data(args) -> int:
    if args.file == "-":
        raw = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as fh:
            raw = fh.read()
    payload = json.loads(raw)
    # Tolerate a wrapper like {"params": [address, data]} by picking the object.
    if "types" not in payload and isinstance(payload.get("params"), list):
        payload = next((p for p in payload["params"] if isinstance(p, dict)), payload)
    result = analyze_typed_data(payload)
    eip = verify_typed_data(
        payload,
        rpc_url=args.rpc,
        expected_signer=args.signer,
        signature=args.signature,
        check_domain=args.check_domain,
    )
    result["digest"] = eip["digest"]
    result["signer"] = eip["signer"]
    result["eip712_findings"] = eip["findings"]

    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    d = result["domain"]
    print(f"primaryType     : {result['primaryType']}")
    print(f"domain          : {d['name']} v{d['version']} (chainId {d['chainId']})")
    print(f"verifyingContract: {d['verifyingContract']}")
    if result["digest"]:
        print(f"digest          : {result['digest']}")
    if result["signer"]:
        print(f"signer          : {result['signer']}")
    print("\nmessage")
    for f in result["fields"]:
        print(f"  {f['path']:<24} {f['value']}")
    print("\nfindings")
    for f in result["findings"] + result["eip712_findings"]:
        print(f"  [{f['level']:<7}] {f['message']}")
    return 0


def cmd_eip712(args) -> int:
    expected: dict = {}
    if args.name is not None:
        expected["name"] = args.name
    if args.version is not None:
        expected["version"] = args.version
    if args.salt is not None:
        expected["salt"] = args.salt
    if args.chain_id is not None:
        expected["chainId"] = args.chain_id

    info = verify_domain(args.target, args.rpc, expected or None)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"address           : {info['address']}")
    print(f"declaration       : {info['declaration_source'] or '(none found)'}")
    print(f"node chainId      : {info['node_chain_id']}")
    declared = info["declared_domain"]
    if declared:
        print("declared domain")
        for key in ("name", "version", "chainId", "verifyingContract", "salt"):
            if key in declared:
                print(f"  {key:<16}: {declared[key]}")
    if info.get("extensions"):
        print(f"extensions        : {info['extensions']}")
    if info.get("onchain_separator"):
        print(f"on-chain separator: {info['onchain_separator']}")
    if info.get("recomputed_separator"):
        print(f"recomputed sep    : {info['recomputed_separator']}")
        match = info.get("match")
        print(f"match             : {'yes' if match else 'NO' if match is False else 'unknown'}")

    print("\nfindings")
    for f in info["findings"]:
        print(f"  [{f['level']:<7}] {f['message']}")
    return 0


def cmd_eip712_check(args) -> int:
    if args.file == "-":
        text = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as fh:
            text = fh.read()
    entries = read_corpus(text)
    if not entries:
        print("no entries found (blank lines and '#' comments are skipped)",
              file=sys.stderr)
        return 1

    if args.corpus:
        return _report_corpus(verify_corpus(entries, args.rpc, quiet=args.csv or args.json),
                              args)

    report = batch_verify(entries, args.rpc, quiet=args.csv or args.json)

    if args.csv:
        import csv

        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["address", "status", "separator", "recomputed",
                         "declared_by", "findings"])
        for row in report["rows"]:
            writer.writerow([
                row["address"], row["status"], row["separator"] or "",
                row["recomputed"] or "", row["declared_by"] or "",
                " | ".join(row["findings"]),
            ])
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    for row in report["rows"]:
        note = f"  {row['findings'][0]}" if row["status"] == "mismatch" and row["findings"] else ""
        print(f"  [{row['status']:<10}] {row['address']}{note}")

    counts = report["counts"]
    print(f"\nchecked           : {report['checked']} of {report['total']}")
    for key in ("ok", "mismatch", "unverified", "no_domain", "uncompared", "error"):
        if counts.get(key):
            print(f"  {key:<12}: {counts[key]}")
    rate = report["mismatch_rate"]
    print("mismatch rate     : "
          + ("n/a (nothing verifiable)" if rate is None
             else f"{rate:.1%} of {report['checked']} verifiable domains"))
    if counts.get("unverified"):
        print("note              : 'unverified' contracts expose no DOMAIN_SEPARATOR(), "
              "so they are not evidence either way.")
    if counts.get("no_domain"):
        print("note              : 'no_domain' contracts may not use EIP-712 at all, or "
              "(pre-ERC-5267) need a name/version in the corpus to be checked.")
    return 0


def _report_corpus(report: dict, args) -> int:
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    for row in report["rows"]:
        line = f"  [{row['status']:<11}] {row['address']}"
        if row["status"] == "mismatch":
            line += f"  {row['findings'][0]}"
        print(line)
    counts = report["counts"]
    print(f"\ncross-checked     : {report['cross_checked']} of {report['total']} "
          "(have ERC-5267 to compare against)")
    for key in ("match", "mismatch", "no_erc5267"):
        if counts.get(key):
            print(f"  {key:<12}: {counts[key]}")
    if counts.get("no_erc5267"):
        print("note              : 'no_erc5267' entries cannot be cross-checked from the "
              "chain; their name/version is only as good as the file.")
    return 0


def cmd_eip712_scan(args) -> int:
    if args.addresses:
        if args.addresses == "-":
            text = sys.stdin.read()
        else:
            with open(args.addresses, "r", encoding="utf-8") as fh:
                text = fh.read()
        addresses = [e["address"] for e in read_corpus(text)]
        if not addresses:
            print("no addresses found in the supplied file", file=sys.stderr)
            return 1
        report = discover_addresses(addresses, args.rpc, args.chain_id,
                                    quiet=args.json or args.corpus)
    else:
        report = discover(
            lookback_blocks=args.lookback,
            to_block=args.to_block,
            rpc_url=args.rpc,
            chain=args.chain_id,
            page=args.page,
            quiet=args.json or args.corpus,
        )

    if args.corpus:
        text = discovery_to_corpus(report)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {len(report['candidates'])} candidates to {args.out}",
                  file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    if report["blocks"][0] is not None:
        print(f"chainId           : {report['chainId']}")
        print(f"blocks scanned    : {report['blocks'][0]}..{report['blocks'][1]} "
              f"({report['pages']} pages)")
    print(f"addresses seen    : {report['seen']}")
    print(f"EIP-2612 tokens   : {len(report['candidates'])}")
    print(f"not EIP-2612      : {len(report['rejected'])}")
    if report.get("log_errors"):
        print(f"log errors        : {len(report['log_errors'])} ranges failed")
        print("note              : public nodes often reject topics-only eth_getLogs; "
              "use --addresses with a token list instead.")

    print("\ncandidates (answered DOMAIN_SEPARATOR() on-chain)")
    for row in sorted(report["candidates"], key=lambda r: (-r["activity"], r["address"]))[: args.top]:
        tag = "ERC-5267" if row["erc5267"] else "separator"
        name = (row.get("declared") or {}).get("name")
        label = f'  "{name}"' if name else ""
        print(f"  {row['address']}  [{tag:<9}]{label}")
    if report["candidates"] and not any(r["erc5267"] for r in report["candidates"]):
        print("note              : none of these implement ERC-5267, so a name cannot be "
              "read from the chain; the corpus keeps them as bare addresses.")
    return 0


def cmd_allowances(args) -> int:
    tokens = None
    if args.tokens:
        if args.tokens == "-":
            text = sys.stdin.read()
        else:
            with open(args.tokens, "r", encoding="utf-8") as fh:
                text = fh.read()
        tokens = load_token_list(text)
        if not tokens:
            print("no token addresses found in the supplied list", file=sys.stderr)
            return 1

    report = scan(
        args.owner,
        tokens,
        from_block=args.from_block,
        to_block=args.to_block,
        lookback_blocks=args.lookback,
        page=args.page,
        chunk=args.chunk,
        max_calls=args.max_calls,
        rpc_url=args.rpc,
        permit2=args.permit2,
        include_permit2=not args.no_permit2,
        quiet=args.json or args.csv,
    )

    if args.csv:
        import csv

        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["owner", "status", "kind", "token", "symbol", "spender",
                         "spender_kind", "allowance", "amount", "balance", "exposure",
                         "expiration", "first_block", "last_block", "count", "message"])
        for row in report["rows"]:
            writer.writerow([
                report["owner"], row["status"], row["kind"], row["token"],
                row["symbol"] or "", row["spender"], row["spender_kind"] or "",
                row["allowance"] if row["allowance"] is not None else "",
                row["amount"] if row["amount"] is not None else "",
                row["balance"] if row["balance"] is not None else "",
                row["exposure"] if row["exposure"] is not None else "",
                row["expiration"] if row["expiration"] is not None else "",
                row["first_block"] if row["first_block"] is not None else "",
                row["last_block"] if row["last_block"] is not None else "",
                row["count"], row["message"],
            ])
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    _print_allowances(report, show_all=args.all)
    return 0


def _print_allowances(report: dict, show_all: bool) -> None:
    blocks = report["blocks"]
    print(f"owner             : {report['owner']}")
    print(f"chainId           : "
          f"{report['chainId'] if report['chainId'] is not None else '(unknown)'}")
    print(f"blocks scanned    : {blocks[0]}..{blocks[1]} ({report['calls']} log requests)")
    source = ("supplied list" if report["tokensSupplied"]
              else "bundled seed -- NOT a token list")
    print(f"tokens scanned    : {report['tokensScanned']} ({source})")
    permit2 = report["permit2"]
    line = permit2["status"]
    if permit2["status"] == "verified":
        line += f" {permit2['address']} ({permit2['code_size']} bytes)"
    elif permit2.get("address") and permit2["status"] in ("absent", "unverified"):
        line += f" {permit2['address']}"
    print(f"permit2           : {line}")
    print(f"candidate events  : {report['candidateEvents']} "
          "(every one re-read from current state)")
    if report.get("spenders"):
        kinds: dict[str, int] = {}
        for info in report["spenders"].values():
            kinds[info["kind"]] = kinds.get(info["kind"], 0) + 1
        summary = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
        print(f"spenders          : {len(report['spenders'])} ({summary})")

    print("\nfindings")
    shown = [row for row in report["rows"]
             if show_all or row["status"] in VISIBLE_STATUSES]
    if not shown:
        print("  (none found in the scanned range and token list)")
    for row in shown:
        print(f"  [{row['level']:<7}] {row['message']}")

    print("\ncounts")
    for status in ("unlimited", "operator", "active", "unreadable", "expired",
                   "self", "revoked"):
        if report["counts"].get(status):
            print(f"  {status:<11} {report['counts'][status]}")
    if report["unreadable"]:
        print("note              : 'unreadable' is not 'revoked'. Those states were not read.")
    hidden = (report["counts"].get("revoked", 0) + report["counts"].get("expired", 0)
              + report["counts"].get("self", 0))
    if not show_all and hidden:
        print(f"note              : {hidden} revoked/expired/self row(s) counted above but "
              "hidden; --all shows them.")

    print("\nnot checked")
    print(f"  - approvals granted before block {blocks[0]} (outside the scanned range)")
    if report["tokensSupplied"]:
        print(f"  - tokens outside the {report['tokensScanned']}-address list supplied")
    else:
        print("  - tokens outside the bundled seed of 10; it is not a token list")
    print("  - ERC-721 per-tokenId approvals and marketplace listings")
    print("  - what a contract spender will do with the allowance")
    if report["log_errors"]:
        print(f"  - {len(report['log_errors'])} log range(s) failed; "
              f"first: {report['log_errors'][0]}")


def _resolve_source_target(target: str, args) -> tuple[str, dict, list[str], dict]:
    """Return (kind, sources, notes, extra) for the `source` command target."""
    notes: list[str] = []
    extra: dict = {}

    if target == "-":
        return "source", {"<stdin>": sys.stdin.read()}, notes, extra

    if ADDRESS_RE.match(target):
        chain_id = args.chain_id
        if chain_id is None:
            try:
                chain_id = rpc.chain_id(args.rpc)
            except Exception as exc:  # noqa: BLE001 - surfaced to the user
                raise SystemExit(
                    "could not determine the chain id from the RPC; pass "
                    f"--chain-id (error: {exc})"
                )
        info = fetch_sources(target, chain_id)
        if info["status"] == "unverified":
            notes.append(
                f"No verified source for {target} on chain {chain_id} in Sourcify. "
                "It may be verified on an explorer that Sourcify does not mirror. "
                "There is nothing to read here -- this is not a clean result."
            )
            return "sourcify", {}, notes, {"sourcify": info}
        notes.append(
            f"Sourcify match: {info['match']} (chain {chain_id}). The source is "
            "what Sourcify matched to the deployed runtime code -- provenance, "
            "not proof of intent."
        )
        return "sourcify", info["sources"], notes, {"sourcify": info}

    if os.path.isdir(target):
        return "source", collect_directory(target), notes, extra

    if os.path.isfile(target):
        if target.endswith(".json"):
            sources, extra, json_notes = sources_from_json(target)
            return "artifact", sources, json_notes, extra
        return "source", collect_files(target), notes, extra

    raise SystemExit(
        "target must be a contract address, a .sol file, a directory, a JSON "
        "artifact, or '-' for stdin"
    )


def cmd_source(args) -> int:
    kind, sources, notes, extra = _resolve_source_target(args.target, args)

    if not sources:
        report = {
            "target": args.target,
            "kind": f"{kind}-facts",
            "notes": notes,
            "ast_facts": (extra or {}).get("ast_facts") or [],
            "abi_signatures": abi_signatures((extra or {}).get("abi")),
            "findings": [],
            "counts": {"high": 0, "notable": 0, "info": 0},
        }
        if args.json:
            print(json.dumps(report, indent=2))
            return 0
        print(f"target          : {report['target']}")
        print(f"kind            : {report['kind']}")
        for n in notes:
            print(f"note            : {n}")
        if report["ast_facts"]:
            print("\nstructural facts (from the AST)")
            for fact in report["ast_facts"]:
                print(f"  {fact}")
        if report["abi_signatures"]:
            print("\nABI functions")
            for row in report["abi_signatures"]:
                print(f"  {row['selector']}  {row['signature']}  [{row['stateMutability']}]")
        print("\nno source-level rules ran: there was no source text to read.")
        return 0

    report = analyze_sources(sources, args.target, kind)
    report["notes"] = notes
    if extra.get("sourcify"):
        report["sourcify"] = {
            k: extra["sourcify"][k] for k in ("match", "chainId", "address")
        }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    _print_source_report(report, args)
    return 0


def _print_source_report(report: dict, args) -> None:
    print(f"target          : {report['target']}")
    print(f"kind            : {report['kind']}")
    s = report["summary"]
    print(f"files           : {s['files']}")
    print(f"contracts       : {s['contracts']}")
    print(f"functions       : {s['functions']}")
    print(f"state variables : {s['state_variables']}")
    for n in report.get("notes", []):
        print(f"note            : {n}")

    print("\ncontracts")
    any_contract = False
    for f in report["files"]:
        for c in f["contracts"]:
            any_contract = True
            base = f" is {', '.join(c['bases'])}" if c["bases"] else ""
            print(f"  {c['name']} ({c['kind']}){base}  [{f['path']}:{c['line']}]")
            shown = c["functions"][: args.top]
            for fn in shown:
                vis = fn["visibility"] or "-"
                mut = fn["mutability"] or "-"
                mods = (" " + " ".join(fn["modifiers"])) if fn["modifiers"] else ""
                tail = "" if fn["hasBody"] else "  (declaration)"
                print(f"      {fn['kind']:<11} {fn['name']}({fn['params']}) "
                      f"{vis} {mut}{mods}{tail}")
            if len(c["functions"]) > len(shown):
                print(f"      ... {len(c['functions']) - len(shown)} more "
                      "(raise --top)")
    if not any_contract:
        print("  (none)")

    print("\nfindings")
    threshold = LEVEL_ORDER[args.min_level]
    shown = [f for f in report["findings"] if LEVEL_ORDER[f["level"]] <= threshold]
    if not shown:
        print("  (none at this level)")
    for f in shown:
        print(f"  [{f['level']:<7}] {f['file']}:{f['line']}  {f['rule']}")
        print(f"            {f['message']}")

    c = report["counts"]
    print(f"\ncounts          : {c.get('high', 0)} high, "
          f"{c.get('notable', 0)} notable, {c.get('info', 0)} info")
    if len(shown) < len(report["findings"]):
        print(f"note            : {len(report['findings']) - len(shown)} finding(s) "
              "hidden by --min-level")

    print("\nnot checked")
    for n in report["not_checked"]:
        print(f"  - {n}")
    print("\nfindings are places to look, not a verdict. Absence of findings is "
          "not a clean bill of health.")


def cmd_serve(args) -> int:
    from .server import run

    run(host=args.host, port=args.port, open_browser=args.open)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evm-audit",
        description="EVM bytecode + signature analysis for auditor practice.",
    )
    p.add_argument("--rpc", help="JSON-RPC endpoint (default: public Ethereum RPC)")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("disasm", help="disassemble an address / raw hex / file")
    d.add_argument("target")
    d.add_argument("--raw", action="store_true", help="treat target as raw hex")
    d.add_argument("--limit", type=int, default=200, help="max instructions to print")
    d.add_argument("--keep-metadata", action="store_true")
    d.set_defaults(func=cmd_disasm)

    f = sub.add_parser("features", help="extract features and signals")
    f.add_argument("target")
    f.add_argument("--raw", action="store_true")
    f.add_argument("--json", action="store_true")
    f.add_argument("--top", type=int, default=12, help="top opcodes to show")
    f.add_argument("--keep-metadata", action="store_true")
    f.set_defaults(func=cmd_features)

    c = sub.add_parser("compare", help="diff two contracts' feature vectors")
    c.add_argument("a")
    c.add_argument("b")
    c.add_argument("--raw", action="store_true")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_compare)

    r = sub.add_parser("resolve", help="resolve a proxy's implementation on-chain")
    r.add_argument("target")
    r.add_argument("--features", action="store_true",
                   help="also analyze the implementation's bytecode")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_resolve)

    s = sub.add_parser("selector", help="compute 4-byte selector(s) from ABI signature(s)")
    s.add_argument("signatures", nargs="+")
    s.set_defaults(func=cmd_selector)

    cd = sub.add_parser("calldata", help="decode transaction calldata (approvals, permits)")
    cd.add_argument("data", help="0x-prefixed calldata hex")
    cd.add_argument("--json", action="store_true")
    cd.set_defaults(func=cmd_calldata)

    td = sub.add_parser("typed-data", help="decode an eth_signTypedData_v4 JSON payload")
    td.add_argument("file", help="path to JSON, or '-' for stdin")
    td.add_argument("--signature", help="65-byte signature to recover the signer from")
    td.add_argument("--signer", help="expected signer address; flags a mismatch")
    td.add_argument("--check-domain", action="store_true",
                    help="also compare the payload domain against the contract on-chain")
    td.add_argument("--json", action="store_true")
    td.set_defaults(func=cmd_typed_data)

    ep = sub.add_parser("eip712", help="verify a contract's EIP-712 domain hashes")
    ep.add_argument("target", help="contract address")
    ep.add_argument("--name", help="expected domain name (for contracts without ERC-5267)")
    ep.add_argument("--version", help="expected domain version")
    ep.add_argument("--salt", help="expected domain salt")
    ep.add_argument("--chain-id", type=int, dest="chain_id",
                    help="expected chainId (default: read from the node)")
    ep.add_argument("--json", action="store_true")
    ep.set_defaults(func=cmd_eip712)

    ec = sub.add_parser("eip712-check",
                        help="batch-verify a list of contracts; the prevalence measurement")
    ec.add_argument("file", help="one address per line, or '-' for stdin")
    ec.add_argument("--csv", action="store_true", help="emit CSV rows for analysis")
    ec.add_argument("--corpus", action="store_true",
                    help="instead of the mismatch check, cross-check each entry's "
                         "name/version against the contract's own ERC-5267 declaration")
    ec.add_argument("--json", action="store_true")
    ec.set_defaults(func=cmd_eip712_check)

    sc = sub.add_parser("eip712-scan",
                        help="discover EIP-2612 tokens from chain history (for building a corpus)")
    sc.add_argument("--lookback", type=int, default=20000,
                    help="blocks of history to scan (default 20000)")
    sc.add_argument("--to-block", type=int, default=None, help="scan up to this block")
    sc.add_argument("--page", type=int, default=2000, help="blocks per eth_getLogs call")
    sc.add_argument("--chain-id", type=int, default=None, help="label the chain (default: ask node)")
    sc.add_argument("--addresses",
                    help="file of addresses to probe directly (recommended on public RPC); "
                         "'-' for stdin")
    sc.add_argument("--corpus", action="store_true", help="emit a corpus file instead of a report")
    sc.add_argument("--out", help="with --corpus, write to a file instead of stdout")
    sc.add_argument("--top", type=int, default=40, help="candidates to print")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_eip712_scan)

    al = sub.add_parser(
        "allowances",
        help="standing approvals for an address, re-read from current state",
        description="What can be taken from an address without another signature.",
    )
    al.add_argument("owner", help="address to inspect")
    al.add_argument("--tokens", help="address list or token-list JSON ('-' for stdin); "
                                     "default is a 10-token mainnet seed, which is not a list")
    al.add_argument("--lookback", type=int, default=20000,
                    help="blocks of history to scan (default 20000)")
    al.add_argument("--from-block", type=int, default=None,
                    help="scan from this block instead of --lookback")
    al.add_argument("--to-block", type=int, default=None)
    al.add_argument("--page", type=int, default=2000, help="blocks per eth_getLogs call")
    al.add_argument("--chunk", type=int, default=8,
                    help="token addresses per eth_getLogs filter (larger filters that a "
                         "node rejects are split automatically)")
    al.add_argument("--max-calls", type=int, default=8000, dest="max_calls",
                    help="give up after this many log requests (default 8000)")
    al.add_argument("--permit2", default=PERMIT2_ADDRESS,
                    help="Permit2 address (default: the canonical deployment)")
    al.add_argument("--no-permit2", action="store_true", help="skip Permit2 allowances")
    al.add_argument("--all", action="store_true",
                    help="also show revoked and expired rows")
    al.add_argument("--csv", action="store_true")
    al.add_argument("--json", action="store_true")
    al.set_defaults(func=cmd_allowances)

    ss = sub.add_parser(
        "source",
        help="read Solidity source: structure + syntactic rules",
        description="Analyze Solidity source from a file, directory, compiler "
                    "artifact, verified contract address, or stdin. Structural "
                    "triage for a human, never a verdict.",
    )
    ss.add_argument("target",
                    help="address, .sol file, directory, artifact .json, or '-'")
    ss.add_argument("--chain-id", type=int, dest="chain_id",
                    help="chain id for an address lookup (default: ask the RPC)")
    ss.add_argument("--min-level", choices=["high", "notable", "info"],
                    default="info", dest="min_level",
                    help="hide findings below this level (default: info)")
    ss.add_argument("--top", type=int, default=40,
                    help="functions to print per contract (default 40)")
    ss.add_argument("--json", action="store_true")
    ss.set_defaults(func=cmd_source)

    sv = sub.add_parser("serve",
                        help="run the local web UI for the source layer")
    sv.add_argument("--host", default="127.0.0.1",
                    help="interface to bind (default: 127.0.0.1, local only)")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--open", action="store_true",
                    help="open the page in a browser")
    sv.set_defaults(func=cmd_serve)

    ft = sub.add_parser("fetch", help="save runtime bytecode to a file")
    ft.add_argument("target")
    ft.add_argument("--out")
    ft.set_defaults(func=cmd_fetch)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
