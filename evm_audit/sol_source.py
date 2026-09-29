"""Read Solidity *source* and report what a human should look at.

This is the layer the bytecode tools cannot reach: access control, ordering
of external calls versus state writes, `tx.origin`, unprotected initializers,
signature checks. Those live in the source, not in the deployed opcodes.

It is deliberately **not** a compiler and **not** a verdict. There is no
dependency on solc or tree-sitter: this is a lexer (comments and strings
removed, line numbers kept) plus a light structural pass that finds
contracts, functions, modifiers and state variables. That is enough to run
*purely syntactic* rules, and it is honest about everything it cannot know:

  - inheritance is not resolved, so a modifier defined in a base contract is
    invisible here unless it is also named at the call site;
  - types are not checked, so a name is only a name;
  - control flow is not evaluated, so "checked in a later statement" and
    "checked on every path" cannot be distinguished;
  - a finding is a place to *look*, never a claim that code is wrong -- and
    the absence of findings is never a claim that code is right.

Every finding carries a rule id, a level (high / notable / info), a file and
line, and a reason. Read them; do not count them.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

#: Two-character operators, so `==` never reads as `=` and `=>` never as `=`.
_PUNCT2 = {
    "=>", "==", "!=", ">=", "<=", "&&", "||", "++", "--", "**", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ":=", "->",
}
_NUMBER_RE = re.compile(
    r"0[xX][0-9a-fA-F_]+"
    r"|\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?"
)
_HEX32_RE = re.compile(r"\b0x[0-9a-fA-F]{64}\b")

VISIBILITIES = {"public", "external", "internal", "private"}
MUTABILITIES = {"pure", "view", "payable", "nonpayable"}
#: Keywords that begin declarations we skip at contract scope.
DECL_KEYWORDS = {
    "function", "modifier", "event", "error", "struct", "enum", "using",
    "import", "pragma", "constructor", "fallback", "receive", "contract",
    "library", "interface", "abstract", "type", "if", "for", "while",
    "return", "assembly", "unchecked", "emit", "require", "assert", "delete",
    "revert", "try", "catch", "do", "else", "new", "continue", "break",
}


@dataclass(frozen=True)
class Token:
    text: str
    kind: str  # "id" | "num" | "str" | "punct"
    line: int
    col: int

    def is_id(self, *names: str) -> bool:
        return self.kind == "id" and self.text in names

    def is_punct(self, *names: str) -> bool:
        return self.kind == "punct" and self.text in names


def tokenize(text: str) -> list[Token]:
    """Turn Solidity source into tokens, dropping comments and whitespace.

    String literals are kept as a single token (their text includes the
    quotes), so braces or keywords inside a string can never be mistaken for
    code -- the bug a naive regex scanner always has.
    """
    toks: list[Token] = []
    i, n = 0, len(text)
    line, col = 1, 1
    while i < n:
        c = text[i]

        if c == "\n":
            i += 1
            line += 1
            col = 1
            continue
        if c in " \t\r":
            i += 1
            col += 1
            continue

        # comments
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            col += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            i += 2
            col += 2
            continue

        # string literal (single or double quoted), with escapes
        if c in ("'", '"'):
            quote = c
            start_line, start_col, start = line, col, i
            i += 1
            col += 1
            while i < n:
                ch = text[i]
                if ch == "\\":
                    i += 2
                    col += 2
                    continue
                if ch == quote:
                    i += 1
                    col += 1
                    break
                if ch == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            toks.append(Token(text[start:i], "str", start_line, start_col))
            continue

        # identifier / keyword
        if c.isalpha() or c == "_" or c == "$":
            start = i
            while i < n and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            toks.append(Token(text[start:i], "id", line, col))
            col += i - start
            continue

        # number literal
        m = _NUMBER_RE.match(text, i)
        if m:
            toks.append(Token(m.group(0), "num", line, col))
            i = m.end()
            col += len(m.group(0))
            continue

        # punctuation
        if i + 1 < n and text[i : i + 2] in _PUNCT2:
            toks.append(Token(text[i : i + 2], "punct", line, col))
            i += 2
            col += 2
            continue
        toks.append(Token(c, "punct", line, col))
        i += 1
        col += 1
    return toks


# ---------------------------------------------------------------------------
# Structural helpers
# ---------------------------------------------------------------------------

def _match(toks: list[Token], i: int) -> tuple[list[Token], int]:
    """Return (inner tokens, index after closer) for the group opening at i."""
    open_t = toks[i].text
    close_t = {"(": ")", "[": "]", "{": "}"}[open_t]
    depth = 0
    j = i
    while j < len(toks):
        if toks[j].text == open_t:
            depth += 1
        elif toks[j].text == close_t:
            depth -= 1
            if depth == 0:
                return toks[i + 1 : j], j + 1
        j += 1
    return toks[i + 1 :], len(toks)  # unbalanced source


def _render(toks: list[Token]) -> str:
    s = " ".join(t.text for t in toks)
    s = re.sub(r"\s+([,;\)\]\}])", r"\1", s)
    s = re.sub(r"([\(\[\.])\s+", r"\1", s)
    s = re.sub(r"\s*=>\s*", " => ", s)
    return s.strip()


def _statement_around(toks: list[Token], i: int) -> list[Token]:
    """The statement containing toks[i], bounded by ; { } ."""
    start = i
    while start > 0 and toks[start - 1].text not in (";", "{", "}"):
        start -= 1
    end = i
    while end < len(toks) and toks[end].text not in (";", "}"):
        end += 1
    return toks[start:end]


def _skip_decl(toks: list[Token], i: int) -> int:
    """Skip one struct/enum/event/error/using declaration."""
    j = i
    while j < len(toks):
        if toks[j].text == "{":
            _, j = _match(toks, j)
            return j
        if toks[j].text == ";":
            return j + 1
        j += 1
    return j


# ---------------------------------------------------------------------------
# Parsed model
# ---------------------------------------------------------------------------

@dataclass
class Function:
    name: str
    kind: str  # function | constructor | fallback | receive | modifier
    line: int
    visibility: str | None = None
    mutability: str | None = None
    modifiers: list[str] = field(default_factory=list)
    params: str = ""
    body: list[Token] | None = None  # None for declarations without a body

    @property
    def is_protected(self) -> bool:
        return any(_looks_like_access_control(m) for m in self.modifiers)

    @property
    def has_initializer(self) -> bool:
        low = {m.lower() for m in self.modifiers}
        return bool(low & {"initializer", "reinitializer", "onlyinitializing"})

    @property
    def has_nonreentrant(self) -> bool:
        return any(m.lower() in {"nonreentrant", "nonreentrantview"} for m in self.modifiers)


@dataclass
class StateVar:
    name: str
    type: str
    line: int
    visibility: str | None = None
    constant: bool = False


@dataclass
class Contract:
    name: str
    kind: str  # contract | library | interface | abstract contract
    line: int
    bases: list[str] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    state_vars: list[StateVar] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)


@dataclass
class FileModel:
    path: str
    tokens: list[Token]
    pragmas: list[tuple[int, str]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    contracts: list[Contract] = field(default_factory=list)
    free_functions: list[Function] = field(default_factory=list)

    @property
    def functions(self) -> list[Function]:
        fns = list(self.free_functions)
        for c in self.contracts:
            fns.extend(c.functions)
        return fns

    @property
    def state_var_names(self) -> set[str]:
        names: set[str] = set()
        for c in self.contracts:
            names.update(v.name for v in c.state_vars)
        return names


def _looks_like_access_control(name: str) -> bool:
    low = name.lower()
    if low.startswith("only") or low.startswith("auth") or low.startswith("requires"):
        return True
    if "role" in low or low in {
        "initializer", "reinitializer", "onlyinitializing", "onlyproxy",
        "onlydelegatecall", "signatureonly", "onlytrustedforwarder",
    }:
        return True
    return False


def _parse_function(toks: list[Token], i: int) -> tuple[Function, int]:
    kw = toks[i].text
    kind = kw if kw in ("constructor", "fallback", "receive", "modifier") else "function"
    line = toks[i].line
    i += 1

    name: str
    if kind == "modifier":
        name = toks[i].text if i < len(toks) else "?"
        i += 1
    elif kw == "function":
        if i < len(toks) and toks[i].text == "(":
            name = "(fallback)"
        else:
            name = toks[i].text if i < len(toks) else "?"
            i += 1
    else:
        name = kind

    params = ""
    if i < len(toks) and toks[i].text == "(":
        inner, i = _match(toks, i)
        params = _render(inner)

    header: list[Token] = []
    body: list[Token] | None = None
    while i < len(toks):
        t = toks[i]
        if t.text == "{":
            body, i = _match(toks, i)
            break
        if t.text == ";":
            i += 1
            break
        header.append(t)
        i += 1

    visibility = None
    mutability = None
    modifiers: list[str] = []
    j = 0
    while j < len(header):
        t = header[j]
        low = t.text.lower()
        if low in VISIBILITIES:
            visibility = low
        elif low in MUTABILITIES:
            mutability = low
        elif low in ("virtual",):
            pass
        elif low == "override":
            if j + 1 < len(header) and header[j + 1].text == "(":
                _, j = _match(header, j + 1)
                j -= 1
        elif low == "returns":
            if j + 1 < len(header) and header[j + 1].text == "(":
                _, j = _match(header, j + 1)
                j -= 1
        elif t.kind == "id":
            modifiers.append(t.text)
            if j + 1 < len(header) and header[j + 1].text == "(":
                _, j = _match(header, j + 1)
                j -= 1
        j += 1

    return Function(name, kind, line, visibility, mutability, modifiers, params, body), i


def _decl_names(stmt: list[Token]) -> list[str]:
    """Best-effort declarator names for a state-variable statement."""
    names: list[str] = []
    depth = 0
    current: list[Token] = []
    parts: list[list[Token]] = []
    for t in stmt:
        if t.text in ("(", "[", "{"):
            depth += 1
        elif t.text in (")", "]", "}"):
            depth -= 1
        if t.text == "," and depth == 0:
            parts.append(current)
            current = []
            continue
        current.append(t)
    parts.append(current)

    for part in parts:
        head: list[Token] = []
        for t in part:
            if t.text == "=":
                break
            head.append(t)
        ids = [t.text for t in head if t.kind == "id"]
        if ids:
            names.append(ids[-1])
    return names


def _parse_state_vars(stmt: list[Token]) -> list[StateVar]:
    if not stmt:
        return []
    first = stmt[0].text
    if first in DECL_KEYWORDS or first == "}":
        return []
    names = _decl_names(stmt)
    if not names:
        return []
    visibility = next((t.text for t in stmt if t.text in VISIBILITIES), None)
    constant = any(t.text in ("constant", "immutable") for t in stmt)
    vis_i = len(stmt)
    for k, t in enumerate(stmt):
        if t.text in VISIBILITIES or t.text in ("constant", "immutable"):
            vis_i = k
            break
    type_text = _render(stmt[:vis_i]) or "(unknown)"
    return [
        StateVar(n, type_text, stmt[0].line, visibility, constant) for n in names
    ]


def _parse_contract(toks: list[Token], i: int) -> tuple[Contract, int]:
    kind = toks[i].text
    line = toks[i].line
    i += 1
    if kind == "abstract":
        kind = "abstract contract"
        if i < len(toks) and toks[i].text == "contract":
            i += 1
    name = toks[i].text if i < len(toks) else "?"
    i += 1

    bases: list[str] = []
    saw_is = False
    while i < len(toks) and toks[i].text != "{":
        if toks[i].text == "is":
            saw_is = True
        elif saw_is and toks[i].kind == "id" and toks[i].text not in ("is",):
            bases.append(toks[i].text)
        elif saw_is and toks[i].text == "(":
            _, i = _match(toks, i)
            i -= 1
        i += 1
    if i >= len(toks):
        return Contract(name, kind, line, bases), i
    body, i = _match(toks, i)

    contract = Contract(name, kind, line, bases)
    j = 0
    while j < len(body):
        t = body[j]
        if t.text in ("function", "modifier") or (
            t.text in ("constructor", "fallback", "receive")
            and j + 1 < len(body)
            and body[j + 1].text == "("
        ):
            fn, j = _parse_function(body, j)
            contract.functions.append(fn)
            continue
        if t.text in ("event", "error", "struct", "enum", "using", "type"):
            j = _skip_decl(body, j)
            continue
        if t.text in DECL_KEYWORDS:
            j += 1
            continue
        stmt: list[Token] = []
        start = j
        while j < len(body) and body[j].text not in (";", "{", "}"):
            j += 1
        stmt = body[start:j]
        if j < len(body) and body[j].text == ";":
            contract.state_vars.extend(_parse_state_vars(stmt))
            j += 1
        elif j < len(body) and body[j].text == "{":
            _, j = _match(body, j)
        else:
            j += 1
    return contract, i


def parse_file(path: str, text: str) -> FileModel:
    toks = tokenize(text)
    model = FileModel(path, toks)
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.text in ("pragma", "import"):
            start = i
            while i < len(toks) and toks[i].text != ";":
                i += 1
            stmt = toks[start:i]
            if t.text == "pragma":
                model.pragmas.append((t.line, _render(stmt)))
            else:
                model.imports.append(_render(stmt))
            i += 1
            continue
        if t.text in ("contract", "library", "interface", "abstract"):
            contract, i = _parse_contract(toks, i)
            model.contracts.append(contract)
            continue
        if t.text == "function":
            fn, i = _parse_function(toks, i)
            model.free_functions.append(fn)
            continue
        if t.text in ("struct", "enum", "error", "event", "using", "type"):
            i = _skip_decl(toks, i)
            continue
        i += 1
    return model


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

LEVEL_ORDER = {"high": 0, "notable": 1, "info": 2}

#: Functions that, if externally reachable and unguarded, usually control value
#: or control flow. Names are matched case-insensitively.
SENSITIVE_FUNCTIONS_HIGH = {
    "initialize", "init", "setowner", "transferownership", "renounceownership",
    "upgradeto", "upgradetoandcall", "setimplementation", "setadmin", "withdraw",
    "withdrawall", "rescue", "sweep", "mint", "setoracle", "setsigner",
    "upgradebeacon", "setguardian",
}
SENSITIVE_FUNCTIONS_NOTABLE = {
    "burn", "pause", "unpause", "setfee", "setfees", "setrouter", "settreasury",
    "setminter", "addminter", "removeminter", "grantrole", "revokerole",
    "setlimits", "setmaxsupply", "blacklist", "freeze", "recover", "migrate",
    "claim", "setoperator", "updateprice", "setwithdrawaddress", "setbaseuri",
    "seturi", "rebalance", "harvest", "emergencywithdraw",
}

_CALLS = {
    "call", "delegatecall", "staticcall", "send", "transfer", "transferFrom",
    "safeTransfer", "safeTransferFrom",
}
_LOW_LEVEL = {"call", "delegatecall", "staticcall", "send"}
_CHECK_MARKERS = {"require", "assert", "revert", "if", "bool", "return"}
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^="}
_ORACLE_FEEDS = {"latestRoundData", "latestAnswer"}
_ORACLE_STALENESS = {"updatedAt", "updatedat", "answeredInRound", "answeredinround"}
_NONCE_GUARD_NAMES = {
    "used", "usedhashes", "usednonces", "processedhashes", "processednonces",
    "consumed", "spent", "executed",
}
_SUSPICIOUS_TARGETS = {
    "target", "_target", "impl", "_impl", "implementation", "_implementation",
    "newimpl", "newimplementation", "delegate", "_delegate", "logic", "_logic",
    "addr", "_addr", "dest", "_dest",
}
_RANDOMNESS = {"blockhash", "prevrandao", "difficulty", "timestamp", "number", "now"}


def _finding(rule: str, level: str, message: str, path: str, line: int) -> dict:
    return {"rule": rule, "level": level, "message": message, "file": path, "line": line}


def _stmt_has(stmt: list[Token], texts: set[str]) -> bool:
    return any(t.text in texts for t in stmt)


def _token_findings(path: str, toks: list[Token]) -> list[dict]:
    out: list[dict] = []
    ids_lower = {t.text.lower() for t in toks if t.kind == "id"}
    has_delegatecall = "delegatecall" in ids_lower

    # --- token-level, statement-scoped rules -------------------------------
    for i, t in enumerate(toks):
        text = t.text

        if text == "tx" and i + 2 < len(toks) and toks[i + 1].text == "." and toks[i + 2].text == "origin":
            out.append(_finding(
                "tx-origin", "high",
                "tx.origin in source: if it gates authorization, a phishing "
                "intermediary contract can pass the check for the victim. "
                "Use msg.sender.",
                path, t.line,
            ))

        if text in ("selfdestruct", "suicide"):
            if has_delegatecall:
                out.append(_finding(
                    "selfdestruct-in-proxy", "high",
                    f"{text}() in a file that also uses delegatecall: if this "
                    "code runs as an implementation behind a proxy, destroying it "
                    "can brick the proxy, and a delegatecall-reachable "
                    "selfdestruct can be triggered through the proxy. Verify "
                    "whether this contract is ever delegatecalled.",
                    path, t.line,
                ))
            else:
                out.append(_finding(
                    "selfdestruct", "high",
                    f"{text}() in source: the function can destroy the contract "
                    "and force-send its balance. (Post-Cancun it only moves the "
                    "balance, but it still strands any code relying on address "
                    "stability.)",
                    path, t.line,
                ))

        if text == "assembly" and i + 1 < len(toks) and toks[i + 1].text == "{":
            inner, _ = _match(toks, i + 1)
            has_effect = any(x.text in ("delegatecall", "call", "sstore") for x in inner)
            extra = (
                " It contains delegatecall/call/sstore, so it can move value or "
                "write storage." if has_effect else
                " Read it by hand; the surrounding source does not constrain it."
            )
            out.append(_finding(
                "assembly", "notable",
                "inline assembly: the compiler's safety checks do not apply here."
                + extra,
                path, t.line,
            ))

        if text == "unchecked" and i + 1 < len(toks) and toks[i + 1].text == "{":
            out.append(_finding(
                "unchecked", "info",
                "unchecked { } block: arithmetic inside wraps instead of "
                "reverting. Verify the bound is established before it.",
                path, t.line,
            ))

        if text == "ecrecover":
            out.append(_finding(
                "ecrecover", "info",
                "ecrecover used: the result is an address, not proof. Whether it "
                "is safe depends on the domain separator, the nonce, and the "
                "address(0) check -- none of which this rule can see.",
                path, t.line,
            ))

        if text in ("keccak256", "sha256", "keccak") and i + 1 < len(toks):
            # look at the argument group and the statement for randomness sources
            stmt = _statement_around(toks, i)
            joined = {x.text for x in stmt}
            if joined & _RANDOMNESS and ("block" in joined or "now" in joined):
                out.append(_finding(
                    "weak-randomness", "notable",
                    "hash of a block value on this line: block.timestamp, "
                    "block.number and prevrandao are miner/validator-influenceable. "
                    "Not safe as randomness.",
                    path, t.line,
                ))

        if text == "assert":
            out.append(_finding(
                "assert", "info",
                "assert() is for invariants and consumes all gas on failure; "
                "input checks should be require(). A reachable assert is a bug.",
                path, t.line,
            ))

        if text == "address" and i + 3 < len(toks) and toks[i + 1].text == "(" \
                and toks[i + 2].text == "this" and toks[i + 3].text == ")":
            if i + 4 < len(toks) and toks[i + 4].text == "." and i + 5 < len(toks) \
                    and toks[i + 5].text == "balance":
                out.append(_finding(
                    "self-balance", "info",
                    "address(this).balance: the contract's balance can be forced "
                    "up by selfdestruct/miner, so do not assume it implies "
                    "accounting.",
                    path, t.line,
                ))

        if i + 1 < len(toks) and toks[i + 1].text == "(" and text in ("getReserves", "slot0"):
            out.append(_finding(
                "spot-price-oracle", "notable",
                f"{text}() reads an AMM's current reserves (spot price). A flash "
                "loan can move them within one transaction, so a price derived "
                "from this is manipulable. A TWAP or an external oracle is the "
                "safe source.",
                path, t.line,
            ))

        if text == "balanceOf" and i + 1 < len(toks) and toks[i + 1].text == "(":
            stmt_texts = {x.text for x in _statement_around(toks, i)}
            if "/" in stmt_texts or "*" in stmt_texts:
                out.append(_finding(
                    "spot-price-oracle", "notable",
                    "balanceOf() used in arithmetic on this line: a balance ratio "
                    "is a spot price an attacker can move (a donation changes "
                    "balanceOf without changing supply). If this computes a "
                    "share/price, confirm the input is not an attacker-movable "
                    "balance.",
                    path, t.line,
                ))

    # --- once-per-file rules ----------------------------------------------
    enc = [t.line for i, t in enumerate(toks)
           if t.text == "abi" and i + 2 < len(toks) and toks[i + 1].text == "."
           and toks[i + 2].text == "encodePacked"]
    if enc:
        out.append(_finding(
            "encode-packed", "info",
            f"abi.encodePacked used {len(enc)}x (first line {enc[0]}): adjacent "
            "variable-length arguments can collide. Use abi.encode, or length-"
            "prefix each dynamic value.",
            path, enc[0],
        ))

    ec = next((t for t in toks if t.text == "ecrecover"), None)
    if ec is not None:
        bound = any("chainid" in x or "domainseparator" in x for x in ids_lower)
        if not bound:
            out.append(_finding(
                "signature-chainid", "info",
                "ecrecover is used but no chain id or EIP-712 domain separator is "
                "visible in this file: a signature valid here may be valid on a "
                "forked or sibling chain. Verify the signed digest binds the "
                "chain (block.chainid / a domain separator).",
                path, ec.line,
            ))

    return out


def _function_findings(
    path: str, fn: Function, state_vars: set[str], file_ids: set[str]
) -> list[dict]:
    if fn.body is None:
        return []  # interface / abstract declaration: nothing implemented here
    out: list[dict] = []
    body = fn.body
    low = fn.name.lower()

    # --- missing access control on sensitive functions --------------------
    if fn.kind == "function" and fn.visibility in ("public", "external"):
        if low in ("initialize", "init"):
            if not fn.has_initializer:
                out.append(_finding(
                    "unprotected-initializer", "high",
                    f"{fn.name}() has no initializer/reinitializer modifier. On a "
                    "proxy, anyone can call it first and take ownership; on a "
                    "deployed contract, it can be re-called unless guarded.",
                    path, fn.line,
                ))
        elif low in SENSITIVE_FUNCTIONS_HIGH | SENSITIVE_FUNCTIONS_NOTABLE:
            inline = _body_checks_caller(body)
            if not fn.modifiers and not inline:
                level = "high" if low in SENSITIVE_FUNCTIONS_HIGH else "notable"
                out.append(_finding(
                    "missing-access-control", level,
                    f"{fn.name}() is externally callable with no modifier at all "
                    "and no msg.sender check in its body. Confirm who may call it.",
                    path, fn.line,
                ))
            elif fn.modifiers and not fn.is_protected and not inline:
                out.append(_finding(
                    "unclear-access-control", "info",
                    f"{fn.name}() is guarded only by {', '.join(fn.modifiers)}, and "
                    "that name does not obviously check the caller. Confirm the "
                    "modifier is access control, not something else.",
                    path, fn.line,
                ))

    # --- ecrecover zero-address check ------------------------------------
    for i, t in enumerate(body):
        if t.text == "ecrecover":
            if not _body_checks_zero(body):
                out.append(_finding(
                    "ecrecover-zero", "notable",
                    "ecrecover result is not checked against address(0) in this "
                    "function: a malformed signature can recover zero, and some "
                    "callers treat that as 'valid'. Verify the check happens "
                    "where it matters.",
                    path, t.line,
                ))
            break

    # --- oracle: staleness and zero-round --------------------------------
    feed = next((t for t in body if t.text in _ORACLE_FEEDS), None)
    if feed is not None:
        provided = {t.text for t in body}
        if not (provided & _ORACLE_STALENESS):
            out.append(_finding(
                "oracle-staleness", "notable",
                "Chainlink feed read with no staleness check visible in this "
                "function: a frozen or stale feed keeps returning its last "
                "answer. Compare updatedAt against a heartbeat and reject a "
                "zero/negative answer.",
                path, feed.line,
            ))

    # --- signature replay: nonce -----------------------------------------
    ec = next((t for t in body if t.text == "ecrecover"), None)
    if ec is not None and not _has_nonce_guard(file_ids):
        out.append(_finding(
            "signature-nonce", "notable",
            "ecrecover is used and no nonce/replay guard is visible anywhere in "
            "this file. A valid signature may be replayable; verify a nonce is "
            "consumed, or the signed message is otherwise single-use.",
            path, ec.line,
        ))

    # --- unchecked external call return values ---------------------------
    for i, t in enumerate(body):
        if t.text != "." or i + 1 >= len(body):
            continue
        callee = body[i + 1].text
        if callee not in _CALLS:
            continue
        stmt = _statement_around(body, i)
        if _stmt_has(stmt, _CHECK_MARKERS) or any(x.text == "=" for x in stmt):
            continue
        level = "high" if callee in ("delegatecall",) else "notable"
        if callee in ("transfer", "send"):
            why = (
                f"{callee}() returns a bool that is ignored here. If this is an "
                "ERC-20 transfer, a false return is silent; native payable."
                f"{'transfer' if callee == 'transfer' else 'send'}() reverts or "
                "returns, depending on the branch. Confirm which one this is."
            )
        else:
            why = (
                f"a failed {callee}() does not revert by itself. Check it "
                "(require/if) or state why failure is acceptable."
            )
        out.append(_finding(
            "unchecked-call", level,
            f"return value of {callee}() is ignored on this line: {why}",
            path, t.line,
        ))

    # --- delegatecall target trust ---------------------------------------
    for i, t in enumerate(body):
        if t.text != "delegatecall":
            continue
        stmt = _statement_around(body, i)
        names = {x.text for x in stmt}
        if "msg" in names and "sender" in names:
            level, why = "high", "the target comes from msg.sender"
        elif names & _SUSPICIOUS_TARGETS:
            level, why = "high", "the target comes from a parameter-like name"
        else:
            level, why = "notable", "verify the target is trusted and immutable"
        if _inside_assembly(body, i):
            level, why = "high", "it runs inside inline assembly"
        out.append(_finding(
            "delegatecall-target", level,
            f"delegatecall ({why}): the callee runs with this contract's storage "
            "and balance.",
            path, t.line,
        ))

    # --- external call before a state write (CEI / reentrancy shape) ------
    if (
        fn.visibility in ("public", "external")
        and fn.mutability not in ("view", "pure")
        and not fn.has_nonreentrant
    ):
        first_call = next(
            (i for i, t in enumerate(body)
             if t.text == "." and i + 1 < len(body) and body[i + 1].text in _CALLS),
            None,
        )
        if first_call is not None:
            written = None
            for i in range(first_call + 1, len(body)):
                if _writes_state(body, i, state_vars):
                    written = body[i]
                    break
            if written is not None:
                out.append(_finding(
                    "state-after-call", "notable",
                    f"state variable '{written.text}' is written after an external "
                    f"call in {fn.name}(), and the function has no nonReentrant "
                    "modifier. Check checks-effects-interactions: a reentrant "
                    "callee could act before the write.",
                    path, written.line,
                ))
    return out


def _body_checks_caller(body: list[Token]) -> bool:
    texts = {t.text for t in body}
    if "onlyOwner" in texts or "_checkOwner" in texts or "_checkRole" in texts:
        return True
    if "msg" in texts and "sender" in texts:
        return bool(texts & {"require", "revert", "assert"})
    return False


def _body_checks_zero(body: list[Token]) -> bool:
    for i in range(len(body) - 2):
        if body[i].text == "address" and body[i + 1].text == "(" and body[i + 2].text == "0":
            return True
    for i in range(len(body) - 1):
        if body[i].text in ("!=", "==") and body[i + 1].text == "0":
            return True
    text = " ".join(t.text for t in body)
    return "address(0)" in text.replace(" ", "")


def _has_nonce_guard(file_ids: set[str]) -> bool:
    """A nonce/replay guard is 'visible' if any identifier in the file looks
    like one. Deliberately lenient: a false negative (missing a real replay
    bug) is quieter here than a false positive on every permit implementation.
    """
    if any("nonce" in name for name in file_ids):
        return True
    return bool(file_ids & _NONCE_GUARD_NAMES)


def _dedup(findings: list[dict]) -> list[dict]:
    """Drop repeats of the same rule at the same file:line."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f["rule"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _writes_state(body: list[Token], i: int, names: set[str]) -> bool:
    """True if the identifier at i is assigned to (`x = ...`, `x[i] = ...`,
    `x.field = ...`). Used to place a write relative to an external call."""
    if i >= len(body) or body[i].kind != "id" or body[i].text not in names:
        return False
    j = i + 1
    while j < len(body):
        t = body[j].text
        if t == "[":
            _, j = _match(body, j)
            continue
        if t == ".":
            j += 2
            continue
        return t in _ASSIGN_OPS
    return False


def _inside_assembly(body: list[Token], index: int) -> bool:
    j = 0
    while j < index:
        if body[j].text == "assembly" and j + 1 < len(body) and body[j + 1].text == "{":
            inner, after = _match(body, j + 1)
            if j < index < after:
                return True
            j = after
            continue
        j += 1
    return False


def _pragma_findings(path: str, pragmas: list[tuple[int, str]]) -> list[dict]:
    out: list[dict] = []
    for line, text in pragmas:
        if "solidity" not in text:
            continue
        if "^" in text or ">=" in text or "<" in text:
            out.append(_finding(
                "floating-pragma", "info",
                f"floating pragma ({text}): the deployed bytecode may come from a "
                "different compiler than the one you read. Pin it to audit.",
                path, line,
            ))
        m = re.search(r"(\d+)\.(\d+)", text)
        if m and int(m.group(1)) == 0 and int(m.group(2)) < 8:
            out.append(_finding(
                "pre-0.8-pragma", "notable",
                f"solc {m.group(1)}.{m.group(2)}: no built-in overflow/underflow "
                "checks. Every arithmetic result must be guarded by SafeMath or "
                "by hand.",
                path, line,
            ))
    return out


def _hex_literal_findings(path: str, text: str) -> list[dict]:
    out: list[dict] = []
    for m in list(_HEX32_RE.finditer(text))[:5]:
        line = text.count("\n", 0, m.start()) + 1
        out.append(_finding(
            "hardcoded-32-bytes", "info",
            "32-byte hex literal in source (0x"
            + m.group(0)[2:10]
            + "...): could be a role hash, a salt, or a secret. A secret in "
            "source is public.",
            path, line,
        ))
    return out


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

NOT_CHECKED = [
    "inheritance: a modifier or state variable defined in a base contract is "
    "invisible here unless named in this file",
    "types and casts: a name is only a name, not a checked type",
    "control flow: 'checked somewhere later' cannot be told from 'checked on "
    "every path', and requires may be bypassable",
    "economic logic: oracle/price manipulation, MEV, rounding, share inflation",
    "libraries and OpenZeppelin internals: only your code is read",
    "the deployed bytecode: the verified source may not match what is on-chain",
]


def analyze_sources(sources: dict[str, str], target: str, kind: str = "source") -> dict:
    """Run the structural pass and rules over {path: content}."""
    files: list[dict] = []
    all_findings: list[dict] = []

    for path, text in sources.items():
        model = parse_file(path, text)
        findings = _token_findings(path, model.tokens)
        findings += _pragma_findings(path, model.pragmas)
        findings += _hex_literal_findings(path, text)
        file_ids = {t.text.lower() for t in model.tokens if t.kind == "id"}
        for fn in model.free_functions:
            findings += _function_findings(path, fn, set(), file_ids)
        for contract in model.contracts:
            names = {v.name for v in contract.state_vars}
            for fn in contract.functions:
                findings += _function_findings(path, fn, names, file_ids)

        findings = _dedup(findings)
        findings.sort(key=lambda f: (LEVEL_ORDER[f["level"]], f["line"]))
        all_findings.extend(findings)

        files.append({
            "path": path,
            "pragmas": [p[1] for p in model.pragmas],
            "imports": model.imports,
            "findings": findings,
            "contracts": [
                {
                    "name": c.name,
                    "kind": c.kind,
                    "bases": c.bases,
                    "line": c.line,
                    "stateVariables": [
                        {"name": v.name, "type": v.type, "line": v.line,
                         "visibility": v.visibility, "constant": v.constant}
                        for v in c.state_vars
                    ],
                    "functions": [
                        {"name": f.name, "kind": f.kind, "line": f.line,
                         "visibility": f.visibility, "mutability": f.mutability,
                         "modifiers": f.modifiers, "params": f.params,
                         "hasBody": f.body is not None}
                        for f in c.functions
                    ],
                }
                for c in model.contracts
            ],
            "freeFunctions": [
                {"name": f.name, "line": f.line, "visibility": f.visibility,
                 "modifiers": f.modifiers}
                for f in model.free_functions
            ],
        })

    all_findings.sort(key=lambda f: (LEVEL_ORDER[f["level"]], f["file"], f["line"]))

    counts = {"high": 0, "notable": 0, "info": 0}
    for f in all_findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1

    return {
        "target": target,
        "kind": kind,
        "files": files,
        "findings": all_findings,
        "counts": counts,
        "summary": {
            "files": len(files),
            "contracts": sum(len(f["contracts"]) for f in files),
            "functions": sum(
                len(c["functions"]) for f in files for c in f["contracts"]
            ) + sum(len(f["freeFunctions"]) for f in files),
            "state_variables": sum(
                len(c["stateVariables"]) for f in files for c in f["contracts"]
            ),
        },
        "not_checked": NOT_CHECKED,
    }


def collect_directory(root: str) -> dict[str, str]:
    """Read every .sol file under a directory (recursive, sorted, bounded)."""
    sources: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "lib", "out", "cache")]
        for name in sorted(filenames):
            if name.endswith(".sol"):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace("\\", "/")
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    sources[rel] = fh.read()
    return sources


def collect_files(path: str) -> dict[str, str]:
    """Read a .sol file and follow its *relative* imports within its directory."""
    sources: dict[str, str] = {}
    root = os.path.dirname(os.path.abspath(path))
    queue = [path]
    seen: set[str] = set()
    while queue and len(sources) < 200:
        current = queue.pop(0)
        real = os.path.abspath(current)
        if real in seen or not os.path.isfile(real):
            continue
        seen.add(real)
        with open(real, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        rel = os.path.relpath(real, root).replace("\\", "/")
        sources[rel] = text
        for m in re.finditer(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']', text):
            imp = m.group(1)
            if imp.startswith("."):
                queue.append(os.path.join(os.path.dirname(real), imp))
    return sources


def sources_from_json(path: str) -> tuple[dict[str, str], dict, list[str]]:
    """Read a compiler/build artifact from disk and extract sources and facts."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return sources_from_json_data(data)


def sources_from_json_data(data: dict) -> tuple[dict[str, str], dict, list[str]]:
    """Extract sources/facts from a compiler or build artifact object.

    Returns (sources, extra, notes). `sources` is empty when the artifact
    embeds no source text (Foundry's `out/*.json` keeps the AST and metadata
    but not the source), in which case `extra['ast_facts']` is populated.
    """
    notes: list[str] = []
    sources: dict[str, str] = {}
    ast_facts: list[str] = []

    # Standard JSON input / solc output with embedded content.
    if isinstance(data.get("sources"), dict):
        for name, entry in data["sources"].items():
            if isinstance(entry, dict) and isinstance(entry.get("content"), str):
                sources[name] = entry["content"]
    if not sources and isinstance(data.get("source"), str):
        sources["<artifact>"] = data["source"]
    for key in ("sourceCode", "source_code"):
        if not sources and isinstance(data.get(key), str):
            sources["<artifact>"] = data[key]

    ast = data.get("ast")
    if isinstance(ast, dict):
        ast_facts = _facts_from_ast(ast)
    abi = data.get("abi")
    if isinstance(abi, str):
        try:
            abi = json.loads(abi)
        except json.JSONDecodeError:
            abi = None
    if isinstance(abi, list) and abi:
        ast_facts.append(f"ABI declares {len(abi)} entries")
    if not sources and ast_facts:
        notes.append(
            "This artifact embeds no source text, so source-level rules were "
            "skipped. It carries an AST/ABI only; the facts below are structural."
        )
    return sources, {"ast_facts": ast_facts, "abi": abi if isinstance(abi, list) else None}, notes


def _facts_from_ast(ast: dict) -> list[str]:
    facts: list[str] = []

    def walk(node):
        if not isinstance(node, dict):
            return
        ntype = node.get("nodeType")
        if ntype == "ContractDefinition":
            kind = (node.get("contractKind") or "contract").lower()
            bases = ", ".join(
                (b.get("baseName") or {}).get("name", "?")
                for b in node.get("baseContracts") or []
            )
            facts.append(f"{kind} {node.get('name')}" + (f" is {bases}" if bases else ""))
            for child in node.get("nodes") or []:
                walk(child)
            return
        if ntype == "FunctionDefinition":
            name = node.get("name") or node.get("kind") or "(fallback)"
            mods = ", ".join(
                (m.get("modifierName") or {}).get("name", "?")
                for m in node.get("modifiers") or []
                if isinstance(m, dict)
            )
            facts.append(
                f"function {name}({_ast_params(node)}) "
                f"[{node.get('visibility')} {node.get('stateMutability')}]"
                + (f" {mods}" if mods else "")
            )
        if ntype == "VariableDeclaration" and node.get("stateVariable"):
            facts.append(
                f"state variable {node.get('name')} "
                f"[{node.get('visibility')}"
                + (" constant" if node.get("constant") else "")
                + "]"
            )
        for key in ("nodes", "body", "statements", "subNodes"):
            for child in node.get(key) or []:
                walk(child)

    walk(ast)
    return facts


def _ast_params(node: dict) -> str:
    params = node.get("parameters") or {}
    names = [p.get("name") or "?" for p in params.get("parameters") or []]
    return ", ".join(names)


def abi_signatures(abi: list) -> list[dict]:
    """Turn an ABI into human signatures + selectors (for artifacts with no source)."""
    from .keccak import selector as selector_of

    if not abi:
        return []
    out = []
    for entry in abi:
        if not isinstance(entry, dict) or entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not name:
            continue
        types = []
        for inp in entry.get("inputs") or []:
            types.append(_abi_type(inp))
        sig = f"{name}({','.join(types)})"
        out.append({
            "signature": sig,
            "selector": selector_of(sig),
            "stateMutability": entry.get("stateMutability"),
        })
    return out


def _abi_type(inp: dict) -> str:
    t = inp.get("type", "")
    if t.startswith("tuple"):
        comps = ",".join(_abi_type(c) for c in inp.get("components") or [])
        suffix = t[len("tuple"):]
        return f"({comps}){suffix}"
    return t
