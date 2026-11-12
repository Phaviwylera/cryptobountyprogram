"""Lightweight Solidity source model.

This is not a full compiler front-end. It strips comments/strings (keeping
offsets stable so line numbers stay correct), then recovers contracts,
functions, modifiers and state variables with brace matching. That is enough
for the heuristic detectors in :mod:`bountyscan.detectors`, and it works on
sources that do not compile in isolation (e.g. a single verified file with
missing imports).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path

VISIBILITIES = {"public", "external", "internal", "private"}
MUTABILITIES = {"view", "pure", "payable", "constant"}
NON_MODIFIER_WORDS = VISIBILITIES | MUTABILITIES | {"virtual", "override", "returns", "immutable"}
PARAM_NOISE = {"memory", "storage", "calldata", "payable", "indexed"}
STATEMENT_SKIP = {
    "using", "event", "error", "struct", "enum", "type", "import", "pragma",
    "function", "modifier", "constructor", "receive", "fallback",
}

CONTRACT_RE = re.compile(
    r"\b(?:(abstract)\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)\s*([^{;]*?)\{"
)
MEMBER_RE = re.compile(
    # The trailing "(" is optional (group 6) so a parenthesis-less modifier definition is parsed too:
    # `modifier byDFO virtual { ... }`, `modifier isSigner { ... }`. Without it the modifier - and the
    # msg.sender auth check in its body - was invisible, so every function it guards read as unprotected.
    r"(?<![.\w])(?:function\s+([A-Za-z_]\w*)|(constructor)|(receive)|(fallback)|modifier\s+([A-Za-z_]\w*))\s*(\()?"
)
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def strip_comments_and_strings(src: str) -> str:
    """Blank out comments and string literal contents, preserving length and newlines."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if src[k] != "\n":
                    out[k] = " "
            i = j
        elif src[i] in "\"'":
            quote = src[i]
            j = i + 1
            while j < n and src[j] != quote and src[j] != "\n":
                if src[j] == "\\":
                    j += 1
                j += 1
            for k in range(i + 1, min(j, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def match_close(text: str, open_idx: int, open_ch: str = "{", close_ch: str = "}") -> int:
    depth = 0
    for j in range(open_idx, len(text)):
        c = text[j]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return len(text) - 1


def split_top_level(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur = [], 0, []
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


@dataclass
class Param:
    type: str
    name: str
    is_storage: bool = False  # declared with the `storage` data location (reference, not ABI-serializable)


@dataclass
class Function:
    kind: str  # function | constructor | receive | fallback | modifier
    name: str
    contract: "Contract"
    params: list[Param]
    visibility: str | None
    mutability: str | None
    modifiers: list[str]
    body: str | None
    body_offset: int
    offset: int

    @property
    def is_entrypoint(self) -> bool:
        """Externally callable, state-changing code with a body."""
        return (
            self.kind in ("function", "receive", "fallback")
            and self.visibility in (None, "public", "external")
            and self.body is not None
            and self.contract.kind != "interface"
        )

    @property
    def is_mutating(self) -> bool:
        return self.mutability not in ("view", "pure", "constant")

    @property
    def param_names(self) -> set[str]:
        return {p.name for p in self.params if p.name}

    def params_of_type(self, prefix: str) -> set[str]:
        return {p.name for p in self.params if p.name and p.type.startswith(prefix)}


@dataclass
class Contract:
    kind: str  # contract | library | interface
    abstract: bool
    name: str
    file: "SourceFile"
    offset: int
    text: str  # full source text of the contract (cleaned)
    inherits: list[str]
    functions: list[Function] = field(default_factory=list)
    modifiers: list[Function] = field(default_factory=list)
    state_vars: set[str] = field(default_factory=set)

    def function(self, name: str) -> Function | None:
        return next((f for f in self.functions if f.name == name), None)


@dataclass
class SourceFile:
    path: Path
    display: str
    raw: str
    clean: str
    pragma: str | None
    contracts: list[Contract] = field(default_factory=list)
    _newlines: list[int] = field(default_factory=list, repr=False)

    def line_of(self, offset: int) -> int:
        return bisect.bisect_left(self._newlines, offset) + 1

    def line_text(self, line: int) -> str:
        lines = self.raw.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    @property
    def is_pre_08(self) -> bool:
        """True when every version the pragma mentions is < 0.8 (no built-in overflow checks)."""
        if not self.pragma:
            return False
        versions = re.findall(r"(\d+)\.(\d+)", self.pragma)
        return bool(versions) and all(int(a) == 0 and int(b) < 8 for a, b in versions)


def _parse_params(text: str) -> list[Param]:
    params = []
    for part in split_top_level(text):
        toks = part.split()
        if not toks:
            continue
        name = toks[-1] if len(toks) >= 2 and toks[-1] not in PARAM_NOISE else ""
        params.append(Param(type=toks[0], name=name, is_storage="storage" in toks))
    return params


def _parse_header_tail(tail: str) -> tuple[str | None, str | None, list[str]]:
    visibility = mutability = None
    modifiers: list[str] = []
    i, n = 0, len(tail)
    tok_re = re.compile(r"[A-Za-z_][\w.]*")
    while i < n:
        m = tok_re.search(tail, i)
        if not m:
            break
        word = m.group(0)
        j = m.end()
        while j < n and tail[j].isspace():
            j += 1
        has_args = j < n and tail[j] == "("
        if has_args:
            j = match_close(tail, j, "(", ")") + 1
        if word in VISIBILITIES:
            visibility = word
        elif word in MUTABILITIES:
            mutability = word
        elif word not in NON_MODIFIER_WORDS:
            modifiers.append(word)
        i = j
    return visibility, mutability, modifiers


def _state_vars(contract_level: str) -> set[str]:
    names = set()
    for stmt in contract_level.split(";"):
        s = " ".join(stmt.split())
        if not s:
            continue
        first = s.split()[0].split("(")[0]
        if first in STATEMENT_SKIP:
            continue
        lhs = re.split(r"=(?!>)", s, maxsplit=1)[0]
        if re.search(r"\bconstant\b", lhs):
            continue
        idents = re.findall(r"[A-Za-z_]\w*", lhs)
        if len(idents) >= 2:
            names.add(idents[-1])
    return names


def parse_source(path: Path, display: str | None = None, raw: str | None = None) -> SourceFile:
    if raw is None:
        raw = path.read_text(encoding="utf-8", errors="replace")
    clean = strip_comments_and_strings(raw)
    pragma = PRAGMA_RE.search(clean)
    sf = SourceFile(
        path=path,
        display=display or str(path),
        raw=raw,
        clean=clean,
        pragma=pragma.group(1).strip() if pragma else None,
        _newlines=[i for i, c in enumerate(raw) if c == "\n"],
    )

    pos = 0
    while True:
        m = CONTRACT_RE.search(clean, pos)
        if not m:
            break
        open_i = m.end() - 1
        close_i = match_close(clean, open_i)
        heritage = m.group(4).strip()
        inherits: list[str] = []
        if heritage.startswith("is"):
            heritage = re.sub(r"\([^)]*\)", "", heritage[2:])
            inherits = [h.strip() for h in heritage.split(",") if h.strip()]
        contract = Contract(
            kind=m.group(2),
            abstract=bool(m.group(1)),
            name=m.group(3),
            file=sf,
            offset=m.start(),
            text=clean[m.start(): close_i + 1],
            inherits=inherits,
        )

        level = list(clean[open_i + 1: close_i])
        base = open_i + 1
        p = open_i + 1
        while True:
            mm = MEMBER_RE.search(clean, p, close_i)
            if not mm:
                break
            if mm.group(1):
                kind, name = "function", mm.group(1)
                if name == contract.name:  # pre-0.4.22 constructor
                    kind = "constructor"
            elif mm.group(2):
                kind, name = "constructor", "constructor"
            elif mm.group(3):
                kind, name = "receive", "receive"
            elif mm.group(4):
                kind, name = "fallback", "fallback"
            else:
                kind, name = "modifier", mm.group(5)

            if mm.group(6):                              # has a parameter list "("
                paren_open = mm.end() - 1
                paren_close = match_close(clean, paren_open, "(", ")")
                params_src = clean[paren_open + 1: paren_close]
                after = paren_close + 1
            elif kind == "modifier":                     # parenthesis-less modifier: `modifier byDFO { ... }`
                paren_close = after = mm.end()
                params_src = ""
            else:                                        # a function-like member must have "(" - skip a stray match
                p = mm.end()
                continue
            j, depth = after, 0
            while j < close_i:
                c = clean[j]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif c in "{;" and depth == 0:
                    break
                j += 1
            tail = clean[after: j]
            visibility, mutability, mods = _parse_header_tail(tail)
            if j < close_i and clean[j] == "{":
                body_close = match_close(clean, j)
                body, body_offset, end = clean[j + 1: body_close], j + 1, body_close + 1
            else:
                body, body_offset, end = None, j, j + 1

            fn = Function(
                kind=kind, name=name, contract=contract,
                params=_parse_params(params_src),
                visibility=visibility, mutability=mutability, modifiers=mods,
                body=body, body_offset=body_offset, offset=mm.start(),
            )
            (contract.modifiers if kind == "modifier" else contract.functions).append(fn)

            for k in range(mm.start() - base, min(end, close_i) - base):
                level[k] = " "
            level[min(end, close_i) - base - 1] = ";"
            p = end

        lvl = "".join(level)
        # blank struct/enum bodies, terminating each with ';'
        while True:
            nested = re.search(r"\{[^{}]*\}", lvl)
            if not nested:
                break
            a, b = nested.span()
            lvl = lvl[:a] + " " * (b - a - 1) + ";" + lvl[b:]
        contract.state_vars = _state_vars(lvl)
        sf.contracts.append(contract)
        pos = close_i + 1
    return sf
