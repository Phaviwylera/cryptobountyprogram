"""Heuristic detectors for fund-loss bug classes in DeFi contracts.

Every detector is a *candidate generator*: it points a human at code worth
reading. Nothing here proves exploitability. A finding only becomes a bounty
report after it has been confirmed with a Foundry PoC on a local fork
(see templates/poc and docs/DISCLOSURE.md).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Iterator

from .solidity import Function, SourceFile, match_close, split_top_level

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    detector: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    contract: str
    function: str
    description: str
    impact: str
    recommendation: str
    snippet: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Hit:
    fn: Function
    offset: int  # offset relative to fn.body (or absolute if absolute=True)
    description: str
    severity: str | None = None
    confidence: str = "medium"
    absolute: bool = False


@dataclass
class Project:
    files: list[SourceFile]
    auth_modifiers: set[str]
    state_vars: set[str]
    meta: dict = field(default_factory=dict)  # deployed-contract metadata (proxy flag, impl address, ...)

    def functions(self) -> Iterator[Function]:
        for f in self.files:
            for c in f.contracts:
                yield from c.functions

    def callables_by_name(self) -> dict[str, list[Function]]:
        if not hasattr(self, "_by_name"):
            m: dict[str, list[Function]] = {}
            for fn in self.functions():
                m.setdefault(fn.name, []).append(fn)
            # library functions live as contract.functions too; include them
            self._by_name = m
        return self._by_name

    def resolve_call(self, name: str) -> Function | None:
        """Best-effort resolve an internal/library function body by name (last definition wins)."""
        got = self.callables_by_name().get(name)
        return got[-1] if got else None


CALL_IN_BODY_RE = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\(")
# `Lib.func(` library-style call
LIB_CALL_RE = re.compile(r"(?<![.\w])[A-Z]\w*\s*\.\s*([A-Za-z_]\w*)\s*\(")


_INLINE_SKIP = {"require", "assert", "revert", "if", "for", "while", "return", "emit", "keccak256",
                "abi", "address", "payable", "uint256", "uint", "int256", "bytes", "bool", "new",
                "sha256", "ecrecover", "type", "this", "super"}

# Proxy shells whose stub functions intentionally have no local access control at the proxy
# level; auth lives behind the delegatecall into the implementation, which is analysed as its
# own contract (see MErc20Delegator / CTokenDelegator admin methods, OpenSea OwnableDelegateProxy,
# ERC1967Proxy admin selectors). Flagging those stubs floods the dashboard with proxies.
_PROXY_SHELL_NAMES = {
    "MErc20Delegator", "CErc20Delegator", "MToken", "CEther", "CToken",
    "DAIPoolDelegator", "USDTPoolDelegator", "LPoolDelegator",
    "OwnableDelegateProxy", "AccessManagedProxy", "ERC1967Proxy",
    "TransparentUpgradeableProxy", "BeaconProxy", "PinnedBeaconProxy", "NullmaskProxy",
    "OptinProxy", "StrategyProxy", "FortuneFiProxy", "RollupProxy",
    "InitializableAdminUpgradeabilityProxy", "XaurumProxyERC20",
}


def effective_body(fn: Function, project: Project, depth: int = 1, _seen: frozenset = frozenset()) -> str:
    """fn.body with one level of internal/library calls SUBSTITUTED AT THE CALL SITE, so a regex
    detector sees a call or state-write a helper performs, in the right textual order
    (V03/V04/V14/V15 shapes). Substituting (not appending) preserves before/after-call ordering."""
    body = fn.body or ""
    if depth <= 0 or fn.name in _seen:
        return body
    seen = _seen | {fn.name}

    type_names = {c.name for f in project.files for c in f.contracts if c.kind in ("library", "interface", "contract")}

    def inline(name: str, start: int, args_text: str) -> str | None:
        """Callee body with parameters bound to this call's arguments, or None to leave the call as is."""
        if name in _INLINE_SKIP:
            return None
        callee = project.resolve_call(name)
        dotted = start > 0 and body[start - 1] == "."
        receiver = expression_before(body, start - 1) if dotted else ""
        self_call = receiver == "this"
        allowed = ("internal", "private", "public", None) + (("external",) if self_call else ())
        if not (callee and callee is not fn and callee.body and callee.visibility in allowed):
            return None
        # `X.f(...)` on anything but `this` is either a library call (using-for / Lib.f) or a call into
        # ANOTHER contract. We only know the code of the former: never paste a same-named function from
        # some other contract in the bundle (LOCKS.claim() is not this bundle's claim()).
        if dotted and not self_call and callee.contract.kind != "library":
            return None
        inner = effective_body(callee, project, depth - 1, seen)
        # Bind the callee's parameter names to the call's actual arguments so a forwarded
        # `data`/`target` reads as the caller's `routerData`/`strategy` (V14/V17 shapes).
        raw_args = split_top_level(args_text)
        # `x.f(a)` via `using X for ...` passes the receiver as the first param; a static library
        # call `Lib.f(a,b)` does not (Lib is a type name), and neither does a `this.f(a)` self-call.
        if dotted and receiver and root_identifier(receiver) not in type_names and not self_call:
            raw_args = [receiver] + raw_args
        for p, a in zip(callee.params, raw_args):
            if p.name and a:
                inner = re.sub(rf"(?<![.\w]){re.escape(p.name)}\b", lambda _m, a=a: a, inner)
        return " { " + inner + " } "

    # Walk the body with real parenthesis matching. A call that is not inlined (a keyword such as
    # `if`/`require`, or an external call) is kept, but we keep scanning INSIDE its parentheses so
    # `if (!_tryRelease(to, amount))` still inlines `_tryRelease`.
    call_start = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*\(")
    out, i = [], 0
    while True:
        m = call_start.search(body, i)
        if not m:
            out.append(body[i:])
            break
        open_idx = m.end() - 1
        close_idx = match_close(body, open_idx, "(", ")")
        out.append(body[i:m.start()])
        replacement = inline(m.group(1), m.start(), body[open_idx + 1:close_idx])
        if replacement is None:
            out.append(body[m.start():open_idx + 1])
            i = open_idx + 1
        else:
            out.append(replacement)
            i = close_idx + 1
    return "".join(out)


@dataclass
class Detector:
    id: str
    title: str
    severity: str
    impact: str
    recommendation: str
    references: list[str]
    run: Callable[[Project], Iterable[Hit]]


DETECTORS: list[Detector] = []


def detector(id: str, title: str, severity: str, impact: str, recommendation: str, references: Iterable[str] = ()):
    def wrap(fn: Callable[[Project], Iterable[Hit]]):
        DETECTORS.append(Detector(id, title, severity, impact, recommendation, list(references), fn))
        return fn
    return wrap


# --------------------------------------------------------------------------- helpers

SENDER = r"(?:msg\.sender|_msgSender\(\))"
AUTH_MODIFIER_RE = re.compile(
    r"only|auth|admin|owner|role|gov|restricted|guardian|keeper|operator|whitelist|allowlist|permission|requires"
    r"|checkAccess|hasAccess|accessControl",   # `modifier checkAccess(UPGRADER_ROLE)` (Privacy Pools PoolVault)
    re.I,
)
AUTH_BODY_RE = re.compile(
    r"_check(?:Owner|Role|Auth|Admin|Caller|Sender|Permission|Canonical)\w*\s*\(|hasRole\s*\(|_?only\w*\s*\(|_authorize\w*|_?isAuthorized|requiresAuth"
    r"|_require\w*(?:Owner|Admin|Role|Auth)\w*\s*\("
    rf"|require\s*\([^;]*{SENDER}|if\s*\([^;{{]*{SENDER}[^;{{]*\)\s*(?:revert|throw|\{{\s*(?:revert|throw))"
    # positive inline guard wrapping a privileged write: `if (msg.sender == owner) { ... }`, and the
    # AND-compound form `if (msg.sender == initializer && state == 0) { ... }` (narrowing conditions only).
    rf"|^\s*if\s*\(\s*{SENDER}\s*==\s*[\w.()]+\s*(?:\)|&&)|^\s*if\s*\(\s*[\w.()]+\s*==\s*{SENDER}\s*(?:\)|&&)"
    rf"|\b_?(?:require|check|only|ensure|validate|assert|verify|auth)\w+\s*\(\s*{SENDER}"   # named helper, not bare require(
    # External/contract authorization PREDICATE in a guard: `if (controller.isSweeper(msg.sender))`,
    # `require(registry.hasAccess(msg.sender))`, `if (!auth.canCall(msg.sender, ...))` - exchange sweeper
    # wallets and access-controller registries delegate the caller check to another contract.
    rf"|(?:require|if)\s*\(\s*!?\s*[\w.]+\.\s*(?:is|has|can|check|allowed|verify|only)\w*\s*\([^;{{]*{SENDER}"
    , re.M)
# `address caller = _msgSender(); if (caller != authority()) revert ...;`
SENDER_ALIAS_RE = re.compile(rf"\b(\w+)\s*=\s*{SENDER}\s*;")
REENTRANCY_GUARD_RE = re.compile(r"re.?entr|^lock(ed)?$|nonreentrant|noreenter|noentry|^mutex$|^guard(ed)?$|synchronized|globallock", re.I)
# set-once guards: require(_implementation() == address(0)), if (owner != address(0)) revert ...
ONE_TIME_GUARD_RE = re.compile(
    r"require\s*\([^;]*==\s*address\s*\(\s*0\s*\)|if\s*\([^;{]*!=\s*address\s*\(\s*0\s*\)[^;{]*\)\s*(?:revert|\{\s*revert)"
)
SIGNATURE_CHECK_RE =re.compile(r"MerkleProof|\.verify\s*\(|ecrecover\s*\(|\.recover\s*\(|SignatureChecker|isValidSignature")


def _split_top(s: str, sep: str) -> list[str]:
    """Split on top-level occurrences of `sep` (|| or &&), respecting parentheses."""
    out, depth, last, i, L = [], 0, 0, 0, len(sep)
    while i < len(s):
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and s[i:i + L] == sep:
            out.append(s[last:i]); i += L; last = i; continue
        i += 1
    out.append(s[last:])
    return out


def _if_condition(body: str, lparen: int) -> str | None:
    """The balanced condition of an `if (...)` starting at the '(' index `lparen`."""
    depth, i = 0, lparen
    while i < len(body):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return body[lparen + 1:i]
        i += 1
    return None


_EQ_SENDER = re.compile(rf"(?:{SENDER}\s*==|==\s*{SENDER})")


def sender_admission_guard(body: str) -> bool:
    """A leading positive caller check whose admission requires msg.sender to equal a principal -
    INCLUDING the multi-principal OR form `if (msg.sender == owner || msg.sender == dev) { ... }`
    (Xaurum). Sound because EVERY top-level `||` disjunct must carry a `msg.sender ==` comparison, so a
    disjunct that would admit a non-sender path (a timestamp, a public bool) is never mistaken for a guard."""
    head = "\n".join((body or "").split("\n")[:12])      # a leading guard (spec: within the first ~10 lines)
    for m in re.finditer(r"\bif\s*\(", head):
        cond = _if_condition(head, m.end() - 1)
        if cond is None or not _EQ_SENDER.search(cond):
            continue
        if all(_EQ_SENDER.search(d) for d in _split_top(cond, "||")):
            return True
    return False


def access_controlled(fn: Function, project: Project) -> bool:
    """Does the function restrict *who* may call it?"""
    for m in fn.modifiers:
        if m in project.auth_modifiers or AUTH_MODIFIER_RE.search(m):
            return True
    body = fn.body or ""
    if AUTH_BODY_RE.search(body):
        return True
    if sender_admission_guard(body):          # inline `if (msg.sender == owner || msg.sender == dev)`
        return True
    if re.search(rf"\bsuper\.{re.escape(fn.name)}\s*\(", body):
        return True  # override delegating to the (checked) parent implementation
    for alias in SENDER_ALIAS_RE.findall(body):
        if re.search(rf"(?:require|if)\s*\([^;{{]*\b{re.escape(alias)}\b\s*[!=]=", body):
            return True
    # Two-step boolean guard (Solady/Solmate `Auth.setAuthority` / `setOwner`): the authorization
    # decision is computed into a flag that then gates a revert -
    #   bool ok = msg.sender == $.owner || auth.canCall(msg.sender, ...);  if (!ok) revert Unauthorized();
    # Require the RHS to carry msg.sender AND an auth comparison/predicate so a plain success flag
    # (`bool ok = token.transfer(msg.sender, amt); require(ok);`) is NOT mistaken for a caller check.
    for mb in re.finditer(r"\bbool\s+(\w+)\s*=\s*([^;]*);", body):
        var, rhs = mb.group(1), mb.group(2)
        if not re.search(SENDER, rhs) or not re.search(
                r"==|!=|canCall|hasRole|isAuthorized|\bowner|\badmin|authori[sz]ed|requiresAuth", rhs, re.I):
            continue
        if re.search(rf"if\s*\(\s*!\s*{re.escape(var)}\s*\)|require\s*\(\s*{re.escape(var)}\b"
                     rf"|\b{re.escape(var)}\s*==\s*false\b", body):
            return True
    # Auth may live inside an internal/library helper (ReserveManager delegates to
    # `ReserveAccrualLib.setFee` which asserts `msg.sender == s.modules.waterfall`; MEV bots'
    # `uniswapV3SwapCallback` forwards to `_v3Callback` which pins msg.sender to the pool).
    # Inline one level of callees before giving up.
    eff = effective_body(fn, project, depth=1)
    if eff != body and AUTH_BODY_RE.search(eff):
        return True
    return False


def uses_sender(fn: Function) -> bool:
    return bool(fn.body and re.search(SENDER, fn.body))


def statement_bounds(body: str, pos: int) -> tuple[int, int]:
    start = max(body.rfind(";", 0, pos), body.rfind("{", 0, pos), body.rfind("}", 0, pos)) + 1
    end = body.find(";", pos)
    return start, (len(body) if end == -1 else end)


def call_args(body: str, open_paren: int) -> tuple[list[str], int]:
    close = match_close(body, open_paren, "(", ")")
    return split_top_level(body[open_paren + 1: close]), close


def result_is_used(body: str, pos: int) -> bool:
    """Is the value produced by the call at `pos` checked or captured?"""
    start, end = statement_bounds(body, pos)
    prefix = body[start:pos]
    if re.search(r"\b(require|assert|if|return|while)\b", prefix):
        return True
    captured = re.search(r"\(\s*bool\s+(\w+)|\bbool\s+(\w+)\s*=|\b(\w+)\s*=\s*[^=]*$", prefix)
    if captured:
        name = next(g for g in captured.groups() if g)
        return bool(re.search(rf"\b{re.escape(name)}\b", body[end:]))
    return False


def expression_before(body: str, pos: int) -> str:
    """The receiver expression immediately before `.member` at pos."""
    j = pos
    depth = 0
    while j > 0:
        c = body[j - 1]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and not (c.isalnum() or c in "_."):
            break
        j -= 1
    return body[j:pos].strip()


def root_identifier(expr: str) -> str:
    expr = re.sub(r"^(?:payable|address|I[A-Z]\w*|\w+)\s*\(\s*", "", expr) if re.match(r"^\w+\s*\(", expr) else expr
    m = re.match(r"[A-Za-z_]\w*", expr)
    return m.group(0) if m else ""


ROLE_MODIFIER_RE = AUTH_MODIFIER_RE
# msg.sender EQUALITY auth (owner/role), not a balance/amount comparison that merely mentions msg.sender.
ROLE_BODY_RE = re.compile(
    r"_check(?:Owner|Role|Auth|Admin|Caller|Sender|Permission)\w*\s*\(|hasRole\s*\(|_?only\w*\s*\(|_authorize\w*"
    r"|_?isAuthorized|requiresAuth|_require\w*(?:Owner|Admin|Role|Auth)\w*\s*\("
    rf"|require\s*\([^;{{]*{SENDER}\s*==|require\s*\([^;{{]*==\s*{SENDER}\b"
    rf"|if\s*\([^;{{]*{SENDER}\s*[!=]=\s*\w[^;{{]*\)\s*(?:revert|throw|\{{\s*(?:revert|throw))"   # throw: solidity <0.5
    rf"|if\s*\([^;{{]*\b\w[\w.()]*\s*!=\s*{SENDER}[^;{{]*\)\s*(?:revert|throw|\{{\s*(?:revert|throw))"
    # positive guard wrapping the action: `if (msg.sender == owner) selfdestruct(owner);` (legacy style),
    # and the AND-compound form `if (msg.sender == initializer && controller == address(0)) { ... }`.
    rf"|^\s*if\s*\(\s*{SENDER}\s*==\s*[\w.()]+\s*(?:\)|&&)|^\s*if\s*\(\s*[\w.()]+\s*==\s*{SENDER}\s*(?:\)|&&)"
    # a guard helper invoked ON the caller: requireMaster(msg.sender), _checkCaller(msg.sender), onlyX(msg.sender)
    rf"|\b_?(?:require|check|only|ensure|validate|assert|verify|auth)\w+\s*\(\s*{SENDER}"   # named helper, not bare require(
    # external/contract authorization predicate: if (controller.isSweeper(msg.sender)) / require(x.hasRole(.., msg.sender))
    rf"|(?:require|if)\s*\(\s*!?\s*[\w.]+\.\s*(?:is|has|can|check|allowed|verify|only)\w*\s*\([^;{{]*{SENDER}"
    , re.M)


def is_role_controlled(fn: Function, project: Project) -> bool:
    """Restricts WHO may call (owner/role/modifier). Unlike access_controlled, a bare
    require that only *mentions* msg.sender (e.g. a balanceOf(msg.sender) check) does not count."""
    for m in fn.modifiers:
        if m in project.auth_modifiers or ROLE_MODIFIER_RE.search(m):
            return True
    body = fn.body or ""
    if ROLE_BODY_RE.search(body):
        return True
    if re.search(rf"\bsuper\.{re.escape(fn.name)}\s*\(", body):
        return True
    for alias in re.findall(rf"\b(\w+)\s*=\s*{SENDER}\s*;", body):
        if re.search(rf"(?:require|if)\s*\([^;{{]*\b{re.escape(alias)}\b\s*[!=]=", body):
            return True
    # One-level inline for helpers that carry the equality check (library setters, _v3Callback).
    eff = effective_body(fn, project, depth=1)
    if eff != body and ROLE_BODY_RE.search(eff):
        return True
    return False


def calls_guarded_helper(fn: Function, project: Project) -> bool:
    """True when the function calls (in its own body) a helper that checks the caller -
    e.g. ENS `setRecord` -> `setOwner(...)` which carries `authorised(node)`. An unauthorised
    caller reverts inside the helper, so the outer function is protected too."""
    body = fn.body or ""
    for name in set(CALL_IN_BODY_RE.findall(body)):
        if name in _INLINE_SKIP or name == fn.name:
            continue
        callee = project.resolve_call(name)
        if not callee or callee is fn or callee.contract.name not in {fn.contract.name, *fn.contract.inherits} \
                and callee.contract.file is not fn.contract.file:
            continue
        if any(m in project.auth_modifiers or AUTH_MODIFIER_RE.search(m) for m in callee.modifiers):
            return True
        if callee.body and ROLE_BODY_RE.search(callee.body):
            return True
        # guard helpers by name (Manifold `requireExtension()`, `_checkCaller()`, `ensureAdmin()`):
        # a require/if on msg.sender inside a helper whose name says it is a check
        if re.match(r"^_?(?:require|check|only|ensure|validate|assert|verify|auth)\w*$", callee.name, re.I) and \
                callee.body and re.search(rf"(?:require|if)\s*\([^;]*{SENDER}", callee.body):
            return True
        # Boolean auth PREDICATE used in a reverting guard: `if (!_isVaultOwner() && !_isManagerAdmin()) revert`
        # / `require(isOwner())`. The predicate `return`s a msg.sender comparison (directly, or via
        # owner()/manager()/hasRole), and the caller reverts unless it holds (Arrakis UniV4StandardModule).
        if callee.body and re.search(rf"return\b[^;]*(?:{SENDER}|hasRole\s*\(|_checkRole)", callee.body) and \
                re.search(rf"(?:require|if)\s*\([^;{{]*\b{re.escape(name)}\s*\(", body):
            return True
        # calldata timelocks (Morpho Vault V2 `timelocked()`): only calldata a curator submitted, after
        # the delay, can execute - the gate is keyed on msg.data rather than msg.sender
        if callee.body and (re.search(r"timelock", callee.name, re.I)
                            or re.search(r"(?:require|if)\s*\([^;]*msg\.data", callee.body)):
            return True
    return False


def family_text(contract, project: Project) -> str:
    """Source text of a contract, everything it inherits, and everything that inherits from it."""
    by_name = {c.name: c for f in project.files for c in f.contracts}
    fam, todo = set(), [contract.name]
    while todo:                                    # ancestors
        n = todo.pop()
        if n in fam or n not in by_name:
            continue
        fam.add(n)
        todo += [i.split(".")[-1].strip() for i in by_name[n].inherits]
    changed = True
    while changed:                                 # descendants
        changed = False
        for c in by_name.values():
            if c.name not in fam and any(i.split(".")[-1].strip() in fam for i in c.inherits):
                fam.add(c.name)
                changed = True
    return "\n".join(by_name[n].text for n in fam if n in by_name)


def is_immutable(contract, ident: str) -> bool:
    """Is `ident` a state variable declared immutable or constant (a fixed, trusted address)?"""
    if not ident:
        return False
    return bool(re.search(rf"\b(?:immutable|constant)\b[^;]*\b{re.escape(ident)}\b\s*[=;]"
                          rf"|\b{re.escape(ident)}\b[^;]*\b(?:immutable|constant)\b", contract.text))


PAYOUT_RE = re.compile(
    r"payable\s*\(\s*(\w+)\s*\)\s*\.\s*(?:transfer|send|call)\b"     # payable(x).transfer(...)
    r"|(\w+)\s*\.\s*call\s*\{\s*value"                              # x.call{value: ...}
    r"|\.\s*safeTransfer\s*\(\s*(\w+)\s*,"                          # token.safeTransfer(x, amt)
    r"|\.\s*transfer\s*\(\s*(\w+)\s*,"                              # token.transfer(x, amt)
    r"|\.\s*(?:safeT|t)ransferFrom\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(\w+)\s*,"   # token.transferFrom(from, x, amt)
    r"|sendValue\s*\(\s*(?:payable\s*\(\s*)?(\w+)"                  # Address.sendValue(x, amt)
    r"|safeTransferETH\s*\(\s*(\w+)"                                # SafeTransferLib.safeTransferETH(x, amt)
    r"|\bcall\s*\(\s*gas\s*\(\s*\)\s*,\s*(\w+)\s*,"                 # assembly { call(gas(), x, amt, ...) }
)


def payout_recipients(body: str) -> set[str]:
    """Root identifiers that receive value (ETH or tokens) in a body."""
    out = set()
    for m in PAYOUT_RE.finditer(body):
        r = next((g for g in m.groups() if g), None)
        if r and r not in ("this", "address"):
            out.add(r)
    return out


def target_whitelisted(fn, target: str) -> bool:
    """Is the call target parameter gated by a membership/allow-list require in the body?"""
    body = fn.body or ""
    return bool(re.search(
        rf"require\s*\(\s*\w*(?:[Aa]pproved|[Ww]hitelist|[Aa]llow\w*|isValid|trusted)\w*\s*\[\s*{re.escape(target)}\s*\]"
        rf"|require\s*\(\s*\w+\s*\[\s*{re.escape(target)}\s*\]"
        rf"|if\s*\(\s*!\s*\w+\s*\[\s*{re.escape(target)}\s*\]\s*\)", body))


def entrypoints(project: Project, mutating: bool = True) -> Iterator[Function]:
    for fn in project.functions():
        if not (fn.is_entrypoint and (fn.is_mutating or not mutating)):
            continue
        # A `public`/`external` LIBRARY function that takes a `storage` reference parameter cannot be
        # called across the ABI boundary (storage pointers do not serialize). It is internal plumbing a
        # guarded wrapper calls (e.g. `AccessableLib.setExternalSanctionsList(storage $, ...)` behind
        # `Vault.setExternalSanctionsList() external onlyWhitelistManager`). Flagging it as an unprotected
        # entrypoint is a false positive — the caller check lives on the wrapper.
        if fn.contract.kind == "library" and any(p.is_storage for p in fn.params):
            continue
        yield fn


# --------------------------------------------------------------------------- access control

PRIVILEGED_NAME_RE = re.compile(
    r"^_?(?:set[A-Z_]\w*|upgrade\w*|transferOwnership|changeOwner|changeAdmin|setAdmin|renounce\w*|"
    r"sweep\w*|rescue\w*|recover\w*|emergency\w*|drain\w*|withdraw(?:All|Fees?|Tokens?|ETH|Eth|Funds|Treasury|Reserves?|Stuck\w*|Protocol\w*)|"
    r"pause|unpause|kill|destroy|shutdown|migrate\w*|grant\w*|addMinter|add(?:Admin|Operator|Keeper)|update(?:Price|Oracle|Rate)\w*|configure\w*)$"
)
REPLAY_GUARD_RE = re.compile(
    r"\w*nonce\w*\s*(?:\[[^\]]*\]\s*)*(?:\+\+|\+=|\|=|=\s*\w*nonce\w*\s*(?:\[[^\]]*\]\s*)*\+)"   # nonce++ / nonces[a]++ / bitmap |=
    r"|\+\+\s*\w*nonce\w*"                                                                      # ++nonce
    r"|_use\w*Nonce\s*\(|incrementNonce|invalidateNonce|_invalidate\w*"                       # OZ Nonces, Permit2
    # mapping-flag replay guards: used[h]=true, pending[h].to != address(0), isPaid[h]=true
    # (EtherDelta orderFills, EdgexBridge pendingWithdrawals, Invoice isPaid).
    r"|\b\w*(?:used|executed|claimed|consumed|processed|redeemed|fill(?:ed|s)?|spent|cancelled|seen|paid|pending)\w*"
    r"\s*(?:\[[^\]]*\]\s*)+(?:=\s*(?!0\b|false\b|address\s*\(\s*0)|\.\w+\s*!=\s*address\s*\(\s*0\s*\))"
    # struct-field one-shot flag CONSUMED: `orders[orderId].executed = true` (BitGo-style MultiSigPool
    # _recordOrder marks the order id used, so the second submission of the same order reverts).
    r"|\.\s*(?:executed|used|claimed|processed|redeemed|filled|settled|consumed|cancelled|finalized|completed)\b"
    r"\s*=\s*true\b"
    r"|sequence|replay|invalidat"
    # monotonic state-channel nonce: `if (nonce <= stored) revert` / `require(newNonce > old)` - a higher
    # nonce overrides, so an old-nonce signed state cannot be replayed (Lithium, Perun/Raiden channels).
    # The nonce is a struct field, not a mapping, so the ++/[..] forms above miss it.
    r"|\w*nonce\w*\s*(?:<=?|>=?)\s*[\w.(]|[\w.)]\s*(?:<=?|>=?)\s*\w*\.?\w*nonce\w*"
    r"|Invalid\w*Nonce|Nonce\w*(?:TooLow|TooOld|Invalid|Used|Replay|Stale|Mismatch|Reused)|StaleNonce|OldNonce"
    r"|\bage\s*<=|Stale\w*|\b(?:last|latest|current)\w*(?:Timestamp|Age|Round|Epoch)\w*\s*>=", re.I)  # monotonic (Chronicle)
PRICE_SOURCE_RE = re.compile(
    r"latestRoundData|latestAnswer|getExpiryPrice|getPrice\w*\s*\(|getUnderlyingPrice|updatePriceFeeds|"
    r"parsePriceFeedUpdates|getUpdateFee|get_virtual_price|getRate\s*\(|pricePerShare|exchangeRate\w*\s*\(|"
    r"consult\s*\(|observe\s*\(")
CRITICAL_PRIVILEGED_RE = re.compile(r"upgrade|owner|admin|sweep|rescue|recover|emergency|drain|withdraw|oracle|price|grant|minter|migrate|kill|destroy", re.I)
USER_SCOPED_SETTERS = {"setApprovalForAll", "setApproval", "setDelegate", "setOperator", "setUserPreferences"}


@detector(
    "unprotected-privileged-function",
    "Privileged function callable by anyone",
    "high",
    "Any account can call an administrative function (upgrade, ownership, oracle/price, fee, sweep/rescue, pause). "
    "Typical outcomes: implementation swap to a malicious contract, oracle set to an attacker value, or treasury drained.",
    "Restrict with onlyOwner / AccessControl roles (or a timelocked governor) and add a regression test that a non-admin call reverts.",
    ["https://swcregistry.io/docs/SWC-105", "https://rekt.news/poly-network-rekt/"],
)
def _privileged(project: Project):
    for fn in entrypoints(project):
        if not PRIVILEGED_NAME_RE.match(fn.name) or fn.name in USER_SCOPED_SETTERS:
            continue
        if fn.name.startswith("initialize") or access_controlled(fn, project) or calls_guarded_helper(fn, project):
            continue
        # Authorised by signature instead of msg.sender (meta-tx, relayer rescue, vouchers): still gated.
        # Whether that signature can be replayed is the signature-replay detector's job.
        if re.search(r"_check\w*Signature\w*\s*\(|_verify\w*Sig\w*\s*\(|SignatureChecker|isValidSignatureNow|"
                     r"ECDSA\s*\.\s*recover|\becrecover\s*\(|MerkleProof\s*\.\s*verify", fn.body or ""):
            continue
        # Metadata setters (token URI, name, symbol, description) cannot move funds.
        if re.search(r"URI|Uri|Metadata|Description|Image|Symbol|Name(?!d)|Banner|Logo", fn.name):
            continue
        # renounceX() acting on the caller only gives up the caller's own role.
        if fn.name.lower().startswith("renounce") and uses_sender(fn):
            continue
        # Keeper / upkeep: no value the caller can choose (no named params) and the caller's identity
        # is unused - e.g. Chainlink Automation `performUpkeep`-style functions gated by checkUpkeep().
        if (not [p for p in fn.params if p.name] and not uses_sender(fn)) or re.search(r"\bcheckUpkeep\s*\(", fn.body or ""):
            continue
        # Delegate-forwarding wallets (exchange deposit wallets: `sweeperOf(t).delegatecall(msg.data)`): the
        # logic - and its caller check - lives in the registered delegate, which is analysed on its own.
        fwd = re.search(r"([\w.()\[\]]+)\s*\.\s*delegatecall\s*\(\s*msg\.data\s*\)", fn.body or "")
        if fwd and root_identifier(fwd.group(1)) not in fn.param_names:
            continue
        # CToken-style delegator stubs: a function body that is literally
        # `delegateToImplementation(abi.encodeWithSignature(...))` or `return abi.decode(delegateTo...)`.
        # The impl behind the delegatecall carries the admin check (`require(msg.sender == admin)`);
        # the stub itself is unguarded BY DESIGN. Same for OwnableDelegateProxy / AccessManagedProxy.
        if re.search(r"\bdelegate(?:To(?:Implementation|And\w+)?|cast)\s*\(\s*abi\.encode(?:WithSelector|WithSignature|Call)?\s*\(",
                     fn.body or ""):
            continue
        # Known proxy contract names where the proxy itself intentionally has no access control at
        # the proxy level; access lives behind the delegatecall (OpenZeppelin, OpenSea, Compound).
        if fn.contract.name in _PROXY_SHELL_NAMES:
            continue
        body = fn.body or ""
        if re.search(rf"\[\s*{SENDER}\s*\]", body):
            continue  # user-scoped state, e.g. prefs[msg.sender]
        # ... also through an alias: `address caller = msg.sender; _keyOf[caller] = ...`
        if any(re.search(rf"\[\s*{re.escape(a)}\s*\]", body) for a in SENDER_ALIAS_RE.findall(body)):
            continue
        # A user action that charges the caller (migrate / deposit own tokens) is not an admin function.
        aliases = "|".join([SENDER] + [re.escape(a) for a in SENDER_ALIAS_RE.findall(body)])
        if re.search(rf"[Tt]ransferFrom\s*\(\s*(?:{aliases})\s*,", body):
            continue
        if not body.strip():
            continue
        # Permissionless sweep/rescue/collect/skim that only moves funds to a FIXED immutable/constant
        # address cannot redirect funds: anyone can trigger it, but the money goes to its owner.
        # Look through internal helpers (`_sendSurplus(refundAddress)`); an address parameter is fine
        # (e.g. which token to rescue) as long as it is never the recipient.
        # Applies to any fund-moving name (withdrawFees, claim..., distribute...): what matters is WHERE the
        # money goes. A protocol-designated recipient (immutable, constant, or a storage variable whose
        # setter is checked separately) is fine; a caller-chosen one (param / msg.sender) is not.
        if re.match(r"^_?(?:sweep|collect|skim|harvest|rescue|recover|withdraw|claim|distribute|payout|release|flush)\w*$",
                    fn.name, re.I):
            recipients = payout_recipients(effective_body(fn, project, depth=3))
            fixed = lambda r: is_immutable(fn.contract, r) or (r in project.state_vars and r not in fn.param_names)
            if recipients and all(fixed(r) for r in recipients) and not (recipients & fn.params_of_type("address")) \
                    and not re.search(rf"{SENDER}", " ".join(recipients)):
                continue
            # Keeper poke (Uniswap v4 hook `sweep()` settling claims): pays nobody it can be told about -
            # no recipient at all, no address argument, and the caller's identity is never used.
            if not recipients and not fn.params_of_type("address") and not re.search(SENDER, fn.body or ""):
                continue
            # General rule: flag only when the CALLER can steer where money goes - a payout to an address
            # parameter that is not allowlisted, or to the caller. Allowlisted executors
            # (`allowedHotswapExecutor[executor]`) and token-identity params (asset/token) are not recipients.
            eff3 = effective_body(fn, project, depth=3)
            addr = fn.params_of_type("address")
            allow = {p for p in addr if re.search(
                rf"\w*(?:allow|approv|whitelist|trusted|valid|registered|enabled|supported|isExecutor)\w*\s*\[\s*{re.escape(p)}\s*\]",
                eff3, re.I)}
            tokenish = {p for p in addr if re.search(r"token|asset|currency|collateral|underlying|erc20|pool|vault|market", p, re.I)}
            steerable = (addr - allow) & (recipients | ({p for p in addr} if not recipients else set())) - tokenish
            to_caller = bool(recipients & {"msg", "_msgSender", *SENDER_ALIAS_RE.findall(eff3)})
            if not steerable and not to_caller:
                continue
        # Permissionless "oracle poke" (Opyn setExpiryPriceInOracle, Pyth updatePrice): anyone may call it,
        # but the price is READ from a trusted source (feed / signed update), never supplied by the caller.
        # Only a numeric caller-supplied value (other than a timestamp / id) could set a price.
        if re.search(r"price|oracle|rate|expiry", fn.name, re.I):
            numeric = [p for p in fn.params if re.match(r"u?int", p.type)
                       and not re.search(r"time|expiry|epoch|round|id$|index|deadline", p.name, re.I)]
            if not numeric and PRICE_SOURCE_RE.search(effective_body(fn, project, depth=2)):
                continue
        sev = "critical" if CRITICAL_PRIVILEGED_RE.search(fn.name) else "high"
        yield Hit(fn, fn.offset, f"`{fn.name}` is {fn.visibility or 'public'} with no access control "
                  f"(modifiers: {', '.join(fn.modifiers) or 'none'}).", severity=sev, absolute=True)


@detector(
    "unrestricted-mint",
    "Anyone can mint tokens/shares without paying",
    "critical",
    "Unlimited minting dilutes every holder to zero and lets the attacker redeem or dump the minted supply against pools - direct theft.",
    "Gate minting behind a minter role, or mint only in exchange for verified incoming assets.",
    ["https://rekt.news/cover-rekt/"],
)
def _mint(project: Project):
    for fn in entrypoints(project):
        if not fn.name.lower().startswith("mint") or access_controlled(fn, project):
            continue
        body = fn.body or ""
        m = re.search(r"\b_mint\s*\(|\b(?:_balances|balanceOf|balances)\s*\[[^\]]+\]\s*\+=", body)
        if not m:
            continue
        # Access control often lives in an OVERRIDDEN internal mint the public wrapper delegates to:
        # `function mint(a, n) public canMint { _mint(a, n); }` with a derived
        # `function _mint(a, n) internal override onlyMinter { super._mint(a, n); }`. The modifier is not
        # in the wrapper's body, so resolve every definition of the internal mint helper this function
        # calls and treat the path as guarded if any carries a caller check (PowerfulERC20 / erc20-generator).
        called_mint = set(re.findall(r"\b(_mint\w*)\s*\(", body))
        if any(access_controlled(d, project)
               for nm in called_mint for d in project.callables_by_name().get(nm, []) if d is not fn):
            continue
        eff = effective_body(fn, project, depth=2)
        if re.search(r"msg\.value|transferFrom\s*\(|safeTransferFrom\s*\(|_burn\s*\(|\bburn\w*\s*\(|SIGNATURE|MerkleProof|ecrecover|\.recover\s*\("
                     r"|_deposit\s*\(|_pull\w*\s*\(|claimable|pending\w*\[", eff):
            continue
        # A mint helper charged to the caller (ERC-7540 `_mint(shares, receiver, msg.sender)` claims the
        # caller's own pending deposit) is accounting, not free minting.
        if re.search(rf"\b_mint\s*\([^;]*{SENDER}", body):
            continue
        if not fn.params_of_type("uint"):
            continue  # e.g. AMM LP mint(address to) that prices from balances
        yield Hit(fn, m.start(), f"`{fn.name}` mints without access control or an incoming payment.")


@detector(
    "unrestricted-burn-from",
    "Anyone can burn another account's tokens",
    "critical",
    "An attacker burns victims' balances (or pool reserves) - destroying funds or skewing AMM reserves to steal from the pool.",
    "Burn only from msg.sender, or spend an allowance (_spendAllowance) before burning from a third party.",
)
def _burn_from(project: Project):
    for fn in entrypoints(project):
        if not fn.name.lower().startswith("burn") or access_controlled(fn, project):
            continue
        body = fn.body or ""
        eff = effective_body(fn, project, depth=2)    # `_spend(from, value)` hides the allowance check
        for m in re.finditer(r"\b_burn\s*\(\s*(\w+)", body):
            if m.group(1) in fn.params_of_type("address") and not re.search(
                r"allowance|_spendAllowance|_spend\w*\s*\(|_approve|isApprovedForAll|_isApprovedOrOwner|getApproved", eff
            ):
                yield Hit(fn, m.start(), f"`_burn({m.group(1)}, ...)` burns from a caller-chosen address with no allowance check.")


@detector(
    "arbitrary-recipient-withdrawal",
    "Withdrawal pays a caller-chosen address without checking the caller",
    "critical",
    "Anyone can call the withdraw/claim path and route the protocol's or other users' funds to themselves.",
    "Debit the balance of msg.sender (or check allowance / signature / merkle proof for the owner) before paying out.",
)
def _arbitrary_withdraw(project: Project):
    pay_re = re.compile(
        r"(\w+)\.call\s*\{\s*value|payable\s*\(\s*(\w+)\s*\)\s*\.(?:transfer|send|call)|"
        r"\.safeTransfer\s*\(\s*(\w+)\s*,|\.transfer\s*\(\s*(\w+)\s*,|safeTransferETH\s*\(\s*(\w+)|sendValue\s*\(\s*payable\s*\(\s*(\w+)"
    )
    for fn in entrypoints(project):
        if not re.match(r"^(withdraw|claim|redeem|payout|transferOut|release|unstake)", fn.name, re.I):
            continue
        if PRIVILEGED_NAME_RE.match(fn.name) or access_controlled(fn, project) or uses_sender(fn):
            continue
        body = fn.body or ""
        if SIGNATURE_CHECK_RE.search(body) or re.search(r"allowance|_spendAllowance", body):
            continue
        recipients = fn.params_of_type("address")
        eff = effective_body(fn, project, depth=2)
        # Custodial multi-sig withdrawal: the recipient is bound into a hash verified against the
        # contract's OWN registered signer set (`isAllowedSigner` / `allSigners` / `signers[]`), with an
        # order-id/digest replay guard. Anyone may relay the transaction, but only the custodians'
        # signatures authorize where the money goes (MultiSigPoolV2). A single external-signer scheme
        # that lacks a registered signer set (e.g. an operator-signed voucher) is NOT covered here.
        # Use a SHALLOW inline (depth=1): the verifier helper's body is pasted verbatim, so its
        # `ECDSA.recover(...)` / `isAllowedSigner(...)` tokens survive (a deeper inline rewrites them away).
        sig_scope = effective_body(fn, project, depth=1)
        if SIGNATURE_CHECK_RE.search(sig_scope) and re.search(
                r"isAllowedSigner|allSigners|\bsigners\s*\[|\bsigners\s*\.\s*length|\bisSigner\b", sig_scope):
            continue
        for m in pay_re.finditer(body):
            to = next((g for g in m.groups() if g), "")
            if to not in recipients:
                continue
            # Paying `account` from `account`'s OWN balance (LQDXStaker.unstake(account, ...)): a stranger can
            # force the payout (griefing) but cannot redirect it - the owner is both debited and paid.
            owner_paid = re.search(rf"\[\s*{re.escape(to)}\s*\]", eff) or re.search(
                rf"\b\w*(?:claim|balance|available|stake|deposit|position|account|user|_update|_burn|_debit)\w*\s*\(\s*{re.escape(to)}\s*[,)]",
                eff, re.I)
            if owner_paid:
                continue
            yield Hit(fn, m.start(), f"`{fn.name}` sends funds to parameter `{to}` and never references msg.sender.")
            break


@detector(
    "unprotected-initializer",
    "Initializer can be called by anyone / more than once",
    "critical",
    "An attacker initializes (or re-initializes) the proxy and becomes owner/admin, then upgrades or drains it.",
    "Use OpenZeppelin `initializer`, call it atomically in the proxy deployment, and call `_disableInitializers()` in the implementation constructor.",
    ["https://rekt.news/parity-wallet-hack/", "https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#initializers"],
)
def _initializer(project: Project):
    # A deployed, fund-holding PROXY has necessarily already been initialized: its implementation's
    # `initialize()` was consumed at deploy, and the OZ `initializer` modifier / already-set storage
    # makes any re-call revert (confirmed by mainnet-fork tests on the BeaconProxy/OptinProxy cluster).
    # The flagged `initialize` always lives in the implementation bundle, not the proxy shell, so there
    # is no front-runnable window left to flag. The impl's own missing `_disableInitializers()` is the
    # separate medium `uninitialized-implementation` finding, not a fund-theft one.
    if project.meta.get("proxy"):
        return
    for fn in entrypoints(project):
        if not re.match(r"^(initiali[sz]e\w*|init)$", fn.name):
            continue
        if any(re.search(r"initializ|reinitializ|onlyInitializing", m, re.I) for m in fn.modifiers):
            continue
        body = fn.body or ""
        if re.search(r"initiali[sz]ed|_initializing|inited|require\s*\(\s*!?\s*\w*[Ii]nit", body) or ONE_TIME_GUARD_RE.search(body):
            continue
        # Versioned one-time guard: `require(newMultiplier == 0); newMultiplier = ...` (or `if (x != 0) revert`)
        once = re.search(r"(?:require\s*\(\s*(\w+)\s*==\s*(?:0|false|address\s*\(\s*0\s*\))\s*[,)]"
                         r"|if\s*\(\s*(\w+)\s*!=\s*(?:0|address\s*\(\s*0\s*\))\s*\)\s*revert)", body)
        if once:
            v = once.group(1) or once.group(2)
            if re.search(rf"(?<![.\w]){re.escape(v)}\s*=(?!=)", body[once.end():]):
                continue
        # A real caller check (`require(msg.sender == factory)`, onlyOwner, ...) protects it.
        # `owner = msg.sender` alone does not - that is the classic front-runnable initializer.
        if is_role_controlled(fn, project) or (access_controlled(fn, project) and not uses_sender(fn)):
            continue
        yield Hit(fn, fn.offset, f"`{fn.name}` has no initializer guard; it can be front-run or called again.", absolute=True)


@detector(
    "uninitialized-implementation",
    "Upgradeable implementation does not disable initializers",
    "medium",
    "Anyone can initialize the implementation contract directly and take ownership of it; with UUPS this has historically enabled destroying or hijacking the logic contract.",
    "Add `constructor() { _disableInitializers(); }` to every upgradeable implementation.",
    ["https://forum.openzeppelin.com/t/uupsupgradeable-vulnerability-post-mortem/15680"],
)
def _uninit_impl(project: Project):
    for f in project.files:
        for c in f.contracts:
            if c.kind != "contract" or c.abstract:
                continue
            init = next((fn for fn in c.functions if any(m in ("initializer", "reinitializer") for m in fn.modifiers)), None)
            if not init:
                continue
            ctor = next((fn for fn in c.functions if fn.kind == "constructor"), None)
            if ctor and ctor.body and "_disableInitializers" in ctor.body:
                continue
            yield Hit(init, init.offset, f"`{c.name}` is initializable but its constructor never calls `_disableInitializers()`.", absolute=True)


@detector(
    "tx-origin-auth",
    "Authorization via tx.origin",
    "high",
    "A phishing contract the owner interacts with can act as the owner (e.g. withdraw everything to the attacker).",
    "Use msg.sender for authorization.",
    ["https://swcregistry.io/docs/SWC-115"],
)
def _tx_origin(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        # ERC-4337 paymasters identify the BUNDLER (an operator server, not a person who can be phished)
        # by tx.origin - that is the standard pattern, not phishable owner auth.
        if re.search(r"UserOperation|[Pp]aymaster|[Bb]undler|handleOps", fn.contract.text):
            continue
        # A view/pure function moves no funds and changes no state, so a tx.origin comparison in it is a
        # read-access predicate or EOA helper (Chainlink SimpleReadAccessController.hasAccess returning
        # `_user == tx.origin`, anti-bot `_isOrigin`), never a phishable fund-moving authorization. Any
        # real risk lives in the state-changing CONSUMER, which is analysed on its own.
        if not fn.is_mutating:
            continue
        for m in re.finditer(r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin", body):
            s, e = statement_bounds(body, m.start())
            if re.search(rf"tx\.origin\s*[!=]=\s*{SENDER}|{SENDER}\s*[!=]=\s*tx\.origin", body[s:e]):
                continue  # EOA-only check, not authorization
            # `tx.origin == Constants.ESTIMATION_ADDRESS` (Optimism gas-estimation sentinel) / comparison
            # to a SCREAMING_CASE constant is a special-mode branch, not owner authorization.
            if re.search(r"tx\.origin\s*==\s*[\w.]*(?:ESTIMATION|SENTINEL|Constants\.\w+|[A-Z]{2,}_[A-Z]{2,})", body[s:e]):
                continue
            # Chainlink AccessControlledOffchainAggregator pattern:
            # `require(msg.sender == owner || tx.origin == owner)` — a legitimate owner-fallback.
            # If the same statement also compares msg.sender to the same identifier (or to owner()),
            # tx.origin is just a convenience branch, not a phishable auth path on its own.
            if re.search(rf"{SENDER}\s*==\s*\w+[\w.()]*\s*\|\|\s*tx\.origin\s*==|"
                         rf"tx\.origin\s*==\s*\w+[\w.()]*\s*\|\|\s*{SENDER}\s*==", body[s:e]):
                continue
            yield Hit(fn, m.start(), "tx.origin is compared in an authorization check.")


@detector(
    "unprotected-selfdestruct",
    "selfdestruct reachable without access control",
    "critical",
    "Anyone can destroy the contract (pre-Cancun) or force-send its ETH to themselves.",
    "Remove selfdestruct, or restrict it to a timelocked admin.",
    ["https://swcregistry.io/docs/SWC-106"],
)
def _selfdestruct(project: Project):
    for fn in entrypoints(project):
        body = fn.body or ""
        m = re.search(r"\b(?:selfdestruct|suicide)\s*\(([^)]+)\)", body)
        if not m or access_controlled(fn, project):
            continue
        # ENS-Deed pattern: `function destroyDeed() { if (active) throw; ... selfdestruct(burn); }`
        # or Solidity >=0.5 `if (active) revert();` style. A state-flag guard at function entry
        # makes the function effectively unreachable to an attacker while `active == true`, and
        # `active` can only be flipped by a role-controlled function elsewhere. Combined with a
        # FIXED beneficiary (constant/immutable/state var, not a caller param), this is a legitimate
        # teardown path - not a fund-theft vector.
        beneficiary = m.group(1).strip()
        bene_root = root_identifier(beneficiary)
        if bene_root and bene_root not in fn.param_names:
            # beneficiary is not a caller-chosen parameter; check if the function also carries a
            # state-flag guard such as `if (active) throw;` or `if (!closed) revert;`
            state_guard = re.search(
                r"\bif\s*\(\s*!?\s*\w+\s*\)\s*(?:throw\s*;|revert\s*\(|\{\s*(?:throw|revert))",
                body)
            if state_guard:
                continue
        yield Hit(fn, m.start(), f"`{fn.name}` calls selfdestruct without access control.")


# --------------------------------------------------------------------------- external calls

@detector(
    "reentrancy",
    "State updated after an external call (reentrancy)",
    "high",
    "The callee re-enters before balances are updated and withdraws repeatedly - the classic pool/vault drain.",
    "Apply checks-effects-interactions (update state before the call) and add `nonReentrant` to every external entry point that moves value.",
    ["https://swcregistry.io/docs/SWC-107", "https://rekt.news/curve-vyper-rekt/"],
)
def _reentrancy(project: Project):
    call_re = re.compile(
        r"\.call\s*\{|\.call\s*\(|\.call\s*\.\s*value\s*\(|safeTransferETH\s*\(|\.sendValue\s*\("
        r"|\b_safeMint\s*\(|\.onERC721Received\s*\(|\.tokensReceived\s*\("
    )
    for fn in entrypoints(project):
        if any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifiers):
            continue
        # Role-gated entrypoints (OZ TimelockController.execute with EXECUTOR_ROLE) cannot be re-entered by
        # an outsider: the re-entrant call would fail the same role check.
        if is_role_controlled(fn, project):
            continue
        body = fn.body or ""
        # Inline one level so a call (or a state-write) hidden in an internal helper is visible.
        eff = effective_body(fn, project)
        call = call_re.search(eff)
        if not call:
            continue
        orig_call = call_re.search(body)
        in_original = orig_call is not None
        # A call to a fixed immutable/constant address is not attacker-controllable reentry.
        receiver = root_identifier(expression_before(eff, call.start())) if eff[call.start()] == "." else ""
        if receiver and is_immutable(fn.contract, receiver):
            continue
        _, stmt_end = statement_bounds(eff, call.start())
        before, after = eff[:call.start()], eff[stmt_end:]
        # Storage-pointer aliases: `UserInfo storage u = userInfo[msg.sender];` means a later
        # `u.amount -= x` is really a write to the state var `userInfo` (MasterChef / V05 shape).
        alias_vars = set()
        for am in re.finditer(r"\bstorage\s+(\w+)\s*=\s*([A-Za-z_]\w*)\s*\[", eff):
            if am.group(2) in project.state_vars:
                alias_vars.add((am.group(1), am.group(2)))
        writes = []
        for alias, target_var in alias_vars:
            if re.search(rf"(?<![.\w]){re.escape(alias)}\b\s*\.\s*\w+\s*(?:[+\-*/]?=(?!=)|\+\+|--)", after):
                writes.append(target_var)
        for v in project.state_vars:
            w = (re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*?\]\s*)*(?:\.\w+\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", after)
                 or re.search(rf"\bdelete\s+{re.escape(v)}\b", after))
            if not w:
                continue
            # Skip an inline-mutex RELEASE: a scalar lock var set to a bool/sentinel at entry and reset
            # after the call. Must be a genuine lock (bool/0/1/ENTERED), never a balance comparison.
            is_lock = re.search(
                rf"(?<![.\w]){re.escape(v)}\b\s*=\s*(?:true|false|1|0|_?(?:ENTERED|NOT_ENTERED|_TRUE|_FALSE|LOCKED|UNLOCKED))\b",
                before)
            lock_require = re.search(
                rf"require\s*\(\s*!\s*{re.escape(v)}\s*[,)]"
                rf"|require\s*\(\s*{re.escape(v)}\s*(?:==|!=)\s*(?:true|false|0|1|_?\w*(?:ENTERED|LOCKED)\w*)\b", before)
            if is_lock and lock_require:
                continue
            writes.append(v)
        if not writes:
            continue
        is_hook = bool(re.match(r"\b_safeMint|\.onERC721Received|\.tokensReceived|\.safeTransferFrom", call.group(0)))
        # A hook/token-transfer reentrancy that lets a PRE-call require be bypassed (the written var is
        # the one guarded) is a real fund-theft vector - escalate to high (V07/V08 mint- or LTV-limit bypass).
        bypass = is_hook and any(re.search(rf"(?:require|assert)\s*\([^;{{]*\b{re.escape(v)}\b", before) for v in writes)
        native = not is_hook
        sev = "high" if (native or bypass) else "medium"
        note = "" if in_original else f" (via internal helper reached from `{fn.name}`)"
        yield Hit(
            fn, orig_call.start() if in_original else fn.offset,
            f"External call in `{fn.name}` happens before writing state variable(s): {', '.join(sorted(writes))}; no reentrancy guard{note}.",
            severity=sev, confidence="high" if native else "medium", absolute=not in_original,
        )


GOVERNANCE_GATE_RE = re.compile(r"proposal|governance|_validateState|timelock|queued|ProposalState|_executeOperations|onlyGovernance", re.I)


@detector(
    "hook-reentrancy",
    "Token-transfer / mint hook lets a pre-call check be bypassed by reentrancy",
    "high",
    "ERC777/ERC721/ERC1155 transfers and safe-mints invoke a hook on the receiver. Re-entering before the contract updates the balance/limit it just checked bypasses that check - minting past a cap, borrowing past the LTV, or claiming twice (Cream/Amp, imBTC).",
    "Apply checks-effects-interactions (update the checked state BEFORE the transfer) and add a reentrancy guard.",
    ["https://rekt.news/cream-rekt/", "https://consensys.io/diligence/blog/2020/11/..."],
)
def _hook_reentrancy(project: Project):
    hook_call = re.compile(
        r"\.safeTransferFrom\s*\(|\.safeBatchTransferFrom\s*\(|\.safeTransfer\s*\(|\.transfer\s*\(|\b_safeMint\s*\(|\b_mint\s*\(|\.mint\s*\(")
    for fn in entrypoints(project):
        if any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifiers):
            continue
        body = effective_body(fn, project)
        m = hook_call.search(body)
        if not m:
            continue
        # token .transfer(X, ...) to a bare address is only a hook risk for ERC777; require the
        # receiver to be a user (msg.sender or a param), not address(this).
        args, _ = call_args(body, m.end() - 1)
        if m.group(0).strip().startswith(".transfer") and args and "address(this)" in args[0]:
            continue
        _, stmt_end = statement_bounds(body, m.start())
        before, after = body[:m.start()], body[stmt_end:]
        for v in project.state_vars:
            written_after = (re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*?\]\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", after)
                             or re.search(rf"\bdelete\s+{re.escape(v)}\b", after))
            check_re = rf"(?:require|assert|if)\s*\([^;{{]*\b{re.escape(v)}\b"
            checked_before = re.search(check_re, before) or re.search(check_re, fn.body or "")
            if written_after and checked_before:
                yield Hit(fn, fn.offset,
                          f"`{fn.name}` transfers/mints (hook can re-enter) before updating `{v}`, which it checked beforehand - "
                          "the check can be bypassed by re-entering.", absolute=True, confidence="medium")
                break


@detector(
    "arbitrary-external-call",
    "Arbitrary call with caller-controlled target and calldata",
    "critical",
    "The attacker makes the contract call `token.transferFrom(victim, attacker, amount)` on any token users approved to it - draining every approval.",
    "Whitelist call targets and function selectors; never forward arbitrary calldata from an approved spender contract.",
    ["https://rekt.news/li-fi-rekt/", "https://rekt.news/socket-rekt/"],
)
def _arbitrary_call(project: Project):
    for fn in entrypoints(project):
        # Only who-may-call matters here; a balanceOf(msg.sender) sanity check is NOT authorization.
        if is_role_controlled(fn, project):
            continue
        body = fn.body or ""
        eff = effective_body(fn, project)
        # Governance executors forward proposal-approved targets/calldata; they are gated by a vote, not open.
        if GOVERNANCE_GATE_RE.search(eff):
            continue
        # bytes params of this fn, plus bytes fields of any struct/array calldata param (V11 LiFi shape).
        bytes_params = fn.params_of_type("bytes")
        calldata_params = {p.name for p in fn.params if p.name}
        call_pat = r"\.(call|functionCall|functionCallWithValue)\s*(?:\{[^}]*\})?\s*\(|\.call\s*\.\s*value\s*\([^)]*\)\s*\("
        orig_has = re.search(call_pat, body)
        for m in re.finditer(call_pat, eff):
            in_original = orig_has is not None
            target_expr = expression_before(eff, m.start())
            target_root = root_identifier(target_expr)
            args, _ = call_args(eff, m.end() - 1)
            if not args:
                continue
            # Target is caller-controlled if it is a param, or a member/index of a calldata param
            # (e.g. swaps[i].callTo), i.e. its root identifier is one of the function's parameters.
            target_user = target_root in fn.param_names or any(
                re.search(rf"(?<![.\w]){re.escape(p)}\b\s*[\[.]", target_expr) for p in calldata_params)
            # The code fixes WHICH function is called (receiver hooks, `abi.encodeCall(IFoo.bar, ...)`): the
            # caller only supplies arguments, so it is not an arbitrary call (ERC721 onERC721Received).
            if re.match(r"\s*abi\s*\.\s*encode(?:WithSelector|Call|WithSignature)\s*\(\s*(?!bytes4\s*\()", args[0]):
                continue
            # Calldata is caller-controlled if it is a bytes param or a .bytesField of a calldata param.
            data_user = any(re.search(rf"\b{re.escape(b)}\b", args[0]) for b in bytes_params) or \
                re.search(r"\.\s*\w*[Dd]ata\b|\.\s*callData\b|\[\s*\w+\s*\]\s*\.\s*\w+", args[0])
            if target_user and data_user and not target_whitelisted(fn, target_root):
                note = "" if in_original else f" (forwarded through a helper/library from `{fn.name}`)"
                off = orig_has.start() if in_original else fn.offset
                yield Hit(fn, off,
                          f"`{fn.name}` makes a call to a caller-supplied target with caller-supplied calldata{note}.",
                          absolute=not in_original)
                break


@detector(
    "arbitrary-transferfrom",
    "Caller-controlled transferFrom drains token approvals",
    "critical",
    "Anyone can call `token.transferFrom(victim, attacker, amount)` through the contract for any token users approved to it - draining every approval (Transit Swap, SushiSwap RouteProcessor2, Multichain).",
    "Only pull funds from msg.sender (`transferFrom(msg.sender, ...)`), or require a signature/permit from the `from` account.",
    ["https://rekt.news/transit-swap-rekt/", "https://rekt.news/sushi-rekt/"],
)
def _arbitrary_transferfrom(project: Project):
    for fn in entrypoints(project):
        if is_role_controlled(fn, project):
            continue
        body = effective_body(fn, project)
        addr_params = fn.params_of_type("address")
        # transferFrom(FROM, ...) / safeTransferFrom(token, FROM, ...) where FROM is a caller-chosen address
        for m in re.finditer(r"\.(safeTransferFrom|transferFrom)\s*\(", body):
            args, _ = call_args(body, m.end() - 1)
            if len(args) < 2:
                continue
            # Method form `token.(safe)transferFrom(from, to, amount/id)` - `from` is the first arg.
            src = root_identifier(args[0])
            if src in addr_params and not re.search(r"permit|_spendAllowance|allowance|ecrecover|\.recover\s*\(|SignatureChecker|isValidSignature|_useNonce|_isApprovedOrOwner|_isAuthorized|getApproved|ownerOf", body, re.I):
                yield Hit(fn, fn.offset, f"`{fn.name}` calls {m.group(1)} with caller-chosen `from` = `{src}`, so anyone can move a victim's approved tokens.", absolute=True)
                break


@detector(
    "arbitrary-approval",
    "Caller-controlled approval lets an attacker spend the contract's tokens",
    "critical",
    "The contract approves a caller-chosen spender (often for its whole balance or max uint), who then transfers the contract's - or its users' - tokens out.",
    "Never approve a caller-supplied spender; approve only known, immutable routers for exact amounts.",
    ["https://rekt.news/transit-swap-rekt/"],
)
def _arbitrary_approval(project: Project):
    for fn in entrypoints(project):
        if is_role_controlled(fn, project):
            continue
        body = effective_body(fn, project)
        addr_params = fn.params_of_type("address")
        for m in re.finditer(r"\.(approve|safeApprove|forceApprove|safeIncreaseAllowance)\s*\(", body):
            args, _ = call_args(body, m.end() - 1)
            if not args:
                continue
            spender = root_identifier(args[0])
            amount = args[1] if len(args) > 1 else ""
            risky_amount = re.search(r"type\s*\(\s*uint\d*\s*\)\s*\.\s*max|balanceOf|2\s*\*\*\s*256|0xff{6,}", amount)
            if spender in addr_params and risky_amount:
                yield Hit(fn, fn.offset, f"`{fn.name}` approves caller-chosen spender `{spender}` for an unbounded amount.", absolute=True)
                break


@detector(
    "cross-function-reentrancy",
    "State shared with a reentrant external call is mutated by an unguarded function",
    "high",
    "While one function holds an external call open (before it settles state), the attacker re-enters a DIFFERENT unguarded function that reads or writes the same balance/collateral mapping - draining funds even though each function looks safe alone (Fei Rari, Cream, Orion).",
    "Put every function that touches the shared state behind the SAME reentrancy guard, and apply checks-effects-interactions everywhere.",
    ["https://rekt.news/cream-rekt-2/", "https://rekt.news/fei-rari/"],
)
def _cross_function_reentrancy(project: Project):
    call_re = re.compile(r"\.call\s*\{|\.call\s*\(|\.call\s*\.\s*value\s*\(|safeTransferETH\s*\(|\.sendValue\s*\(")
    for f in project.files:
        for c in f.contracts:
            entry = [fn for fn in c.functions if fn.is_entrypoint and fn.is_mutating]
            for fn in entry:
                body = fn.body or ""
                call = call_re.search(body)
                if not call:
                    continue
                receiver = root_identifier(expression_before(body, call.start())) if body[call.start()] == "." else ""
                if receiver and is_immutable(c, receiver):
                    continue
                _, stmt_end = statement_bounds(body, call.start())
                after = body[stmt_end:]
                # state vars this function settles AFTER its external call (the reentrancy-sensitive ones)
                touched = {v for v in project.state_vars
                           if re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*?\]\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", after)}
                if not touched:
                    continue
                value_out = re.compile(r"\.call\s*\{|\.transfer\s*\(|\.send\s*\(|\.safeTransfer\s*\(|payable\s*\(|sendValue\s*\(")
                for other in entry:
                    if other is fn or any(REENTRANCY_GUARD_RE.search(m) for m in other.modifiers):
                        continue
                    ob = other.body or ""
                    # The other function must itself be an extraction path (moves value out); a pure
                    # deposit that only credits a balance cannot drain funds by being re-entered.
                    if not value_out.search(ob):
                        continue
                    shared = {v for v in touched
                              if re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*?\]\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", ob)
                              or re.search(rf"\bdelete\s+{re.escape(v)}\b", ob)
                              or re.search(rf"(?<![.\w]){re.escape(v)}\b\s*\[[^\]]*\]", ob)}
                    if shared:
                        yield Hit(fn, fn.offset,
                                  f"`{fn.name}` makes an external call before settling {', '.join(sorted(shared))}, which the unguarded "
                                  f"`{other.name}` also mutates - reentrancy across the two can bypass the accounting.",
                                  absolute=True, confidence="medium")
                        break


@detector(
    "controlled-delegatecall",
    "delegatecall to a caller-controlled address",
    "critical",
    "The attacker's code runs in this contract's storage context: overwrite owner, upgrade, or transfer out every asset.",
    "Only delegatecall to immutable or admin-set, audited implementations.",
    ["https://swcregistry.io/docs/SWC-112"],
)
def _delegatecall(project: Project):
    for fn in entrypoints(project):
        body = fn.body or ""
        eff = effective_body(fn, project)
        orig_dc = re.search(r"\.delegatecall\s*\(|functionDelegateCall\s*\(", body)
        for m in re.finditer(r"\.delegatecall\s*\(|functionDelegateCall\s*\(", eff):
            in_original = orig_dc is not None
            target = root_identifier(expression_before(eff, m.start())) if eff[m.start()] == "." else ""
            if not target:
                args, _ = call_args(eff, m.end() - 1)
                target = root_identifier(args[0]) if args else ""
            # Guards are read from the ORIGINAL source: inlining `_implementation()` inside a
            # `require(... == address(0))` would otherwise hide a one-time-init guard.
            guarded = ONE_TIME_GUARD_RE.search(body) or ONE_TIME_GUARD_RE.search(eff)
            if target in fn.param_names and not is_role_controlled(fn, project) and not guarded:
                note = "" if in_original else f" (forwarded through a helper/library from `{fn.name}`)"
                yield Hit(fn, orig_dc.start() if in_original else fn.offset,
                          f"delegatecall target `{target}` is a function parameter{note}.", absolute=not in_original)


@detector(
    "unchecked-low-level-call",
    "Return value of a low-level call is ignored",
    "medium",
    "A failed ETH/token transfer is treated as success; accounting is updated while funds never move (lost user funds or free withdrawals).",
    "Check the boolean result: `(bool ok, ) = to.call{value: v}(\"\"); require(ok);`.",
    ["https://swcregistry.io/docs/SWC-104"],
)
def _unchecked_call(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        for m in re.finditer(r"\.(call|send)\s*(\{[^}]*\})?\s*\(", body):
            if not result_is_used(body, m.start()):
                yield Hit(fn, m.start(), f"Result of `.{m.group(1)}` is not checked.")


@detector(
    "unchecked-erc20-transfer",
    "ERC20 transfer/transferFrom return value ignored",
    "medium",
    "With tokens that return false instead of reverting (e.g. ZRX, BAT, some bridged tokens), a deposit can be credited without any tokens arriving - free credit that is withdrawn as real assets.",
    "Use OpenZeppelin SafeERC20 (`safeTransfer`/`safeTransferFrom`) everywhere.",
    ["https://github.com/d-xo/weird-erc20#missing-return-values"],
)
def _unchecked_erc20(project: Project):
    expected = {"transfer": 2, "transferFrom": 3}
    for fn in project.functions():
        body = fn.body or ""
        for m in re.finditer(r"\.(transfer|transferFrom)\s*\(", body):
            receiver = expression_before(body, m.start())
            if receiver.startswith("payable(") or receiver.startswith("address("):
                continue
            args, _ = call_args(body, m.end() - 1)
            if len(args) != expected[m.group(1)] or result_is_used(body, m.start()):
                continue
            if re.search(r"(?i)\b\w*id\s*$", args[-1]):
                continue  # ERC721 transferFrom(from, to, tokenId) returns nothing
            if re.match(r"(?i)\w*(nft|erc721|721)\w*\b", receiver):
                continue
            pulls = m.group(1) == "transferFrom"
            yield Hit(
                fn, m.start(),
                f"`{receiver}.{m.group(1)}(...)` return value ignored"
                + (" while pulling funds in - deposits may be credited for free." if pulls else "."),
                severity="medium" if pulls else "low",
            )


# --------------------------------------------------------------------------- price / oracle / accounting

@detector(
    "spot-price-oracle",
    "Price derived from manipulable spot AMM state",
    "high",
    "Inside one flash-loan transaction an attacker skews pool reserves, borrows/mints against the inflated price, and repays - the most common DeFi lending exploit.",
    "Use a manipulation-resistant oracle (Chainlink with staleness checks, or a sufficiently long Uniswap V3 TWAP).",
    ["https://rekt.news/mango-markets-rekt/", "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles"],
)
def _spot_oracle(project: Project):
    amm_infra = re.compile(r"Router|Library|Pair$|Quoter|Factory|Uniswap|Sushi|Pancake|Swapper|Zap|Aggregator|Lens", re.I)
    valuation = re.compile(r"collateral|borrow|liquidat|oracle|healthFactor|\bltv\b|getPrice|latestPrice|priceOf|valueOf|totalValue|getValue|exchangeRate|pricePerShare|sharePrice|_?mint\w*\s*\(|debt", re.I)
    slippage = re.compile(r"amount\w*Min\w*|min\w*Out\w*|minReceiv\w*|minReturn\w*|INSUFFICIENT_OUTPUT|slippage", re.I)
    # Reading reserves to pair liquidity at the current ratio (what UniswapV2Router.addLiquidity does) values nothing.
    lp_provision = re.compile(r"\.mint\s*\(\s*address\s*\(\s*this\s*\)\s*\)|addLiquidity\w*\s*\(|quote\s*\(")
    by_contract: dict[str, list[Function]] = {}
    for f in project.functions():
        by_contract.setdefault(f.contract.name, []).append(f)

    def callers(fn: Function) -> list[Function]:
        """Functions of the same contract family that call `fn` directly."""
        fam = {fn.contract.name, *(i.split(".")[-1].strip() for i in fn.contract.inherits)}
        pat = re.compile(rf"(?<![.\w]){re.escape(fn.name)}\s*\(")
        return [g for name in fam for g in by_contract.get(name, []) if g is not fn and g.body and pat.search(g.body)]

    for fn in project.functions():
        body = fn.body or ""
        m = re.search(r"\.getReserves\s*\(|\.slot0\s*\(|\bget_dy\s*\(|\.getAmountsOut\s*\(", body)
        if not m or fn.contract.kind == "library" or amm_infra.search(fn.contract.name):
            continue
        if re.search(r"observe\s*\(|consult\s*\(|twap|TWAP|cumulative", fn.contract.text):
            continue
        # An internal helper (`_reserves()`, `getCheapestToken()`) is judged by how its callers use it.
        users = callers(fn) if fn.visibility in ("internal", "private") else []
        scope = [body] + [g.body for g in users]
        if any(slippage.search(b) or lp_provision.search(b) for b in scope):
            continue  # reserves used to execute a slippage-protected swap / pair liquidity, not to value anything
        # The spot quote must feed a valuation in THIS function or its callers - a valuation word elsewhere in
        # the contract (an unrelated _mint) does not make a routing/quote helper an oracle.
        if not (valuation.search(fn.name) or any(valuation.search(b) for b in scope)):
            continue
        yield Hit(fn, m.start(), f"`{fn.name}` reads spot AMM state (`{m.group(0).strip('.( ')}`) with no TWAP in the contract.")


@detector(
    "donation-manipulable-rate",
    "Exchange rate uses balanceOf(address(this))",
    "medium",
    "Anyone can donate tokens directly to the contract to move the share price; combined with rounding this steals deposits or breaks collateral valuation.",
    "Track assets in internal accounting instead of raw balanceOf(address(this)).",
    ["https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks"],
)
def _donation(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        m = re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", body)
        if m and re.search(r"totalSupply|totalShares|shares", body) and "/" in body:
            yield Hit(fn, m.start(), f"`{fn.name}` prices shares from the raw token balance.", confidence="low")


@detector(
    "erc4626-inflation",
    "First-depositor share inflation",
    "high",
    "The first depositor mints 1 wei of shares, donates assets to inflate the share price, and later depositors round down to 0 shares - their deposits are stolen.",
    "Use OpenZeppelin ERC4626 with a virtual-share decimals offset, or mint dead shares / require a minimum initial deposit.",
    ["https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks"],
)
def _inflation(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        zero = re.search(r"(?:totalSupply\s*\(\s*\)|_?totalSupply|totalShares|supply)\s*==\s*0", body)
        if not zero or "/" not in body:
            continue
        if not re.search(r"totalAssets|balanceOf\s*\(\s*address\s*\(\s*this", body):
            continue
        if re.search(r"_decimalsOffset|MINIMUM_LIQUIDITY|MIN_SHARES|DEAD|0xdead|_mint\s*\(\s*address\s*\(\s*[01]\s*\)|virtualShares|VIRTUAL", fn.contract.text):
            continue
        yield Hit(fn, zero.start(), f"`{fn.name}` special-cases an empty vault without virtual shares or dead shares.")


@detector(
    "chainlink-stale-price",
    "Chainlink price used without staleness / validity checks",
    "medium",
    "Stale or zero prices during outages let attackers borrow against overvalued collateral or liquidate healthy positions.",
    "Check `answer > 0`, `updatedAt` against a heartbeat (`block.timestamp - updatedAt < MAX_DELAY`), and the L2 sequencer uptime feed on rollups.",
    ["https://docs.chain.link/data-feeds/using-data-feeds#check-the-timestamp-of-the-latest-answer"],
)
def _chainlink(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        m = re.search(r"\.latestAnswer\s*\(", body)
        if m:
            yield Hit(fn, m.start(), "Deprecated `latestAnswer()` has no freshness information.")
            continue
        m = re.search(r"\.latestRoundData\s*\(", body)
        if m and not (re.search(r"updatedAt", body) and re.search(r"block\.timestamp", body)):
            yield Hit(fn, m.start(), "`latestRoundData()` result is used without a staleness check.")


@detector(
    "missing-slippage-protection",
    "Swap executed with zero minimum output",
    "high",
    "Any swap the contract performs can be sandwiched by MEV bots, extracting most of its value.",
    "Pass a caller- or oracle-derived `amountOutMin`, and a deadline.",
    ["https://dacian.me/defi-slippage-attacks"],
)
def _slippage(project: Project):
    pat = re.compile(
        r"swapExact\w*\s*(?:\{[^}]*\})?\s*\(\s*(?:[^,()]+(?:\([^()]*\))?\s*,\s*)?0\s*,|amountOutMin(?:imum)?\s*:\s*0\b|minAmountOut\s*:\s*0\b|min_dy\s*:\s*0\b"
    )
    for fn in project.functions():
        body = fn.body or ""
        m = pat.search(body)
        if m:
            public = fn.is_entrypoint and not access_controlled(fn, project)
            yield Hit(fn, m.start(), f"Swap in `{fn.name}` sets minimum output to 0"
                      + (" and anyone can trigger it." if public else "."), severity="high" if public else "medium")


# --------------------------------------------------------------------------- signatures / flash loans

@detector(
    "signature-replay",
    "Signatures can be replayed",
    "high",
    "A valid signature (withdrawal, permit, order, claim) is reused - on the same chain without a nonce, or on another chain/fork without chainid - draining funds repeatedly.",
    "Use EIP-712 (`_hashTypedDataV4`) including chainid and the verifying contract, plus a per-signer nonce or a used-digest mapping.",
    ["https://swcregistry.io/docs/SWC-121", "https://swcregistry.io/docs/SWC-117"],
)
def _sig_replay(project: Project):
    recover_re = re.compile(r"\becrecover\s*\(|ECDSA\.recover\s*\(|\.recover\s*\(|_?recoverKey\s*\(")
    # Replay is a property of the STATE-CHANGING function that consumes a signature, not of a view or
    # internal helper that merely recovers a signer (that helper may be used safely by its caller).
    for fn in entrypoints(project):
        if fn.contract.kind == "library":
            continue
        own = fn.body or ""
        body = effective_body(fn, project, depth=2)
        m = recover_re.search(body)
        if not m:
            continue
        in_own = recover_re.search(own)
        if in_own:
            m = in_own
        # The nonce often lives in a child (GnosisSafe holds `nonce`, SignatureDecoder recovers), so
        # judge the whole family: the contract, what it inherits, and what inherits from it.
        ctext = family_text(fn.contract, project)
        # ERC-1271 validators (isValidSignature, return 0x1626ba7e): they answer "did my key sign this?"
        # for an external protocol, which owns the nonce/order bookkeeping (AirSwap, Permit2, Seaport).
        if re.search(r"0x1626ba7e|isValidSignature", body + " " + fn.name) or fn.name == "isValidSignature":
            continue
        # ERC-4337 smart accounts: the EntryPoint enforces the nonce and the userOpHash binds chainid +
        # EntryPoint address, so replay protection lives outside the account contract by design.
        if re.search(r"UserOperation|userOpHash|IEntryPoint|_validateSignature", ctext) and \
                re.search(r"userOp|UserOperation", body + ctext):
            continue
        # replay protection comes under many names: nonces, sequence ids (BitGo), used/executed/claimed
        # digests, invalidated hashes, cancelled orders, bitmaps (Permit2)...
        # A nonce only protects if it is CONSUMED: incremented, marked used, or a bitmap bit set.
        # A declared-but-never-incremented nonce is itself the bug.
        off, absolute = (m.start(), False) if in_own else (fn.offset, True)
        # Consuming the signature also counts when the entrypoint (or its helpers) marks it - e.g. a
        # per-trade id `if (bridged[tradeId]) revert; bridged[tradeId] = true` in the caller's own code.
        # State-channel / library-delegation designs put the signature check AND the replay guard (a
        # monotonic struct-field nonce, `if (nonce <= stored) revert InvalidNonce()`) in dedicated
        # libraries the entrypoint delegates into (Lithium -> LithiumUpdater/Settler/Verification). Those
        # libraries are not in the family text, so collect the text of every library the call tree
        # transitively references and fold it into both the replay-guard and chainid-binding scopes.
        by_name = {c.name: c for f in project.files for c in f.contracts}
        refd: set[str] = set()
        frontier = ctext + " " + body
        for _ in range(3):
            new = {n for n, c in by_name.items() if c.kind == "library" and n not in refd
                   and re.search(rf"(?<![.\w]){re.escape(n)}\s*\.", frontier)}
            if not new:
                break
            refd |= new
            frontier = " ".join(by_name[n].text for n in new)
        reflib_text = " ".join(by_name[n].text for n in refd)
        scope = ctext + " " + body + " " + reflib_text
        guarded = bool(REPLAY_GUARD_RE.search(scope))
        # Self-signed: the recovered signer must BE the caller (2FA / password-style schemes). Nobody else can
        # submit that signature, so "replaying" it only re-does the caller's own action.
        aliases = "|".join([SENDER] + [re.escape(a) for a in SENDER_ALIAS_RE.findall(body)])
        rec_vars = re.findall(r"(\w+)\s*=\s*[^;]*(?:ecrecover|\.recover)\s*\(", body)
        if any(re.search(rf"\b{re.escape(v)}\s*[!=]=\s*(?:{aliases})\b|(?:{aliases})\s*[!=]=\s*{re.escape(v)}\b", body)
               for v in rec_vars) or re.search(rf"recover\s*\([^;]*\)\s*[!=]=\s*(?:{aliases})\b", body):
            guarded = True
        # One-shot state flag: `require(!charged)` / `require(charged == false)` ... `charged = true;` - the
        # function (and therefore the signature) can only ever take effect once.
        for flag in re.findall(r"require\s*\(\s*(?:!\s*(\w+)\s*\)|(\w+)\s*==\s*false\s*\))", body):
            name = flag[0] or flag[1]
            if re.search(rf"\b{re.escape(name)}\s*=\s*true\s*;", body):
                guarded = True
        if not guarded:
            declared = re.search(r"\bnonce", ctext, re.I)
            yield Hit(fn, off, f"`{fn.name}` acts on a signature but nothing consumes a nonce or marks the digest used"
                               + (" (a nonce is declared but never incremented)." if declared else "."), absolute=absolute)
        elif not re.search(r"block\.chainid|chainid\s*\(|_hashTypedDataV4|DOMAIN_SEPARATOR|_domainSeparator|EIP712"
                           r"|getNetworkId|networkId|chainId", scope):   # BitGo binds via a per-chain network id
            yield Hit(fn, off, f"`{fn.name}` signed digest does not bind chainid (cross-chain replay).", severity="medium",
                      absolute=absolute)
        # Zero-address check: only judged where ecrecover is called directly (a helper returning it defers).
        if in_own and "ecrecover" in m.group(0) and not re.search(r"address\s*\(\s*0\s*\)", own) \
                and not re.search(r"return\s+ecrecover\s*\(", own):
            yield Hit(fn, m.start(), "`ecrecover` result is not checked against address(0); invalid signatures may authorize an unset signer.", severity="medium")


FLASH_CALLBACKS = {
    "onFlashLoan", "executeOperation", "receiveFlashLoan", "uniswapV2Call", "pancakeCall",
    "uniswapV3SwapCallback", "uniswapV3FlashCallback", "pancakeV3SwapCallback", "algebraSwapCallback",
    "callFunction", "onMorphoFlashLoan", "hook", "unlockCallback", "lockAcquired",
}
# Named callback families whose name alone is a reliable signal.
CALLBACK_NAME_RE = re.compile(
    r"^(?:\w+FlashLoanCall|\w+(?:Swap|Flash|Mint|Pay)Callback|unlockCallback|lockAcquired"
    r"|receiveFlashLoan|executeOperation|onFlashLoan|onMorpho\w+)$"
)
# Known Uniswap-V2-fork flash-swap callbacks end in `Call` (NOT `AndCall`), with signature
# (address sender, uint amount0, uint amount1, bytes data). ERC677/ERC1363 transferAndCall/
# approveAndCall are excluded by shape: they start with a token verb and carry no leading address+bytes.
V2_CALL_NAME_RE = re.compile(r"^[a-z]\w*Call$")
V2_CALL_EXCLUDE = re.compile(r"^(?:transfer|approve|send|mint|burn|deposit|withdraw|safe|multi|pre|post|try|external|internal|low|static|delegate)\w*", re.I)
# msg.sender actually compared (to the pool/lender), or validated via a callback-validation helper.
SENDER_AUTH_RE = re.compile(
    rf"{SENDER}\s*[!=]=|[!=]=\s*{SENDER}\b|verifyCallback\s*\(|CallbackValidation\.|_verifyCallback\w*\s*\("
    r"|_validate\w*(?:Pool|Caller|Pair|Sender)\w*\s*\(|require\s*\(\s*\w+\s*\[\s*" + SENDER + r"\s*\]"
)
INITIATOR_PARAMS = {"initiator", "sender", "_initiator", "_sender", "origin", "initiator_", "sender_", "borrower"}


def _is_callback(fn) -> bool:
    name = fn.name
    if name in FLASH_CALLBACKS or CALLBACK_NAME_RE.match(name):
        return True
    # V2-fork flash-swap callback: name ends in ...Call, not a token verb, and has the
    # (address, uint, uint, bytes) shape - first param address, last param bytes.
    if V2_CALL_NAME_RE.match(name) and not V2_CALL_EXCLUDE.match(name) and "AndCall" not in name:
        p = fn.params
        return bool(p) and p[0].type.startswith("address") and any(x.type.startswith("bytes") for x in p)
    return False


@detector(
    "unvalidated-flash-callback",
    "Flash-loan / swap callback does not authenticate the caller",
    "critical",
    "Anyone can invoke the callback directly with crafted data, making the contract pay out, approve, or execute arbitrary actions with its own funds.",
    "Require msg.sender to be the expected pool/lender (verify via the factory, e.g. getPair/getPool/computeAddress), and that `initiator`/`sender` equals address(this).",
    ["https://rekt.news/dodo-rekt/"],
)
def _flash_callback(project: Project):
    for fn in entrypoints(project):
        if not _is_callback(fn):
            continue
        # One-level inline: MEV arb bots route uniswapV3SwapCallback/pancakeV3SwapCallback into a
        # shared `_v3Callback(amount0Delta, amount1Delta, data)` helper that pins msg.sender to the
        # expected pool via a packed-address compare `require(uint96(uint160(msg.sender)) == uint96(expected))`.
        # Without inlining we'd flag every one of those bots as unauthenticated.
        body = effective_body(fn, project, depth=1)
        authed = SENDER_AUTH_RE.search(body) or access_controlled(fn, project)
        pays_sender = re.search(rf"\.(?:transfer|safeTransfer|call\s*\{{[^}}]*value)\s*\(\s*{SENDER}\b", body)
        if not authed:
            extra = " and pays msg.sender without verifying it is the pool" if pays_sender else ""
            yield Hit(fn, fn.offset, f"`{fn.name}` does not compare msg.sender to the expected pool/lender{extra}.", absolute=True)
            continue
        # Caller is checked; now the initiator/sender argument must be pinned to address(this),
        # not merely referenced (logging or decoding it proves nothing).
        initiator = next((p for p in fn.param_names if p.lower() in INITIATOR_PARAMS), None)
        if initiator:
            pinned = re.search(
                rf"(?:require|if)\s*\([^;{{]*(?:\b{re.escape(initiator)}\s*[!=]=\s*(?:address\s*\(\s*this\s*\)|\w+)"
                rf"|(?:address\s*\(\s*this\s*\)|\w+)\s*[!=]=\s*{re.escape(initiator)}\b)", body)
            if not pinned:
                yield Hit(fn, fn.offset, f"`{fn.name}` checks the caller but never pins `{initiator}` to address(this) - "
                          "another user can start the loan into this contract.", severity="high", absolute=True)


# --------------------------------------------------------------------------- arithmetic / randomness

@detector(
    "pre-0.8-overflow",
    "Unchecked arithmetic on Solidity < 0.8 without SafeMath",
    "high",
    "Integer overflow/underflow of balances lets an attacker mint huge balances or bypass checks (BEC/batchOverflow).",
    "Upgrade to Solidity >= 0.8 or use SafeMath for every arithmetic operation on balances.",
    ["https://swcregistry.io/docs/SWC-101"],
)
def _overflow(project: Project):
    for f in project.files:
        if not f.is_pre_08 or "SafeMath" in f.clean:
            continue
        for c in f.contracts:
            for fn in c.functions:
                # Only state-changing code an outsider can call matters: views can't steal, and
                # admin-only paths (onlyWallet/onlyOwner) aren't attacker-controlled.
                if not fn.is_entrypoint or not fn.body or not fn.is_mutating or is_role_controlled(fn, project):
                    continue
                body = fn.body
                uint_params = {p for p in fn.params_of_type("uint")}
                if not uint_params:
                    continue
                state = project.state_vars
                hit = None
                # (a) batchOverflow: a multiplication involving an attacker-chosen amount (BEC, CVE-2018-10299)
                for m in re.finditer(r"([\w\])]+)\s*(\*=|\*(?!\*))\s*([\w.]+)", body):
                    left = set(re.findall(r"\w+", m.group(1))); right = m.group(3).split(".")[0]
                    if (left | {right}) & uint_params:
                        hit = (m.start(), f"multiplication with caller-chosen amount in `{fn.name}` can overflow")
                        break
                # (b)/(c) a balance-like state mapping credited or debited by a caller-chosen amount
                if not hit:
                    for m in re.finditer(r"\b(\w+)\s*\[[^\]]*\]\s*(\+=|-=)\s*(\w+)|"
                                         r"\b(\w+)\s*\[([^\]]*)\]\s*=\s*\4\s*\[\5\]\s*([+-])\s*(\w+)", body):
                        var = m.group(1) or m.group(4)
                        op = m.group(2) or (m.group(6) + "=")
                        amt = m.group(3) or m.group(7)
                        if var not in state or amt not in uint_params:
                            continue
                        before = body[:m.start()]
                        if re.search(rf"(?:require|assert|if)\s*\([^;]*\b(?:{re.escape(var)}|{re.escape(amt)})\b[^;]*(?:>=|<=|>|<)", before):
                            continue      # bounded first, e.g. require(balances[from] >= value)
                        hit = (m.start(), f"`{var}` {'credited' if op == '+=' else 'debited'} by caller-chosen `{amt}` "
                                          f"in `{fn.name}` with no bound check")
                        break
                if hit:
                    yield Hit(fn, hit[0], hit[1] + f" (pragma `{f.pragma}`, no SafeMath).", confidence="low")


@detector(
    "divide-before-multiply",
    "Division before multiplication (precision loss)",
    "low",
    "Rounding error accumulates; in lending/vault math attackers loop small operations to round in their favour.",
    "Multiply before dividing (or use mulDiv), and round against the user.",
    ["https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply"],
)
def _div_mul(project: Project):
    pat = re.compile(r"[\w)\]]\s*/\s*[\w.\[\]]+(?:\([^()]*\))?\s*\)?\s*\*\s*[\w(]")
    for fn in project.functions():
        m = pat.search(fn.body or "")
        if m:
            yield Hit(fn, m.start(), f"`{fn.name}` divides before multiplying.", confidence="low")


@detector(
    "weak-randomness",
    "Randomness from block data",
    "medium",
    "Validators/builders and contracts in the same block can predict or influence the outcome and win every draw/lottery/mint.",
    "Use Chainlink VRF or a commit-reveal scheme.",
    ["https://swcregistry.io/docs/SWC-120"],
)
def _randomness(project: Project):
    for fn in project.functions():
        body = fn.body or ""
        for m in re.finditer(r"keccak256\s*\(", body):
            s, e = statement_bounds(body, m.start())
            stmt = body[s:e]
            if re.search(r"block\.(timestamp|prevrandao|difficulty|number|coinbase)|blockhash\s*\(", stmt) and "%" in stmt:
                yield Hit(fn, m.start(), f"`{fn.name}` derives a random number from block data.")
                break


# --------------------------------------------------------------------------- runner

def build_project(files: list[SourceFile], meta: dict | None = None) -> Project:
    auth_mods: set[str] = set()
    state_vars: set[str] = set()
    for f in files:
        for c in f.contracts:
            state_vars |= c.state_vars
            for mod in c.modifiers:
                if mod.body and (re.search(SENDER, mod.body) or AUTH_BODY_RE.search(mod.body)):
                    auth_mods.add(mod.name)
    return Project(files, auth_mods, state_vars, meta or {})


def run_detectors(files: list[SourceFile], only: set[str] | None = None, exclude: set[str] | None = None,
                  meta: dict | None = None) -> list[Finding]:
    project = build_project(files, meta)
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for det in DETECTORS:
        if (only and det.id not in only) or (exclude and det.id in exclude):
            continue
        for hit in det.run(project):
            fn = hit.fn
            sf = fn.contract.file
            abs_off = hit.offset if hit.absolute else fn.body_offset + hit.offset
            line = sf.line_of(abs_off)
            key = (det.id, sf.display, line, hit.description)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                detector=det.id,
                title=det.title,
                severity=hit.severity or det.severity,
                confidence=hit.confidence,
                file=sf.display,
                line=line,
                contract=fn.contract.name,
                function=fn.name,
                description=hit.description,
                impact=det.impact,
                recommendation=det.recommendation,
                snippet=sf.line_text(line),
                references=det.references,
            ))
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line))
    return findings
