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

    def functions(self) -> Iterator[Function]:
        for f in self.files:
            for c in f.contracts:
                yield from c.functions


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
    r"only|auth|admin|owner|role|gov|restricted|guardian|keeper|operator|whitelist|allowlist|permission|requires",
    re.I,
)
AUTH_BODY_RE = re.compile(
    r"_check(?:Owner|Role|Auth|Admin|Caller|Sender|Permission|Canonical)\w*\s*\(|hasRole\s*\(|_?only\w*\s*\(|_authorize\w*|_?isAuthorized|requiresAuth"
    r"|_require\w*(?:Owner|Admin|Role|Auth)\w*\s*\("
    rf"|require\s*\([^;]*{SENDER}|if\s*\([^;{{]*{SENDER}[^;{{]*\)\s*(?:revert|\{{\s*revert)"
)
# `address caller = _msgSender(); if (caller != authority()) revert ...;`
SENDER_ALIAS_RE = re.compile(rf"\b(\w+)\s*=\s*{SENDER}\s*;")
REENTRANCY_GUARD_RE = re.compile(r"reentr|^lock$|^nonReentrant|^mutex", re.I)
# set-once guards: require(_implementation() == address(0)), if (owner != address(0)) revert ...
ONE_TIME_GUARD_RE = re.compile(
    r"require\s*\([^;]*==\s*address\s*\(\s*0\s*\)|if\s*\([^;{]*!=\s*address\s*\(\s*0\s*\)[^;{]*\)\s*(?:revert|\{\s*revert)"
)
SIGNATURE_CHECK_RE =re.compile(r"MerkleProof|\.verify\s*\(|ecrecover\s*\(|\.recover\s*\(|SignatureChecker|isValidSignature")


def access_controlled(fn: Function, project: Project) -> bool:
    """Does the function restrict *who* may call it?"""
    for m in fn.modifiers:
        if m in project.auth_modifiers or AUTH_MODIFIER_RE.search(m):
            return True
    body = fn.body or ""
    if AUTH_BODY_RE.search(body):
        return True
    if re.search(rf"\bsuper\.{re.escape(fn.name)}\s*\(", body):
        return True  # override delegating to the (checked) parent implementation
    for alias in SENDER_ALIAS_RE.findall(body):
        if re.search(rf"(?:require|if)\s*\([^;{{]*\b{re.escape(alias)}\b\s*[!=]=", body):
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


def entrypoints(project: Project, mutating: bool = True) -> Iterator[Function]:
    for fn in project.functions():
        if fn.is_entrypoint and (fn.is_mutating or not mutating):
            yield fn


# --------------------------------------------------------------------------- access control

PRIVILEGED_NAME_RE = re.compile(
    r"^_?(?:set[A-Z_]\w*|upgrade\w*|transferOwnership|changeOwner|changeAdmin|setAdmin|renounce\w*|"
    r"sweep\w*|rescue\w*|recover\w*|emergency\w*|drain\w*|withdraw(?:All|Fees?|Tokens?|ETH|Eth|Funds|Treasury|Reserves?|Stuck\w*|Protocol\w*)|"
    r"pause|unpause|kill|destroy|shutdown|migrate\w*|grant\w*|addMinter|add(?:Admin|Operator|Keeper)|update(?:Price|Oracle|Rate)\w*|configure\w*)$"
)
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
        if fn.name.startswith("initialize") or access_controlled(fn, project):
            continue
        if re.search(rf"\[\s*{SENDER}\s*\]", fn.body or ""):
            continue  # user-scoped state, e.g. prefs[msg.sender]
        if not (fn.body or "").strip():
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
        if re.search(r"msg\.value|transferFrom\s*\(|safeTransferFrom\s*\(|_burn\s*\(|\bburn\w*\s*\(|SIGNATURE|MerkleProof|ecrecover|\.recover\s*\(", body):
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
        for m in re.finditer(r"\b_burn\s*\(\s*(\w+)", body):
            if m.group(1) in fn.params_of_type("address") and not re.search(
                r"allowance|_spendAllowance|_approve|isApprovedForAll|_isApprovedOrOwner|getApproved", body
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
        for m in pay_re.finditer(body):
            to = next((g for g in m.groups() if g), "")
            if to in recipients:
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
    for fn in entrypoints(project):
        if not re.match(r"^(initiali[sz]e\w*|init)$", fn.name):
            continue
        if any(re.search(r"initializ|reinitializ|onlyInitializing", m, re.I) for m in fn.modifiers):
            continue
        body = fn.body or ""
        if re.search(r"initiali[sz]ed|_initializing|inited|require\s*\(\s*!?\s*\w*[Ii]nit", body) or ONE_TIME_GUARD_RE.search(body):
            continue
        if access_controlled(fn, project) and not uses_sender(fn):
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
        for m in re.finditer(r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin", body):
            s, e = statement_bounds(body, m.start())
            if re.search(rf"tx\.origin\s*[!=]=\s*{SENDER}|{SENDER}\s*[!=]=\s*tx\.origin", body[s:e]):
                continue  # EOA-only check, not authorization
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
        m = re.search(r"\b(?:selfdestruct|suicide)\s*\(", fn.body or "")
        if m and not access_controlled(fn, project):
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
        r"\.call\s*\{|\.call\s*\(|safeTransferETH\s*\(|\.sendValue\s*\(|\b_safeMint\s*\(|\.onERC721Received\s*\(|\.tokensReceived\s*\("
    )
    for fn in entrypoints(project):
        if any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifiers):
            continue
        body = fn.body or ""
        call = call_re.search(body)
        if not call:
            continue
        _, stmt_end = statement_bounds(body, call.start())
        after = body[stmt_end:]
        writes = [
            v for v in project.state_vars
            if re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*?\]\s*)*(?:\.\w+\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", after)
            or re.search(rf"\bdelete\s+{re.escape(v)}\b", after)
        ]
        if not writes:
            continue
        native = not re.match(r"\b_safeMint|\.onERC721Received|\.tokensReceived", call.group(0))
        yield Hit(
            fn, call.start(),
            f"External call in `{fn.name}` happens before writing state variable(s): {', '.join(sorted(writes))}; no reentrancy guard.",
            severity="high" if native else "medium",
            confidence="high" if native else "medium",
        )


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
        if access_controlled(fn, project):
            continue
        body = fn.body or ""
        bytes_params = fn.params_of_type("bytes")
        for m in re.finditer(r"\.(call|functionCall|functionCallWithValue)\s*(\{[^}]*\})?\s*\(", body):
            target = root_identifier(expression_before(body, m.start()))
            args, _ = call_args(body, m.end() - 1)
            if target in fn.param_names and args and any(
                re.search(rf"\b{re.escape(b)}\b", args[0]) for b in bytes_params
            ):
                yield Hit(fn, m.start(), f"`{target}.{m.group(1)}(...)` uses a caller-supplied target and calldata.")


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
        for m in re.finditer(r"\.delegatecall\s*\(|functionDelegateCall\s*\(", body):
            target = root_identifier(expression_before(body, m.start())) if body[m.start()] == "." else ""
            if not target:
                args, _ = call_args(body, m.end() - 1)
                target = root_identifier(args[0]) if args else ""
            if target in fn.param_names and not access_controlled(fn, project) and not ONE_TIME_GUARD_RE.search(body):
                yield Hit(fn, m.start(), f"delegatecall target `{target}` is a function parameter.")


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
    for fn in project.functions():
        body = fn.body or ""
        m = re.search(r"\.getReserves\s*\(|\.slot0\s*\(|\bget_dy\s*\(|\.getAmountsOut\s*\(", body)
        if not m:
            continue
        if re.search(r"observe\s*\(|consult\s*\(|twap|TWAP|cumulative", fn.contract.text):
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
    for fn in project.functions():
        body = fn.body or ""
        m = re.search(r"\becrecover\s*\(|ECDSA\.recover\s*\(|\.recover\s*\(", body)
        if not m or fn.contract.kind == "library":
            continue  # stateless helpers (e.g. ECDSA) cannot hold nonces themselves
        ctext = fn.contract.text
        if not re.search(r"nonce|used\w*\s*\[|executed\s*\[|claimed\s*\[|consumed\s*\[|_useNonce|isUsed", ctext, re.I):
            yield Hit(fn, m.start(), f"`{fn.name}` verifies a signature but the contract tracks no nonce/used-digest.")
        elif not re.search(r"block\.chainid|chainid\s*\(|_hashTypedDataV4|DOMAIN_SEPARATOR|_domainSeparator|EIP712", ctext):
            yield Hit(fn, m.start(), f"`{fn.name}` signed digest does not bind chainid (cross-chain replay).", severity="medium")
        if "ecrecover" in m.group(0) and not re.search(r"address\s*\(\s*0\s*\)", body):
            yield Hit(fn, m.start(), "`ecrecover` result is not checked against address(0); invalid signatures may authorize an unset signer.", severity="medium")


FLASH_CALLBACKS = {
    "onFlashLoan", "executeOperation", "receiveFlashLoan", "uniswapV2Call", "pancakeCall",
    "uniswapV3SwapCallback", "uniswapV3FlashCallback", "pancakeV3SwapCallback", "algebraSwapCallback",
    "callFunction", "onMorphoFlashLoan", "hook",
}


@detector(
    "unvalidated-flash-callback",
    "Flash-loan / swap callback does not authenticate the caller",
    "critical",
    "Anyone can invoke the callback directly with crafted data, making the contract pay out, approve, or execute arbitrary actions with its own funds.",
    "Require msg.sender to be the expected pool/lender, and that `initiator`/`sender` equals address(this).",
    ["https://rekt.news/dodo-rekt/"],
)
def _flash_callback(project: Project):
    for fn in entrypoints(project):
        if fn.name not in FLASH_CALLBACKS:
            continue
        body = fn.body or ""
        if not (uses_sender(fn) or access_controlled(fn, project)):
            yield Hit(fn, fn.offset, f"`{fn.name}` never checks msg.sender.", absolute=True)
            continue
        initiator = next((p for p in fn.param_names if p in ("initiator", "sender", "_initiator", "_sender")), None)
        if initiator and not re.search(rf"\b{initiator}\b", body):
            yield Hit(fn, fn.offset, f"`{fn.name}` checks the caller but ignores `{initiator}` - another user can start the loan into this contract.",
                      severity="high", absolute=True)


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
                if not fn.is_entrypoint or not fn.body:
                    continue
                body = fn.body
                uint_params = fn.params_of_type("uint")
                for m in re.finditer(r"([\w\])]\s*)(\+=|-=|\*=|\*(?!=)|-(?![=>-]))\s*([\w.]+)", body):
                    op, operand = m.group(2), m.group(3)
                    before = body[: m.start()]
                    bounded = re.search(r"(?:require|assert|if)\s*\([^;]*(?:>=|<=|>|<)", before)
                    if op in ("-=", "-") and bounded:
                        continue  # e.g. require(balance >= wad); balance -= wad;
                    if op == "+=" and (operand not in uint_params or bounded):
                        continue  # msg.value / bounded amounts cannot realistically overflow
                    if op in ("*", "*=") and not ({operand} | set(re.findall(r"\w+", m.group(1))) & uint_params):
                        continue
                    yield Hit(fn, m.start(), f"`{op}` in `{fn.name}` under pragma `{f.pragma}` without SafeMath or a prior bound check.",
                              confidence="low")
                    break


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

def build_project(files: list[SourceFile]) -> Project:
    auth_mods: set[str] = set()
    state_vars: set[str] = set()
    for f in files:
        for c in f.contracts:
            state_vars |= c.state_vars
            for mod in c.modifiers:
                if mod.body and (re.search(SENDER, mod.body) or AUTH_BODY_RE.search(mod.body)):
                    auth_mods.add(mod.name)
    return Project(files, auth_mods, state_vars)


def run_detectors(files: list[SourceFile], only: set[str] | None = None, exclude: set[str] | None = None) -> list[Finding]:
    project = build_project(files)
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
