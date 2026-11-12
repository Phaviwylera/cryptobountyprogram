"""Per-contract vulnerability reports and the run-wide summary for `bountyscan auto`."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .detectors import Finding
from .remediation import REMEDIATION
from .sources import explorer_url

WEI = 10**18
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH"}


def _context(path: str, line: int, radius: int = 4) -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    width = len(str(hi))
    return "\n".join(f"{'>' if n == line else ' '} {n:>{width}} | {lines[n - 1]}" for n in range(lo, hi + 1))


def _verdict_lines(v) -> list[str]:
    if v is None:
        return []
    mark = "confirmed by independent second pass" if v.confirmed else "NOT confirmed"
    extra = (" - " + "; ".join(v.counter_checks)) if v.counter_checks else ""
    return [f"> **Verification:** {mark} ({v.reason}){extra}", ""]


def _rel(path: str, src_dir: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(src_dir.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def _fmt_amt(n) -> str:
    if n is None:
        return "n/a"
    sign = "-" if n < 0 else ""
    a = abs(int(n))
    return sign + (f"{a/1e18:.6f} e18" if a >= 10**12 else str(a))


def _payload_exec_lines(pv, f) -> list[str]:
    if pv is None:
        return ["_No generic payload for this detector class — confirm with a hand-written fork PoC._", ""]
    moved = "funds moved to the attacker wallet" if pv.outcome == "confirmed" else \
            ("call reverted — the guard held" if pv.outcome == "reverted" else
             "call succeeded but moved nothing (fallback / no drain)" if pv.outcome == "no_change" else
             "left for manual verification")
    return [
        f"- **Outcome:** {pv.status_word} — {pv.detail}",
        f"- **State injection:** {pv.injected or 'vm.deal: gas only'}",
        "- **Attack path:**",
        "  1. Fork mainnet at the latest block; prank the attacker (msg.sender AND tx.origin = the receiving wallet).",
        f"  2. Fire `{f.function}(...)` with an attacker-favourable payload routed to the wallet.",
        f"  3. {moved}.",
        "",
    ]


def _differential_lines(pv) -> list[str]:
    if not pv or not pv.metrics:
        return ["_Not measured (no dynamic run)._", ""]
    m = pv.metrics
    ok = pv.outcome == "confirmed"
    return [
        f"- **Call returned:** {'success' if m.get('call_ok') else 'revert'}",
        f"- **Attacker delta:** wei `{_fmt_amt(m.get('att_wei', 0))}` · token `{_fmt_amt(m.get('att_tok', 0))}`",
        f"- **Target delta:** wei `{_fmt_amt(m.get('tgt_wei', 0))}` · token `{_fmt_amt(m.get('tgt_tok', 0))}`",
        f"- **Code length delta:** `{m.get('code', 0)}` (selfdestruct check)",
        f"- **Assertion — attacker GAINS and target LOSES:** {'✅ PASS' if ok else '❌ FAIL — not a confirmed exploit'}",
        "",
    ]


def write_contract_report(chain: str, address: str, meta: dict, findings: list[Finding], balance_wei: int | None,
                          src_dir: Path, out_dir: Path, verdicts=None, holdings=None, payloads=None) -> Path:
    from .value import describe as describe_value
    vmap = {}
    if verdicts:
        for v in verdicts:
            vmap[(v.finding.detector, v.finding.contract, v.finding.function, v.finding.line)] = v
    pmap = {}
    if payloads:
        for pv in payloads:
            pmap[(pv.finding.detector, pv.finding.contract, pv.finding.function)] = pv
    target = out_dir / "vulnerable" / chain / address.lower()
    target.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    name = meta.get("contract_name") or "unknown"
    crit = sum(f.severity == "critical" for f in findings)
    high = len(findings) - crit
    # forensic overall status from the dynamic payload attack
    outs = {pv.outcome for pv in (payloads or [])}
    fstatus = ("CONFIRMED EXPLOIT" if "confirmed" in outs else
               "LATENT / MANUAL REVIEW" if ("manual" in outs or not payloads) else
               "STATIC CANDIDATE")

    lines = [
        f"# 🛡️ BountyScan Forensic Report: {name} ({chain} {address})",
        "",
        "| | |",
        "|---|---|",
        f"| Status | **{fstatus}** |",
        f"| Verdict | **VULNERABLE**: {crit} critical, {high} high fund-theft candidate(s) |",
        f"| Chain / address | {chain} / [`{address}`]({explorer_url(chain, address)}) |",
        f"| Contract | {name} (compiler {meta.get('compiler') or '?'}) |",
        f"| Proxy | {'yes, implementation ' + str(meta.get('implementation')) if meta.get('proxy') else 'no'} |",
        f"| Value held at scan | {describe_value(holdings) if holdings else ('unknown' if balance_wei is None else f'{balance_wei / WEI:.6f} native')} |",
        f"| Scanned | {now} |",
        "",
        "> These are fund-theft **candidates** from static analysis. Before telling anyone: confirm the call path,",
        "> check the funds at risk (token balances too, not just native), and prove it with a fork PoC",
        "> (`templates/poc`). Never send a transaction to the live contract. See docs/DISCLOSURE.md.",
        "",
    ]
    for i, f in enumerate(findings, 1):
        rem = REMEDIATION.get(f.detector, {})
        loc = _rel(f.file, src_dir)
        pv = pmap.get((f.detector, f.contract, f.function))
        status = pv.status_word if pv else "STATIC CANDIDATE (no dynamic run)"
        lines += [
            f"## {i}. [{SEV_LABEL.get(f.severity, f.severity.upper())}] {f.title}",
            "",
            f"**Status:** {status}" + (f" — {pv.detail}" if pv else ""),
            "",
            f"**Where:** `{loc}:{f.line}` in `{f.contract}.{f.function}()`",
            "",
            "### 1. Executive summary",
            "",
            f.description,
            "",
            "### 2. Static analysis & code trace",
            "",
            f"- **Vulnerable function:** `{f.contract}.{f.function}()`",
            f"- **Flaw:** {f.title}",
            *_verdict_lines(vmap.get((f.detector, f.contract, f.function, f.line))),
            "```solidity",
            _context(f.file, f.line) or f.snippet,
            "```",
            "",
            "### 3. Dynamic payload execution (Foundry fork)",
            "",
            *_payload_exec_lines(pv, f),
            "### 4. 200% differential verification",
            "",
            *_differential_lines(pv),
            "### 5. How it can be exploited & how to fix",
            "",
            *[f"{n}. {step}" for n, step in enumerate(rem.get("attack", []), 1)],
            "",
            f"**Impact:** {f.impact}",
            "",
            f"**Fix:** {f.recommendation}",
            "",
            "```solidity",
            rem.get("fix", "// see recommendation"),
            "```",
            "",
            *([f"**References:** {' / '.join(f.references)}", ""] if f.references else []),
            "**Verify before reporting:** [ ] reachable by an unprivileged caller  [ ] funds actually at risk  "
            "[ ] not a known/accepted issue  [ ] PoC passes on a fork",
            "",
        ]
    lines += [
        "## Next steps",
        "",
        "1. Confirm each finding by reading the code path (modifiers in parent contracts, deployed configuration).",
        "2. Write a Foundry fork PoC from `templates/poc` showing attacker profit / victim loss.",
        "3. Report privately: the project's bounty program (Immunefi etc.) or security contact. If funds are being",
        "   drained right now and the team is unreachable, contact SEAL 911.",
    ]
    report = target / "REPORT.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    (target / "findings.json").write_text(json.dumps({
        "chain": chain, "address": address, "meta": meta, "balance_wei": balance_wei,
        "findings": [f.to_dict() for f in findings],
    }, indent=2), encoding="utf-8")
    return report


def write_summary(store, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = store.counts()
    vulns = store.by_status("vulnerable")
    rank = {"critical": 0, "high": 1}
    vulns = sorted(vulns, key=lambda r: (-(r["value_usd"] or 0), rank.get(r["max_severity"], 9)))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = sum(counts.values())
    lines = [
        "# bountyscan auto: summary",
        "",
        f"Updated {now}. Contracts tracked: {total}",
        "",
        "| Status | Count | Meaning |",
        "|---|---|---|",
        f"| VULNERABLE | {counts.get('vulnerable', 0)} | Fund-theft candidate(s) found; report written |",
        f"| SAFE | {counts.get('safe', 0)} | No fund-theft pattern detected (not a guarantee - logic bugs need manual review) |",
        f"| Waiting for verification | {counts.get('unverified', 0) + counts.get('queued', 0)} | Retried automatically |",
        f"| Unverified (gave up) | {counts.get('unverified_final', 0)} | Source never published |",
        f"| Skipped | {counts.get('low_value', 0) + counts.get('no_code', 0)} | Below balance threshold / no code |",
        f"| Errors | {counts.get('error', 0)} | See `bountyscan status --errors` |",
        "",
        "## Vulnerable contracts",
        "",
    ]
    if not vulns:
        lines.append("None so far.")
    else:
        lines += ["| Worst | Findings | Chain | Address | Contract | Value held (USD) | Report |", "|---|---|---|---|---|---|---|"]
        for r in vulns:
            bal = f"${r['value_usd']:,.2f}" if r["value_usd"] is not None else "?"
            rel = Path(r["report"]).resolve()
            try:
                rel = rel.relative_to(out_dir.resolve())
            except ValueError:
                pass
            lines.append(f"| {r['max_severity'].upper()} | {r['findings']} | {r['chain']} | `{r['address']}` | {r['name'] or ''} | {bal} | [{rel.as_posix()}]({rel.as_posix()}) |")
    safe = store.by_status("safe")
    (out_dir / "safe.txt").write_text("\n".join(f"{r['chain']}:{r['address']}  {r['name'] or ''}" for r in safe), encoding="utf-8")
    path = out_dir / "SUMMARY.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
