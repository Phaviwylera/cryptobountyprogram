"""Report writers: Markdown triage report, JSON, SARIF, and per-finding submission drafts."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .detectors import DETECTORS, Finding
from .scanner import ScanResult

# Immunefi Vulnerability Severity Classification System v2.3 (smart contracts) - abbreviated.
IMMUNEFI_IMPACTS = {
    "critical": "Direct theft of any user funds (at-rest or in-motion), permanent freezing of funds, protocol insolvency, or governance takeover",
    "high": "Theft of unclaimed yield/royalties, or temporary freezing of funds",
    "medium": "Contract unable to operate due to lack of token funds, griefing, or block stuffing",
    "low": "Contract fails to deliver promised returns, but does not lose value",
    "info": "Best-practice / informational - usually not eligible for a bounty",
}
BADGE = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🔵 Low", "info": "⚪ Info"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def _program_header(program: dict | None) -> list[str]:
    if not program:
        return []
    lines = [f"**Program:** {program.get('program', 'unknown')}  "]
    if program.get("platform"):
        lines.append(f"**Platform:** {program['platform']}  ")
    if program.get("submission_url"):
        lines.append(f"**Submit verified findings at:** {program['submission_url']}  ")
    if program.get("security_contact"):
        lines.append(f"**Security contact:** {program['security_contact']}  ")
    if program.get("max_bounty_usd"):
        lines.append(f"**Max bounty:** ${program['max_bounty_usd']:,}  ")
    if program.get("rules"):
        lines += ["", "**Program rules:**", *[f"- {r}" for r in program["rules"]]]
    return lines + [""]


def write_markdown(result: ScanResult, path: Path, program: dict | None = None) -> Path:
    counts = result.counts()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# bountyscan triage report",
        "",
        f"Generated {now} by bountyscan {__version__}. Targets: {', '.join(f'`{t}`' for t in result.targets)}  ",
        f"Files parsed: {len(result.files)} · Contracts: {sum(len(f.contracts) for f in result.files)}",
        "",
        *_program_header(program),
        "> **These are unverified candidates, not vulnerabilities.** Before reporting anything: read the code path,",
        "> confirm it is in scope, and prove impact with a PoC on a local fork (`templates/poc`). Submitting raw",
        "> scanner output is against the rules of every major bounty platform and gets accounts banned.",
        "",
        "## Summary",
        "",
        "| Severity | Count | Typical Immunefi impact |",
        "|---|---|---|",
        *[f"| {BADGE[s]} | {counts[s]} | {IMMUNEFI_IMPACTS[s]} |" for s in counts],
        "",
    ]
    if result.errors:
        lines += ["## Scan warnings", "", *[f"- {e}" for e in result.errors], ""]

    lines += ["## Findings", ""]
    if not result.findings:
        lines.append("No candidates found. That does not mean the code is safe - review business logic manually.")
    for i, f in enumerate(result.findings, 1):
        lines += [
            f"### {i}. {BADGE[f.severity]} - {f.title}",
            "",
            f"- **Location:** `{f.file}:{f.line}` - `{f.contract}.{f.function}`",
            f"- **Detector:** `{f.detector}` (confidence: {f.confidence})",
            "",
            f.description,
            "",
            *([f"```solidity\n{f.snippet}\n```", ""] if f.snippet else []),
            f"**Impact if confirmed:** {f.impact}",
            "",
            f"**Fix:** {f.recommendation}",
            "",
            *([f"**References:** {' · '.join(f.references)}", ""] if f.references else []),
            "- [ ] Reachable from an external call?  - [ ] In program scope?  - [ ] PoC passes on fork?",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_json(result: ScanResult, path: Path, program: dict | None = None) -> Path:
    payload = {
        "tool": "bountyscan", "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": program, "targets": result.targets,
        "summary": result.counts(), "errors": result.errors,
        "findings": [f.to_dict() for f in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_sarif(result: ScanResult, path: Path) -> Path:
    """SARIF 2.1.0 - upload with github/codeql-action/upload-sarif for GitHub code scanning."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = {d.id: d for d in DETECTORS}
    rule_ids = sorted({f.detector for f in result.findings})
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "bountyscan", "version": __version__,
                "informationUri": "https://github.com/Phaviwylera/cryptobountyprogram",
                "rules": [{
                    "id": rid,
                    "shortDescription": {"text": rules[rid].title if rid in rules else rid},
                    "help": {"text": rules[rid].recommendation if rid in rules else ""},
                } for rid in rule_ids],
            }},
            "results": [{
                "ruleId": f.detector,
                "level": level[f.severity],
                "message": {"text": f"[{f.severity.upper()}] {f.description}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)},
                }}],
            } for f in result.findings],
        }],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


SUBMISSION_TEMPLATE = """# {title}

<!-- DRAFT generated by bountyscan. Do NOT submit until every TODO is replaced with verified facts. -->

**Program:** {program}
**Submit to:** {submit_to}
**Proposed severity:** {severity} - {immunefi_impact}
**Asset / target:** {target}
**Location:** `{file}:{line}` (`{contract}.{function}`)

## Brief / Intro

TODO: one paragraph - what is broken and what an attacker gains (amount at risk in USD, which users).

## Vulnerability Details

{description}

```solidity
{snippet}
```

TODO: walk through the exact call path from an external entry point to the bug, with line references.

## Impact Details

{impact}

TODO: quantify - TVL/balances at risk at block N, funds an attacker can extract, preconditions.

## References

{references}

## Proof of Concept

TODO: paste the Foundry test from `templates/poc` adapted to this bug, plus the passing `forge test -vvv` output.
The PoC must run on a **local fork** (`--fork-url`), never against mainnet or a public testnet deployment.

```solidity
// test/Exploit.t.sol
```

## Recommended Fix

{recommendation}
"""


def write_submission_drafts(result: ScanResult, out_dir: Path, program: dict | None = None, min_severity: str = "medium") -> list[Path]:
    from .detectors import SEVERITY_RANK

    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    eligible = [f for f in result.findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[min_severity]]
    for i, f in enumerate(eligible, 1):
        p = out_dir / f"{i:02d}-{f.severity}-{_slug(f.detector)}-{_slug(f.contract)}.md"
        p.write_text(SUBMISSION_TEMPLATE.format(
            title=f"{f.title} in {f.contract}.{f.function}",
            program=(program or {}).get("program", "TODO"),
            submit_to=(program or {}).get("submission_url") or (program or {}).get("security_contact") or "TODO - see docs/DISCLOSURE.md",
            severity=f.severity.capitalize(),
            immunefi_impact=IMMUNEFI_IMPACTS[f.severity],
            target=", ".join(result.targets),
            file=f.file, line=f.line, contract=f.contract, function=f.function,
            description=f.description, snippet=f.snippet or "// TODO",
            impact=f.impact, recommendation=f.recommendation,
            references="\n".join(f"- {r}" for r in f.references) or "- TODO",
        ), encoding="utf-8")
        paths.append(p)
    return paths


def write_all(result: ScanResult, out_dir: Path, formats: set[str], program: dict | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if "md" in formats:
        written.append(write_markdown(result, out_dir / "report.md", program))
    if "json" in formats:
        written.append(write_json(result, out_dir / "findings.json", program))
    if "sarif" in formats:
        written.append(write_sarif(result, out_dir / "results.sarif"))
    if "drafts" in formats:
        written += write_submission_drafts(result, out_dir / "submissions", program)
    return written
