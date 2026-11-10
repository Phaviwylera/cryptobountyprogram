"""Optional: merge Slither results (https://github.com/crytic/slither) into bountyscan findings.

Slither needs a compilable project (Foundry/Hardhat or solc on PATH). If it is not
installed or fails, the scan continues with bountyscan's own detectors.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .detectors import Finding

IMPACT_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info", "Optimization": "info"}


def available() -> bool:
    return shutil.which("slither") is not None


def run_slither(target: Path) -> tuple[list[Finding], str | None]:
    if not available():
        return [], "slither not installed (pip install slither-analyzer)"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "slither.json"
        proc = subprocess.run(
            ["slither", str(target), "--json", str(out)],
            capture_output=True, text=True, timeout=900,
        )
        if not out.exists():
            return [], f"slither failed: {(proc.stderr or proc.stdout).strip()[-500:]}"
        data = json.loads(out.read_text(encoding="utf-8"))

    findings = []
    for d in (data.get("results") or {}).get("detectors", []):
        elems = d.get("elements") or [{}]
        sm = elems[0].get("source_mapping") or {}
        lines = sm.get("lines") or [0]
        parent = (elems[0].get("type_specific_fields") or {}).get("parent") or {}
        findings.append(Finding(
            detector=f"slither:{d.get('check')}",
            title=d.get("check", "slither"),
            severity=IMPACT_MAP.get(d.get("impact"), "info"),
            confidence=(d.get("confidence") or "medium").lower(),
            file=sm.get("filename_relative") or sm.get("filename_short") or "",
            line=lines[0],
            contract=parent.get("name", ""),
            function=elems[0].get("name", ""),
            description=(d.get("description") or "").strip(),
            impact="See Slither detector documentation.",
            recommendation="See Slither detector documentation.",
            snippet="",
            references=[f"https://github.com/crytic/slither/wiki/Detector-Documentation#{d.get('check')}"],
        ))
    return findings, None
