"""Scan orchestration: collect sources, parse, run detectors, optionally merge Slither."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import slither_bridge
from .detectors import SEVERITY_RANK, Finding, run_detectors
from .solidity import SourceFile, parse_source
from .sources import collect_files


@dataclass
class ScanResult:
    targets: list[str]
    files: list[SourceFile]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_RANK}
        for f in self.findings:
            out[f.severity] += 1
        return out


def relevant_contracts(files: list[SourceFile], roots: list[str]) -> set[str] | None:
    """The deployed contract(s) plus everything they inherit from.

    Verified bundles often include mocks, tests and unrelated contracts; findings there are not
    findings in the deployed code. Returns None (= don't filter) when no root can be located."""
    by_name = {}
    for f in files:
        for c in f.contracts:
            by_name.setdefault(c.name, c)
    todo = [r for r in roots if r in by_name]
    if not todo:
        return None
    seen: set[str] = set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        c = by_name.get(name)
        if c:
            todo += [i.split(".")[-1].strip() for i in c.inherits]
    return seen


def scan(
    paths: list[str | Path],
    include_deps: bool = False,
    min_severity: str = "low",
    only: set[str] | None = None,
    exclude: set[str] | None = None,
    use_slither: bool = False,
    meta: dict | None = None,
) -> ScanResult:
    errors: list[str] = []
    files: list[SourceFile] = []
    for path in collect_files(paths, include_deps=include_deps):
        try:
            files.append(parse_source(path, display=path.as_posix()))
        except Exception as exc:  # keep scanning other files
            errors.append(f"{path}: parse error: {exc}")

    findings = run_detectors(files, only=only, exclude=exclude, meta=meta)
    if use_slither:
        for p in map(Path, paths):
            extra, err = slither_bridge.run_slither(p)
            findings.extend(extra)
            if err:
                errors.append(err)

    limit = SEVERITY_RANK[min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= limit]
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line))
    return ScanResult([str(p) for p in paths], files, findings, errors)
