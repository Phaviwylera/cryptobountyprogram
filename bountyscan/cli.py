"""Command-line interface: `bountyscan scan|fetch|program|detectors`."""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .detectors import DETECTORS, SEVERITIES, SEVERITY_RANK
from .program import run_program
from .report import write_all
from .scanner import ScanResult, scan
from .sources import CHAIN_IDS, fetch_verified_source

FORMATS = {"md", "json", "sarif", "drafts"}


def _formats(value: str) -> set[str]:
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    bad = chosen - FORMATS
    if bad:
        raise argparse.ArgumentTypeError(f"unknown format(s) {sorted(bad)}; choose from {sorted(FORMATS)}")
    return chosen


def _ids(value: str | None) -> set[str] | None:
    return {v.strip() for v in value.split(",") if v.strip()} if value else None


def _add_scan_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", type=Path, default=Path("reports"), help="report directory root (default: reports/)")
    p.add_argument("--format", type=_formats, default={"md", "json", "sarif", "drafts"}, help="comma list of md,json,sarif,drafts")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity (CI use)")
    p.add_argument("--only", help="comma list of detector ids to run")
    p.add_argument("--exclude", help="comma list of detector ids to skip")
    p.add_argument("--include-deps", action="store_true", help="also scan lib/, node_modules/, tests and mocks")
    p.add_argument("--slither", action="store_true", help="also run Slither if installed and merge its findings")


def _print_summary(result: ScanResult, written: list[Path]) -> None:
    counts = result.counts()
    print(f"Parsed {len(result.files)} file(s), {sum(len(f.contracts) for f in result.files)} contract(s).")
    print("  ".join(f"{s.capitalize()}: {n}" for s, n in counts.items()))
    for f in result.findings[:15]:
        print(f"  [{f.severity.upper():8}] {f.file}:{f.line}  {f.contract}.{f.function}  - {f.title}")
    if len(result.findings) > 15:
        print(f"  ... {len(result.findings) - 15} more in the report")
    for e in result.errors:
        print(f"  warning: {e}", file=sys.stderr)
    if written:
        print(f"Reports: {written[0].parent}")


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if fail_on and any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[fail_on] for f in result.findings):
        return 1
    return 0


def _run_dir(root: Path, name: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return root / f"{re.sub(r'[^A-Za-z0-9_.-]+', '-', name).strip('-') or 'scan'}-{stamp}"


def cmd_scan(args) -> int:
    result = scan(args.paths, include_deps=args.include_deps, min_severity=args.min_severity,
                  only=_ids(args.only), exclude=_ids(args.exclude), use_slither=args.slither)
    written = write_all(result, _run_dir(args.out, args.name or Path(args.paths[0]).name), args.format)
    _print_summary(result, written)
    return _exit_code(result, args.fail_on)


def cmd_fetch(args) -> int:
    out = fetch_verified_source(args.address, args.chain, args.dest, args.api_key)
    print(f"Saved verified source to {out}")
    if args.scan:
        result = scan([out], min_severity="low")
        written = write_all(result, _run_dir(Path("reports"), f"{args.chain}-{args.address[:10]}"), {"md", "json", "sarif", "drafts"})
        _print_summary(result, written)
    return 0


def cmd_program(args) -> int:
    meta, result = run_program(args.scope, args.cache, args.api_key, include_deps=args.include_deps,
                               min_severity=args.min_severity, only=_ids(args.only), exclude=_ids(args.exclude),
                               use_slither=args.slither)
    written = write_all(result, _run_dir(args.out, meta.get("program", "program")), args.format, meta)
    _print_summary(result, written)
    if meta.get("submission_url"):
        print(f"After verifying a finding with a PoC, submit it at: {meta['submission_url']}")
    return _exit_code(result, args.fail_on)


def cmd_detectors(_args) -> int:
    for d in sorted(DETECTORS, key=lambda d: (SEVERITY_RANK[d.severity], d.id)):
        print(f"{d.severity:9} {d.id:34} {d.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bountyscan", description="Find fund-loss bug candidates in Solidity DeFi contracts.")
    p.add_argument("--version", action="version", version=f"bountyscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan local .sol files or directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--name", help="name used for the report folder")
    _add_scan_options(s)
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fetch", help="download a verified contract from an Etherscan-family explorer")
    f.add_argument("address")
    f.add_argument("--chain", default="ethereum", help=f"one of {', '.join(sorted(CHAIN_IDS))} or a chain id")
    f.add_argument("--dest", type=Path, default=Path(".bountyscan/onchain"))
    f.add_argument("--api-key", help="explorer API key (default: $ETHERSCAN_API_KEY)")
    f.add_argument("--scan", action="store_true", help="scan the downloaded source right away")
    f.set_defaults(func=cmd_fetch)

    g = sub.add_parser("program", help="fetch + scan every asset in a bounty program scope file")
    g.add_argument("scope", type=Path)
    g.add_argument("--cache", type=Path, default=Path(".bountyscan"))
    g.add_argument("--api-key", help="explorer API key (default: $ETHERSCAN_API_KEY)")
    _add_scan_options(g)
    g.set_defaults(func=cmd_program)

    d = sub.add_parser("detectors", help="list available detectors")
    d.set_defaults(func=cmd_detectors)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
