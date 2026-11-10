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


def _store(args):
    from .state import Store
    return Store(args.state)


def cmd_auto(args) -> int:
    import os

    from .auto import AutoConfig, discover_blocks, parse_address_lines, run_queue, watch
    from .program import load_scope
    from .rpc import RPC
    from .sources import ExplorerFatal

    store = _store(args)
    rpc_url = args.rpc_url or os.environ.get("RPC_URL")
    rpc = RPC(rpc_url) if rpc_url else None
    cfg = AutoConfig(out_dir=args.out, cache_dir=args.cache, api_key=args.api_key, rpc=rpc,
                     min_balance_wei=int(args.min_balance * 10**18))

    added = 0
    for f in args.addresses or []:
        for chain, addr in parse_address_lines(Path(f).read_text(encoding="utf-8"), args.chain):
            added += store.enqueue(chain, addr, f"list:{Path(f).name}")
    for s in args.scope or []:
        scope = load_scope(Path(s))
        for a in scope["assets"]:
            if "address" in a:
                added += store.enqueue(a["chain"], a["address"], f"program:{scope['program']}")
    for a in args.address or []:
        chain, addr = parse_address_lines(a, args.chain)[0]
        added += store.enqueue(chain, addr, "cli")
    if args.retry_errors:
        print(f"Re-queued {store.reset({'error'})} errored contract(s).")

    needs_rpc = args.watch or args.from_block is not None
    if needs_rpc and rpc is None:
        print("error: --watch/--from-block need an RPC endpoint (--rpc-url or $RPC_URL)", file=sys.stderr)
        return 2
    try:
        if args.from_block is not None and not args.watch:
            end = args.to_block if args.to_block is not None else rpc.block_number()
            print(f"Discovering contracts deployed in {args.chain} blocks {args.from_block}..{end}")
            added += discover_blocks(store, rpc, args.chain, args.from_block, end, cfg)
        print(f"Queued {added} new contract(s); {store.pending_count()} pending in total.")
        if args.watch:
            watch(store, rpc, args.chain, cfg, poll=args.poll, from_block=args.from_block)
        else:
            tally = run_queue(store, cfg, limit=args.limit)
            print("This run: " + (", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "nothing due"))
    except ExplorerFatal as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped. Progress is saved; run the same command to continue.")
    print(f"Summary: {args.out / 'SUMMARY.md'}")
    return 1 if args.fail_on_vulnerable and store.counts().get("vulnerable") else 0


def cmd_serve(args) -> int:
    import os

    from .server import serve
    serve(args.host, args.port, args.out, args.cache, args.state,
          args.api_key or os.environ.get("ETHERSCAN_API_KEY"),
          args.rpc_url or os.environ.get("RPC_URL"), verify=not args.no_verify)
    return 0


def cmd_status(args) -> int:
    store = _store(args)
    counts = store.counts()
    print("  ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "queue is empty")
    for r in store.by_status("vulnerable"):
        print(f"  VULNERABLE [{r['max_severity']}] {r['chain']}:{r['address']} {r['name'] or ''} -> {r['report']}")
    if args.errors:
        for r in store.by_status("error"):
            print(f"  ERROR {r['chain']}:{r['address']}: {r['error']}")
    return 0


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

    a = sub.add_parser("auto", help="scan contracts one after another: SAFE / VULNERABLE (fund theft only)")
    a.add_argument("--addresses", action="append", help="file with one `0x...` or `chain:0x...` per line (repeatable)")
    a.add_argument("--address", action="append", help="single address (repeatable)")
    a.add_argument("--scope", action="append", help="program scope JSON; its address assets are queued (repeatable)")
    a.add_argument("--chain", default="ethereum", help="default chain for addresses and block discovery")
    a.add_argument("--from-block", type=int, help="discover contracts deployed from this block")
    a.add_argument("--to-block", type=int, help="last block to discover (default: chain head)")
    a.add_argument("--watch", action="store_true", help="keep following new blocks and scan every new contract")
    a.add_argument("--poll", type=float, default=15.0, help="seconds between polls in --watch (default 15)")
    a.add_argument("--rpc-url", help="JSON-RPC endpoint (default: $RPC_URL)")
    a.add_argument("--api-key", help="explorer API key (default: $ETHERSCAN_API_KEY)")
    a.add_argument("--min-balance", type=float, default=0.0, help="skip contracts holding less native coin than this (needs RPC)")
    a.add_argument("--limit", type=int, help="process at most N contracts this run")
    a.add_argument("--retry-errors", action="store_true", help="re-queue contracts that errored before")
    a.add_argument("--fail-on-vulnerable", action="store_true", help="exit 1 if any contract is VULNERABLE")
    a.add_argument("--out", type=Path, default=Path("reports/auto"))
    a.add_argument("--cache", type=Path, default=Path(".bountyscan"))
    a.add_argument("--state", type=Path, default=Path(".bountyscan/state.db"))
    a.set_defaults(func=cmd_auto)

    sv = sub.add_parser("serve", help="run the web dashboard (Live Scan + Immunefi Scan buttons)")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 behind a reverse proxy)")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--rpc-url", help="JSON-RPC endpoint for live scan (default: $RPC_URL)")
    sv.add_argument("--api-key", help="explorer API key (default: $ETHERSCAN_API_KEY)")
    sv.add_argument("--no-verify", action="store_true", help="skip the independent confirmation pass")
    sv.add_argument("--out", type=Path, default=Path("reports/auto"))
    sv.add_argument("--cache", type=Path, default=Path(".bountyscan"))
    sv.add_argument("--state", type=Path, default=Path(".bountyscan/state.db"))
    sv.set_defaults(func=cmd_serve)

    st = sub.add_parser("status", help="show auto-scan progress and vulnerable contracts")
    st.add_argument("--state", type=Path, default=Path(".bountyscan/state.db"))
    st.add_argument("--errors", action="store_true", help="also list errored contracts")
    st.set_defaults(func=cmd_status)

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
