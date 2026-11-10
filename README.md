# cryptobountyprogram

A toolkit for **hunting fund-theft bugs in DeFi smart contracts and reporting them responsibly**.
It covers lending markets, vaults, AMM pools, bridges and token contracts.

- **`bountyscan`** scans Solidity source, either local or verified on-chain via Etherscan, for the bug classes behind most
  large DeFi losses. It writes a triage report plus Immunefi-style submission drafts.
- **Program scope files** (`programs/*.json`) list each bounty's in-scope assets and where to submit.
  One command fetches and scans all of them.
- **A Foundry PoC template** (`templates/poc`) proves impact on a local fork, which is what triagers pay for.
- **The [disclosure guide](docs/DISCLOSURE.md)** covers where to send a confirmed bug and what never to do.

> bountyscan produces **candidates**. Every finding must be manually verified and proven with a fork PoC before it is
> reported. Never run exploit code against live contracts. That is theft, not bounty hunting.

## Install

```bash
git clone https://github.com/Phaviwylera/cryptobountyprogram && cd cryptobountyprogram
pip install -e .            # zero runtime dependencies (Python >= 3.10)
pip install -e .[slither]   # optional: merge Slither results with --slither
```

## Use

```bash
# 1. Scan a local repo (skips lib/, node_modules/, tests, mocks by default)
bountyscan scan path/to/protocol/src

# 2. Pull verified source for a deployed contract (follows proxies) and scan it
export ETHERSCAN_API_KEY=...        # free key; Etherscan V2 covers ethereum, bsc, arbitrum, base, polygon, ...
bountyscan fetch 0xYourTarget --chain arbitrum --scan

# 3. Run a whole bounty program from its scope file
cp programs/example-scope.json programs/acme.json   # fill in assets + submission_url from the program page
bountyscan program programs/acme.json

# CI gate: non-zero exit if anything critical/high is found; SARIF for GitHub code scanning
bountyscan scan src --fail-on high --format sarif

bountyscan detectors                 # list every check
```

Each run writes `reports/<name>-<timestamp>/`:

| File | Purpose |
|---|---|
| `report.md` | Triage report sorted by severity, with Immunefi impact mapping and a verification checklist per finding |
| `findings.json` | Machine-readable findings |
| `results.sarif` | Upload to GitHub code scanning |
| `submissions/NN-*.md` | One report draft per medium+ finding, pre-addressed to the program's submission URL |

## What it looks for

| Severity | Detector | Bug class |
|---|---|---|
| Critical | `arbitrary-external-call` | `target.call(data)` with caller-controlled target and calldata drains user approvals |
| Critical | `arbitrary-recipient-withdrawal` | Withdraw/claim pays a caller-chosen address without checking the caller |
| Critical | `controlled-delegatecall` | delegatecall to a parameter address |
| Critical | `unprotected-initializer` | Proxy initializer that anyone can call, or call again |
| Critical | `unrestricted-mint` / `unrestricted-burn-from` | Free mint, or burning other people's tokens |
| Critical | `unvalidated-flash-callback` | `onFlashLoan` / `uniswapV3SwapCallback` etc. that never authenticate the caller |
| Critical | `unprotected-selfdestruct` | Anyone can destroy the contract |
| High/Crit | `unprotected-privileged-function` | Upgrade, ownership, oracle/price, sweep or rescue functions without access control |
| High | `reentrancy` | State written after an external ETH call, with no guard |
| High | `spot-price-oracle` | Prices taken from `getReserves()` / `slot0()`, which flash loans can manipulate |
| High | `erc4626-inflation` | First-depositor share-inflation attack |
| High | `missing-slippage-protection` | Swaps with `amountOutMin = 0` that bots can sandwich |
| High | `signature-replay` | Signature checks with no nonce, or no chainid |
| High | `tx-origin-auth`, `pre-0.8-overflow` | Classic auth and overflow bugs |
| Medium | `chainlink-stale-price`, `donation-manipulable-rate`, `unchecked-erc20-transfer`, `unchecked-low-level-call`, `uninitialized-implementation`, `weak-randomness` | |
| Low | `divide-before-multiply` | Precision loss |

**Accuracy:** on the vulnerable fixtures in `tests/fixtures/vulnerable`, every planted bug is detected, and the hardened
`tests/fixtures/safe` vault produces zero findings. On OpenZeppelin Contracts (250 production files with default
exclusions) it reports a single low-severity note. Heuristics still miss logic bugs, such as wrong math or a broken
invariant. Use the scanner to decide where to read first, not as a substitute for reading the code.

## Workflow

```
scope file -> bountyscan program -> read report.md -> confirm the call path by hand
     -> PoC in templates/poc on a fork -> fill submissions/NN-*.md -> submit at the program's URL
```

See [docs/DISCLOSURE.md](docs/DISCLOSURE.md) for where to report. It covers the project's bounty platform,
`SECURITY.md`, GitHub private advisories, and SEAL 911 for live incidents.

## Development

```bash
python -m unittest discover -s tests -v
```

To add a detector, write a function decorated with `@detector(...)` in `bountyscan/detectors.py`. Then add a vulnerable
snippet to `tests/fixtures/vulnerable` and make sure `tests/fixtures/safe` stays clean.
