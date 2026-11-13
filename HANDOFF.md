# BountyScan — Project Handoff / State

Read this first on any machine to get full context. Pairs with the code in this repo.

## What it is
A Solidity fund-theft vulnerability scanner, deployed 24/7 on AWS EC2. Three-pass pipeline:
**static detectors → independent verifier → dynamic Foundry payload attack** on a mainnet fork.
A finding is only trustworthy when the payload proves it (funds actually move to the attacker wallet).

## Access (secrets are NOT in this repo — keep them in your own password manager)
- **Dashboard URL:** https://44-195-62-179.sslip.io/  (HTTPS, Let's Encrypt; HTTP redirects to HTTPS)
- **Login:** basic auth, user `admin` (password kept out of git — see your notes / ask).
- **EC2:** instance `i-036d7ea8313de9c22`, region `us-east-1`, managed via AWS SSM (no SSH needed).
- **Service:** systemd `bountyscan`, venv at `/opt/cryptobountyprogram/.venv`, repo at `/opt/cryptobountyprogram`.
- **Auto-deploy:** push to `main` → a timer pulls, runs the test suite, and switches versions (rollback on failure).
- **Forge:** `/home/ec2-user/.foundry/bin/forge`; RPC in `deploy/bountyscan.env` (`RPC_URL`, untracked).
- **Attacker/receiving wallet:** `0xE4754d8237C9528FC23E81F9BB8F0aEE9B646bF8` (payloads route stolen funds here).

## Architecture (code map)
- `bountyscan/detectors.py` — static fund-theft detectors + guard recognition (access control, set-once init,
  multi-principal `owner||dev`, external auth predicates).
- `bountyscan/verifier.py` — independent second-pass confirmation.
- `bountyscan/forge_verify.py` — dynamic payload engine: one-shot payloads, Tier-1 overflow (two-pass),
  Tier-3 historical signature replay, and the multi-step takeover→drain chain.
- `bountyscan/auto.py` / `server.py` — the scan loop, queue, API, and dashboard.
- `bountyscan/ui.py` — the live dashboard (CONTRACT JOURNEY widget, HUD, findings table).
- `tests/` — unit + red-team corpus; the auto-deploy gate runs these before switching versions.

## What is built and live
- FP elimination across many classes (proxy initializers, parser bugs, `owner||dev` guards, ERC-7540
  operator checks, `require(!initialized)` set-once, tx-origin, etc.).
- **Tier-1 overflow** — validated live on AkivaCoin (drains to the wallet; verdict THEORETICAL — needs 2^240 tokens).
- **Tier-3 signature replay** — validated live on RelayContract (FALSE POSITIVE, correctly dropped).
- **Phase-2/4 CFG guards** — validated live on XaurumProxy (8 FPs → 0) and UserWallet (0).
- **Multi-step takeover→drain chain** — seizes owner/role then drains; confirms only on a fork-proven
  200% differential (wallet gains AND target loses).

## Honest status (important)
The dynamic payload has confirmed **0 unconditional real drains** on live mainnet; the 2 positives are
THEORETICAL overflows. "AT RISK $" = value held by LATENT candidates, not proven-stealable funds. The tool
is currently a strong **low-noise triage / monitoring** engine, not yet an autonomous **exploit confirmer**.
Reason: real theft on already-deployed, picked-over mainnet is usually multi-step and mostly already drained.

## Highest-yield next work (pick one)
1. **Fresh-deployment priority** — scan newly-verified contracts in their first hours (theft hasn't happened yet).
2. **Per-class multi-step chains** — reentrancy attacker-contract; arbitrary-transferFrom victim-allowance;
   funded-position withdrawal. (The value-holding findings cluster in these classes, not privileged-function.)
3. **Proof/signature-guard modeling** — stop FPs on bridge `claim`-style functions (e.g. the $15k KalqiXBridge FP).

## Working across two computers
- Code: this GitHub repo — clone on either machine.
- Running system: the dashboard URL above — same on any machine.
- The Claude Code chat transcript itself is local to each machine and does not sync; start a fresh session
  on the other computer and point it at this file for context.
