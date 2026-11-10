# Where and how to report

bountyscan finds **candidates**. A report goes out only after you have confirmed the bug yourself.
Follow these steps in order.

## 1. Verify before you report

1. **Is it in scope?** Look the address or repo up on the program page. Out-of-scope reports are closed without payment.
2. **Is it reachable?** Trace an external call path from an unprivileged account to the bug. Many findings sit behind an
   `onlyOwner` in a parent contract, a modifier the scanner did not resolve, or a function that is never deployed.
3. **Is it a known issue?** Check the program's "known issues" list, past audit reports, and their acknowledged findings.
4. **Prove impact with a PoC** on a local fork using `templates/poc`:
   ```bash
   forge test --fork-url "$RPC_URL" --fork-block-number <N> -vvv
   ```
   Put numbers on it, such as attacker profit and protocol or user loss at block N.
5. **Never touch a live deployment.** Do not send exploit transactions, even "small test" ones, to mainnet or to a project's
   public testnet. Doing so is theft or unauthorized access, and it disqualifies you.

## 2. Find the right channel (in priority order)

| Where | When |
|---|---|
| The project's own bounty page on **Immunefi** (`immunefi.com/bug-bounty/<slug>`) | Most DeFi protocols. Submit through the dashboard. Use the draft from `submissions/`. |
| **HackenProof**, **Cantina** bounties, **Sherlock** bounties, **Code4rena** bounties | When the project lists its program there. |
| The project's `SECURITY.md`, `security.txt`, or `security@` email | No platform program. Encrypt with their PGP key if they publish one. |
| **GitHub private vulnerability reporting** ("Security → Report a vulnerability") | Open-source repos that have it enabled. |
| **SEAL 911** (Security Alliance emergency line, `securityalliance.org`) | An exploit is **actively happening** or funds are at immediate risk and you cannot reach the team. |
| **Audit contests** (Code4rena, Sherlock, Cantina) | Code under a live contest goes to the contest, not to bounties. |

Before you search for a contact, put the `submission_url` / `security_contact` for each program in its scope file
(`programs/*.json`). Every report bountyscan writes for that program then names the right destination.

## 3. Write the report

Fill in `reports/<run>/submissions/NN-*.md` and replace every TODO:

- **Title:** the bug class, the contract and the impact, e.g. "Unprotected `withdrawTo` lets anyone drain Vault USDC".
- **Severity:** use the program's own classification table. Immunefi v2.3 is mapped in the report header.
  Pick the lowest severity your PoC actually proves. Inflating it gets reports closed.
- **Root cause, call path, impact with numbers, PoC code and output, recommended fix.**
- Keep it private until the program confirms a fix and agrees to disclosure.

## 4. What not to do

- Do not paste raw scanner output. Platforms ban accounts for it.
- Do not demand payment, set deadlines as threats, or threaten public disclosure. That is extortion and voids safe harbor.
- Do not use funds or data you obtained while testing. If you accidentally gain access to anything, stop and report it.
