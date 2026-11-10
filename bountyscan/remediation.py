"""Fund-theft bug classes: how each is exploited and how to fix it (with code).

Only detectors listed in FUND_THEFT are reported by `bountyscan auto`; everything else
(precision loss, randomness, unchecked returns, stale-oracle hygiene) is treated as a minor bug.
"""
from __future__ import annotations

REMEDIATION: dict[str, dict] = {
    "arbitrary-external-call": {
        "attack": [
            "Find users who approved this contract to spend their tokens (Approval events).",
            "Call the function with `target = token` and `data = transferFrom(victim, attacker, amount)`.",
            "The contract is the approved spender, so the token moves the victim's balance to the attacker.",
        ],
        "fix": """// Only allow known targets and selectors; never forward raw calldata from an approved spender.
mapping(address => bool) public allowedTarget;
mapping(bytes4 => bool) public allowedSelector;

function execute(address target, bytes calldata data) external {
    require(allowedTarget[target], "target");
    require(allowedSelector[bytes4(data[:4])], "selector");
    require(bytes4(data[:4]) != IERC20.transferFrom.selector, "no transferFrom");
    (bool ok, ) = target.call(data);
    require(ok, "call failed");
}""",
    },
    "arbitrary-recipient-withdrawal": {
        "attack": [
            "Call the withdraw/claim function with `to = attacker` and `amount = contract balance`.",
            "Nothing ties the payout to msg.sender's own balance, so the contract pays the attacker.",
        ],
        "fix": """function withdraw(address to, uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;          // debit the CALLER (reverts on underflow in >=0.8)
    token.safeTransfer(to, amount);
}""",
    },
    "controlled-delegatecall": {
        "attack": [
            "Deploy a contract whose function writes the owner slot / transfers all tokens to the attacker.",
            "Pass its address as the delegatecall target; it runs with this contract's storage and balance.",
        ],
        "fix": """address public immutable trustedImplementation;

function run(bytes calldata data) external onlyOwner {
    (bool ok, ) = trustedImplementation.delegatecall(data);   // fixed target, admin only
    require(ok);
}""",
    },
    "unprotected-initializer": {
        "attack": [
            "Call `initialize()` on the proxy (front-run deployment, or re-call it if there is no one-time guard).",
            "Set yourself as owner/admin, then upgrade to a malicious implementation or sweep funds.",
        ],
        "fix": """import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Vault is Initializable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
    }
}
// Deploy the proxy and call initialize in the SAME transaction (ERC1967Proxy(impl, initData)).""",
    },
    "unrestricted-mint": {
        "attack": [
            "Call `mint(attacker, hugeAmount)`.",
            "Sell the minted tokens into every pool, or redeem vault shares for the real underlying assets.",
        ],
        "fix": """bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}""",
    },
    "unrestricted-burn-from": {
        "attack": [
            "Call `burn(victimOrPool, amount)`: the victim's balance is destroyed.",
            "Burning an AMM pair's balance then calling sync() skews the price so the attacker can drain the other side.",
        ],
        "fix": """function burnFrom(address account, uint256 amount) external {
    _spendAllowance(account, msg.sender, amount);   // require approval from the owner
    _burn(account, amount);
}""",
    },
    "unvalidated-flash-callback": {
        "attack": [
            "Call the callback (e.g. `uniswapV3SwapCallback` / `onFlashLoan`) directly, not via a pool.",
            "Provide crafted data so the contract pays 'the pool' (attacker) or performs actions with its own funds.",
        ],
        "fix": """function uniswapV3SwapCallback(int256 a0, int256 a1, bytes calldata data) external {
    require(msg.sender == expectedPool, "not pool");          // or verify via the factory's computeAddress
    ...
}

function onFlashLoan(address initiator, address, uint256, uint256, bytes calldata) external returns (bytes32) {
    require(msg.sender == address(lender), "not lender");
    require(initiator == address(this), "not self-initiated");
    ...
}""",
    },
    "unprotected-selfdestruct": {
        "attack": [
            "Call the function: the contract's ETH is sent to the attacker (and pre-Cancun the code is deleted, bricking dependents).",
        ],
        "fix": """// Remove selfdestruct entirely. If an emergency exit is needed, use a pausable, timelocked admin withdrawal.""",
    },
    "unprotected-privileged-function": {
        "attack": [
            "Call the admin function directly: e.g. set the oracle/price to an attacker value, change the owner, upgrade the implementation, or sweep balances.",
            "Use the new privilege to drain the protocol in the same transaction.",
        ],
        "fix": """function setOracle(address newOracle) external onlyOwner {   // or onlyRole(ADMIN_ROLE) behind a timelock
    oracle = IOracle(newOracle);
}""",
    },
    "reentrancy": {
        "attack": [
            "Deposit from an attacker contract, then call the withdraw function.",
            "When ETH arrives, the attacker's receive() calls withdraw again before the balance is set to 0.",
            "Repeat until the contract is empty.",
        ],
        "fix": """function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;                         // effects BEFORE interactions
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}""",
    },
    "spot-price-oracle": {
        "attack": [
            "Flash-loan a large amount and swap it into the pool the contract reads (getReserves/slot0).",
            "The contract now sees an inflated collateral price: borrow/mint far more than the collateral is worth.",
            "Swap back, repay the flash loan, keep the difference. All in one transaction.",
        ],
        "fix": """// Chainlink with sanity checks, or a long Uniswap V3 TWAP (>= 30 min) - never instantaneous reserves.
(, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
require(answer > 0, "bad price");
require(block.timestamp - updatedAt <= HEARTBEAT, "stale price");
uint256 price = uint256(answer);""",
    },
    "erc4626-inflation": {
        "attack": [
            "Be the first depositor: deposit 1 wei to get 1 share.",
            "Transfer a large amount of the asset directly to the vault (donation), inflating the price per share.",
            "The next depositor's shares round down to 0; the attacker redeems the 1 share for everything.",
        ],
        "fix": """// OpenZeppelin ERC4626 with a decimals offset (virtual shares) makes the attack unprofitable.
contract Vault is ERC4626 {
    function _decimalsOffset() internal pure override returns (uint8) { return 6; }
}
// Alternatively mint dead shares to address(1) on first deposit and track assets internally.""",
    },
    "missing-slippage-protection": {
        "attack": [
            "Watch the mempool for the contract's swap (or trigger it yourself when it is public).",
            "Sandwich it: buy before, let the contract swap at a terrible price with amountOutMin = 0, sell after.",
        ],
        "fix": """uint256 expected = oracle.quote(amountIn);
uint256 minOut = expected * (10_000 - maxSlippageBps) / 10_000;
router.swapExactTokensForTokens(amountIn, minOut, path, address(this), block.timestamp + 300);""",
    },
    "signature-replay": {
        "attack": [
            "Copy a valid signature from a past transaction (it is public on-chain).",
            "Submit it again - same chain (no nonce) or on another chain/fork (no chainid) - to repeat the withdrawal/claim.",
        ],
        "fix": """// EIP-712 binds chainid + this contract; the nonce makes every signature single-use.
bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount, nonces[signer]++, deadline));
address recovered = ECDSA.recover(_hashTypedDataV4(structHash), signature);   // reverts on invalid/zero
require(recovered == signer && block.timestamp <= deadline, "bad sig");""",
    },
    "tx-origin-auth": {
        "attack": [
            "Lure the owner into calling any attacker contract (airdrop claim, NFT mint).",
            "That contract calls the victim contract; tx.origin is still the owner, so the check passes and funds are withdrawn.",
        ],
        "fix": """require(msg.sender == owner, "not owner");   // never tx.origin for authorization""",
    },
    "pre-0.8-overflow": {
        "attack": [
            "Pick inputs that overflow the multiplication/addition (e.g. 2 receivers x 2^255).",
            "The bounds check passes on the wrapped (tiny) value while each receiver is credited a huge balance.",
        ],
        "fix": """// Upgrade to Solidity >= 0.8 (checked arithmetic by default), or use SafeMath everywhere:
uint256 amount = _value.mul(cnt);
balances[msg.sender] = balances[msg.sender].sub(amount);""",
    },
}

FUND_THEFT = set(REMEDIATION)
FUND_THEFT_SEVERITIES = {"critical", "high"}


def is_fund_theft(finding) -> bool:
    return finding.detector in FUND_THEFT and finding.severity in FUND_THEFT_SEVERITIES
