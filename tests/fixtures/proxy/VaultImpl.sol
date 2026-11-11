// An upgradeable implementation whose initialize() sets owner = msg.sender with no initializer guard.
// On a FRESH (non-proxy) scan this is a genuine front-runnable initializer and MUST flag.
// When the deployed address is a PROXY (meta.proxy == true) the initializer was already consumed at
// deploy and any re-call reverts, so the finding must be suppressed. Used by the proxy-suppression test.
pragma solidity ^0.8.0;

contract VaultImpl {
    address public owner;
    bool public isInversed;
    uint256 public maxSlippage;

    function initialize(address, bool isInversed_, uint256 maxSlippage_) external {
        owner = msg.sender;
        isInversed = isInversed_;
        maxSlippage = maxSlippage_;
    }
}
