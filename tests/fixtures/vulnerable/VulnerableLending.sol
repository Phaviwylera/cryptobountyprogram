// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE - test fixture for bountyscan. Never deploy.
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

interface IRouter {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline)
        external returns (uint256[] memory);
}

contract VulnerableLending {
    IUniswapV2Pair public pair;
    AggregatorV3Interface public feed;
    IRouter public router;
    address public lender;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public nonces;

    // spot price oracle: flash-loan manipulable
    function collateralPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    // Chainlink without staleness check
    function feedPrice() public view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return uint256(answer);
    }

    // zero slippage, triggerable by anyone
    function harvest(uint256 amount, address[] calldata path) external {
        router.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp);
    }

    // callback with no msg.sender check
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        collateral[initiator] += amount;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // signature without nonce/chainid and without zero-address check
    function withdrawWithSig(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer == lender, "bad sig");
        payable(to).transfer(amount);
    }

    function lottery() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }

    function interest(uint256 principal, uint256 rate, uint256 time) external pure returns (uint256) {
        return principal / 10000 * rate * time;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
