// SPDX-License-Identifier: MIT
// Hardened counterpart used to check bountyscan for false positives.
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract SafeVault is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    uint256 private constant DECIMALS_OFFSET = 3;
    uint256 private constant MAX_DELAY = 1 hours;

    IERC20 public immutable asset;
    AggregatorV3Interface public feed;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public ethDeposits;

    constructor(IERC20 _asset) Ownable(msg.sender) {
        asset = _asset;
    }

    function depositEth() external payable {
        ethDeposits[msg.sender] += msg.value;
    }

    function withdrawEth() external nonReentrant {
        uint256 amount = ethDeposits[msg.sender];
        ethDeposits[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
    }

    function deposit(uint256 assets) external nonReentrant returns (uint256 shares) {
        shares = assets * (totalSupply + 10 ** DECIMALS_OFFSET) / (totalAssets + 1);
        asset.safeTransferFrom(msg.sender, address(this), assets);
        totalAssets += assets;
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external nonReentrant {
        uint256 assets = shares * (totalAssets + 1) / (totalSupply + 10 ** DECIMALS_OFFSET);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
        asset.safeTransfer(msg.sender, assets);
    }

    function setFeed(AggregatorV3Interface newFeed) external onlyOwner {
        feed = newFeed;
    }

    function price() external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(answer > 0 && block.timestamp - updatedAt < MAX_DELAY, "stale");
        return uint256(answer);
    }
}

// ERC1363-style transferAndCall / approveAndCall must NOT be flagged as flash callbacks.
contract SafeERC1363Like {
    mapping(address => uint256) public balanceOf;
    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool) {
        return true;
    }
    // A flash-swap callback that DOES verify the pool is safe.
    function uniswapV2Call(address sender, uint256 a0, uint256 a1, bytes calldata data) external {
        require(msg.sender == pair, "not pair");
        require(sender == address(this), "not self");
    }
    address public pair;
}
