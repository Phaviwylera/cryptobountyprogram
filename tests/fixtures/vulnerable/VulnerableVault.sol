// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE - test fixture for bountyscan. Never deploy.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract VulnerableVault {
    IERC20 public asset;
    address public owner;
    address public implementation;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public ethDeposits;
    bool private initialized_;

    function initialize(address _asset) external {
        asset = IERC20(_asset);
        owner = msg.sender;
    }

    // reentrancy: state written after the ETH call
    function withdrawEth() external {
        uint256 amount = ethDeposits[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        ethDeposits[msg.sender] = 0;
    }

    function depositEth() external payable {
        ethDeposits[msg.sender] += msg.value;
    }

    // first-depositor inflation + unchecked transferFrom + donation-manipulable rate
    function deposit(uint256 assets) external returns (uint256 shares) {
        if (totalSupply == 0) {
            shares = assets;
        } else {
            shares = assets * totalSupply / asset.balanceOf(address(this));
        }
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    // anyone can redirect the vault's tokens
    function withdrawTo(address to, uint256 amount) external {
        asset.transfer(to, amount);
    }

    // privileged setter without access control
    function setImplementation(address impl) external {
        implementation = impl;
    }

    // anyone can mint shares
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    // arbitrary call: drains every approval users gave this vault
    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: msg.value}(data);
        require(ok);
        return ret;
    }

    function upgradeAndCall(address impl, bytes calldata data) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = impl.delegatecall(data);
        require(ok);
    }

    function sendFee(address payable treasury, uint256 fee) external {
        require(msg.sender == owner);
        treasury.send(fee);
    }
}
