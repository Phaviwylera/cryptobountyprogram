// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Uniswap V2-pair style `lock` modifier using a uint unlocked flag
contract PairLike {
    uint256 private unlocked = 1;
    modifier lock() { require(unlocked == 1, "LOCKED"); unlocked = 0; _; unlocked = 1; }
    uint256 public reserve;
    function skim(address payable to) external lock {
        (bool ok, ) = to.call{value: address(this).balance - reserve}("");
        require(ok);
        reserve = address(this).balance;
    }
}
