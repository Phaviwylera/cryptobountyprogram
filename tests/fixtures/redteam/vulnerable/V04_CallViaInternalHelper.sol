// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// External call lives in an internal helper (Compound doTransferOut style)
contract HelperCallVault {
    mapping(address => uint256) public shares;
    function deposit() external payable { shares[msg.sender] += msg.value; }
    function redeem(uint256 amount) external {
        require(shares[msg.sender] >= amount, "bal");
        _doTransferOut(payable(msg.sender), amount);
        shares[msg.sender] -= amount;
    }
    function _doTransferOut(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
}
