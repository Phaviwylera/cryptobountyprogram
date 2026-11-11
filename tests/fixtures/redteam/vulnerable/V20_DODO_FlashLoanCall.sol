// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// DODO DVM/DPP flash-loan callbacks are not in FLASH_CALLBACKS
contract DodoArb {
    function DVMFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        (address token, address to, uint256 amt) = abi.decode(data, (address, address, uint256));
        IERC20(token).transfer(to, amt);
        sender; baseAmount; quoteAmount;
    }
    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        (address token, address to, uint256 amt) = abi.decode(data, (address, address, uint256));
        IERC20(token).transfer(to, amt);
        sender; baseAmount; quoteAmount;
    }
}
