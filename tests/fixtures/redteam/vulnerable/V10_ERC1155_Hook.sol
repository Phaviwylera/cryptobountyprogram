// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC1155 { function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external; }
// ERC1155 onERC1155Received re-entry before the claim flag is set
contract Claim1155 {
    IERC1155 public immutable items;
    mapping(address => bool) public claimed;
    constructor(IERC1155 i) { items = i; }
    function claim() external {
        require(!claimed[msg.sender], "claimed");
        items.safeTransferFrom(address(this), msg.sender, 1, 1, "");
        claimed[msg.sender] = true;
    }
}
