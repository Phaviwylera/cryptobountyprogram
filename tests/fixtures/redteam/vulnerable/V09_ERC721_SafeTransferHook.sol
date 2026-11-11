// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC721 { function safeTransferFrom(address, address, uint256) external; function transferFrom(address, address, uint256) external; }
// NFT staking: safeTransferFrom calls onERC721Received on the receiver before the stake is cleared
contract NftStaking {
    IERC721 public immutable nft;
    mapping(uint256 => address) public stakerOf;
    mapping(address => uint256) public rewards;
    constructor(IERC721 n) { nft = n; }
    function stake(uint256 id) external { nft.transferFrom(msg.sender, address(this), id); stakerOf[id] = msg.sender; }
    function unstake(uint256 id) external {
        require(stakerOf[id] == msg.sender, "owner");
        nft.safeTransferFrom(address(this), msg.sender, id);
        rewards[msg.sender] += 100e18;
        delete stakerOf[id];
    }
}
