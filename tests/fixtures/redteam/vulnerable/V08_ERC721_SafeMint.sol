// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC721Receiver { function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4); }
// HypeBears / Omni style: per-wallet limit updated after _safeMint (onERC721Received re-enters)
contract LimitedMint {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public mintedBy;
    uint256 public nextId;
    function mint() external payable {
        require(msg.value == 0.1 ether && mintedBy[msg.sender] == 0, "limit");
        _safeMint(msg.sender, nextId);
        nextId++;
        mintedBy[msg.sender] += 1;
    }
    function _safeMint(address to, uint256 id) internal {
        ownerOf[id] = to;
        if (to.code.length > 0) IERC721Receiver(to).onERC721Received(msg.sender, address(0), id, "");
    }
}
