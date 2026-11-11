// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Socket WrappedTokenSwapperImpl (Jan 2024): fromToken.call(swapExtraData)
contract SocketLikeImpl {
    function performAction(address fromToken, address toToken, uint256 amount, address receiverAddress, bytes32 metadata, bytes calldata swapExtraData) external payable returns (uint256) {
        (bool success, ) = fromToken.call(swapExtraData);
        require(success, "swap");
        toToken; amount; receiverAddress; metadata;
        return 0;
    }
}
