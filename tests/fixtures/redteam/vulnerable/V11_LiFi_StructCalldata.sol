// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// LI.FI (Mar 2022 / Jul 2024): callTo + callData come from a caller-supplied struct array
contract LiFiLikeSwapper {
    struct SwapData { address callTo; address approveTo; address sendingAssetId; address receivingAssetId; uint256 fromAmount; bytes callData; }
    function swapTokensGeneric(bytes32 txId, address receiver, SwapData[] calldata swaps) external payable {
        for (uint256 i = 0; i < swaps.length; i++) {
            (bool success, ) = swaps[i].callTo.call{value: msg.value}(swaps[i].callData);
            require(success, "swap failed");
        }
        txId; receiver;
    }
}
