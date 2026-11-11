// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Proxy forwarding to an immutable implementation + self-multicall
contract FixedProxy {
    address public immutable implementation;
    constructor(address impl) { implementation = impl; }
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory r) = address(this).delegatecall(data[i]);
            require(ok);
            results[i] = r;
        }
    }
    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
