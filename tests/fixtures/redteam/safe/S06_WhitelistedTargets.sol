// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Aggregator that only calls governance-whitelisted routers with whitelisted selectors
contract WhitelistedAggregator {
    address public immutable governance;
    mapping(address => bool) public isApprovedRouter;
    mapping(bytes4 => bool) public isApprovedSelector;
    constructor(address g) { governance = g; }
    function setRouter(address r, bool ok) external { require(msg.sender == governance); isApprovedRouter[r] = ok; }
    function swap(address router, bytes calldata routerData) external payable {
        require(isApprovedRouter[router], "router");
        require(isApprovedSelector[bytes4(routerData[:4])], "selector");
        (bool ok, ) = router.call{value: msg.value}(routerData);
        require(ok, "swap");
    }
}
