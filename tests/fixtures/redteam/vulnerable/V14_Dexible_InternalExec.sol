// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Dexible selfSwap (Feb 2023): router + routerData forwarded through an internal helper
contract DexibleLike {
    function selfSwap(address router, address spender, bytes calldata routerData) external {
        _fill(router, routerData);
        spender;
    }
    function _fill(address router, bytes calldata data) internal {
        (bool ok, ) = router.call(data);
        require(ok, "fill");
    }
}
