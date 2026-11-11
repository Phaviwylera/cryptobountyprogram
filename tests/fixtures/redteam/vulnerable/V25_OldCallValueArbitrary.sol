pragma solidity ^0.5.0;
// pre-0.6 arbitrary call with value: target.call.value(v)(data)
contract LegacyProxyWallet {
    function forward(address target, uint256 v, bytes memory data) public {
        (bool ok, ) = target.call.value(v)(data);
        require(ok);
    }
}
