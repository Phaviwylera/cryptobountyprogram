// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PluginHost {
    address public owner = msg.sender;
    function runPlugin(address plugin, bytes calldata data) external {
        (bool ok, ) = plugin.delegatecall(data);
        require(ok);
    }
}
