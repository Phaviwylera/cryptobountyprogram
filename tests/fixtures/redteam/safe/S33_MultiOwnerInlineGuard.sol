// SAFE: privileged setters guarded by a multi-principal inline check
// `if (msg.sender == owner || msg.sender == dev)` (Xaurum XaurumProxyERC20 pattern).
// Both OR-branches are msg.sender comparisons, so admission requires a privileged caller -> not unprotected.
pragma solidity ^0.4.24;

contract MultiOwnerGuarded {
    address owner;
    address dev;
    address public meltingContract;
    address public dataContract;

    function MultiOwnerGuarded() public { owner = msg.sender; dev = msg.sender; }

    function setMeltingContract(address _c) public {
        if (msg.sender == owner || msg.sender == dev) {
            meltingContract = _c;
        }
    }

    function setDataContract(address _c) public {
        if (msg.sender == owner || msg.sender == dev) {
            dataContract = _c;
        }
    }
}
