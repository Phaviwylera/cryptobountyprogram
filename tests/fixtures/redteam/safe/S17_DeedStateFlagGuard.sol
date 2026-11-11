// Deed-style one-shot teardown: selfdestruct has no local modifier, BUT:
//  1. gated by `if (active) throw;` state flag at entry
//  2. `active` is only ever flipped by `closeDeed()` which is `onlyRegistrar`
//  3. beneficiary `burn` is a constant, NOT caller-controlled
// This is the ENS Deed pattern and is NOT a fund-theft path.
pragma solidity ^0.4.11;

contract Deed {
    address constant burn = 0xdead000000000000000000000000000000000000;
    address public registrar;
    address public owner;
    bool public active = true;

    modifier onlyRegistrar { if (msg.sender != registrar) throw; _; }

    function Deed(address _registrar, address _owner) public {
        registrar = _registrar;
        owner = _owner;
    }

    function closeDeed(uint refundRatio) onlyRegistrar {
        active = false;
        if (!burn.send(((1000 - refundRatio) * this.balance) / 1000)) throw;
        destroyDeed();
    }

    function destroyDeed() {
        if (active) throw;
        if (owner.send(this.balance)) {
            selfdestruct(burn);
        }
    }
}
