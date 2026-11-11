// Privileged setter guarded by an inline AND-compound msg.sender check (set-once admin wiring,
// RelayContract.setController). The caller check is `if (msg.sender == initializer && controller == 0)`.
// Must NOT flag as "privileged function callable by anyone".
pragma solidity ^0.8.0;

contract RelayGuarded {
    address public controller;
    address public initializer;

    constructor() {
        initializer = msg.sender;
    }

    function setController(address candidate) public {
        if (msg.sender == initializer && controller == address(0)) {
            controller = candidate;
        }
    }
}
