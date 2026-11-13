// SAFE: a privileged setter protected by a set-once initialization guard.
// `require(!initialized)` means it can run exactly once (at init) and reverts ever after, so it is not
// exploitable on a live contract - the same reasoning as proxy-initializer suppression.
pragma solidity ^0.8.0;

contract SetOnceInit {
    bool initialized;
    address public controller;
    address public dataFeed;

    function initialize(address _controller, address _feed) external {
        require(!initialized);
        initialized = true;
        controller = _controller;
        dataFeed = _feed;
    }
}
