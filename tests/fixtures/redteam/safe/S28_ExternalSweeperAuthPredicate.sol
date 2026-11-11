// Exchange sweeper wallet: the privileged sweep is gated by an EXTERNAL authorization predicate
// `if (controller.isSweeper(msg.sender))` - the caller check is delegated to the controller contract.
// Must NOT flag "privileged function callable by anyone".
pragma solidity ^0.8.0;

interface IController { function isSweeper(address) external view returns (bool); }
interface Token {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract UserWallet {
    IController public controller;

    function sweep(address _token, address _to, uint256 _amount) public returns (bool) {
        if (controller.isSweeper(msg.sender)) {
            if (_amount > Token(_token).balanceOf(address(this))) {
                return false;
            }
            return Token(_token).transfer(_to, _amount);
        }
        return false;
    }
}
