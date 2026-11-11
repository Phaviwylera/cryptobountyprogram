// SPDX-License-Identifier: MIT
// Exchange deposit wallet (UserWallet/DefaultSweeper): sweep() delegatecalls a registered sweeper whose
// canSweep modifier checks the caller, and funds go to the controller's fixed destination.
pragma solidity ^0.4.24;
contract SweeperList { function sweeperOf(address) public returns (address); }
contract DepositUserWallet {
    SweeperList sweeperList;
    function sweep(address _token, uint _amount) public returns (bool) {
        _amount;
        return sweeperList.sweeperOf(_token).delegatecall(msg.data);
    }
}
